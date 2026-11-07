"""Balance Guard：先认模型，再问钱。

挂了哪几家、各用什么地址，直接从 AstrBot 的 provider 配置里读；
复用的那把 key 不另存、不回显；页面手填的 key 加密存本机、重启自动恢复，
明文只在进程内存里，页面永远只看到末四位掩码。
按 api_base 的 hostname 精确认厂商，有官方余额接口的定时拉一次；
没有接口的（本地模型、只给账单页的）老实标注，不瞎编数字。
余额掉到阈值以下时，可选地让当前人设生成一句提醒，由机器人自己开口，
一轮只说一次，充值回到阈值以上才复位。

纯逻辑全部在 balance_core.py（零框架依赖，可直接单测）；
本文件只负责插件生命周期、框架 API 与页面路由。
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime
from pathlib import Path

import aiohttp

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star, register

try:  # 新版导出路径
    from astrbot.api.provider import ProviderType  # type: ignore
except Exception:  # pragma: no cover
    try:
        from astrbot.core.provider.entities import ProviderType  # type: ignore
    except Exception:
        ProviderType = None  # type: ignore[assignment]


# ---- 纯逻辑层：零框架依赖，可独立单测（见 balance_core.py） ----
# 依次尝试：包内相对导入（AstrBot 正常加载）→ 目录在 sys.path（离线测试）
# → 按文件路径加载（精确重载后的兜底）。三条路都把 __all__ 里的名字注入本模块。
try:
    from . import balance_core as _core  # type: ignore
except ImportError:  # pragma: no cover
    try:
        import balance_core as _core  # type: ignore
    except ImportError:
        import importlib.util as _ilu

        _spec = _ilu.spec_from_file_location(
            "balance_core", Path(__file__).with_name("balance_core.py")
        )
        _core = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
        assert _spec.loader is not None
        _spec.loader.exec_module(_core)
globals().update({_n: getattr(_core, _n) for _n in _core.__all__})

try:
    from quart import request as _quart_request
except Exception:  # pragma: no cover
    _quart_request = None


class _ManualProvider:
    """页面上手填的那一家，装成 provider 的样子骗过 _query。

    balance_kind 只用于自建/中转站这类「域名认不出来」的情况，
    由用户在页面上选一个接口类型；官方域名不用选，自动认。
    """

    def __init__(
        self, pid: str, model: str, base: str, key: str, kind: str = ""
    ) -> None:
        self.model_name = model or "手动"
        self.balance_kind = str(kind or "").strip()
        # 这把 key 是不是页面这次亲手填的。复用的 AstrBot key 绝不允许
        # 发往非官方域名（见 _query 里的检查），手填的由用户自己负责。
        self.key_is_user_supplied = bool(key)
        self.provider_config = {
            "id": pid or "手动",
            "api_base": base or "",
            "model": model or "",
            "key": [key] if key else [],
        }

    def get_current_key(self) -> str:
        keys = self.provider_config.get("key") or []
        return str(keys[0]) if keys else ""

    def get_model(self) -> str:
        return self.model_name


@register(
    PLUGIN_ID,
    "Balance Guard contributors",
    "按接口地址认出各家的余额接口，key 复用 AstrBot 已配好的；没接口的老实标注",
    "0.4.0",
)
class BalanceBoard(Star):
    def __init__(self, context: Context, config: AstrBotConfig | None = None) -> None:
        super().__init__(context)
        self.config = config or {}
        self._base = (
            Path(__file__).resolve().parents[2]
            / "plugin_data"
            / PLUGIN_ID
        )
        self._base.mkdir(parents=True, exist_ok=True)
        self._state_path = self._base / "state.json"
        self._state = self._load_state()
        self._migrate_alert_state()
        self._task: asyncio.Task | None = None
        self._wake: asyncio.Event | None = None  # 改了刷新间隔就立刻按新节奏跑
        self._lock = asyncio.Lock()
        # 页面手填的 key：明文只留在进程内存里（不回显、不写日志），
        # 落盘的是本机密钥加密后的密文；插件启动/重载时自动解回来，不用重填。
        self._keyring_path = self._base / KEYRING_FILENAME
        self._manual_key_in_memory = ""
        self._restore_manual_key()

    # ------------------------------------------------------------------ 配置
    @property
    def refresh_minutes(self) -> int:
        try:
            v = int(self.config.get("refresh_minutes", 10))
        except Exception:
            v = 10
        return max(1, min(v, 720))

    @property
    def low_balance(self) -> float:
        try:
            return float(self.config.get("low_balance", 2.0))
        except Exception:
            return 2.0

    @property
    def cooldown_hours(self) -> float:
        """重复提醒间隔（小时）。0 = 一轮低余额只发一次，不重复。"""
        try:
            return max(0.0, float(self.config.get("alert_cooldown_hours", 0)))
        except Exception:
            return 0.0

    @property
    def notify_session(self) -> str:
        return str(self.config.get("notify_session") or "").strip()

    def _config_path(self) -> Path:
        return (
            Path(__file__).resolve().parents[2]
            / "config"
            / f"{PLUGIN_ID}_config.json"
        )

    async def _persist_config(self, patch: dict) -> bool:
        """把页面填的值写回插件配置，内存和文件一起更新。"""
        saver = getattr(self.config, "save_config_async", None)
        if callable(saver):
            try:
                await saver(patch)
                return True
            except Exception as e:
                logger.warning(f"[balance_guard] 配置没存下来，走兜底: {e}")
        # 兜底：config 不是 AstrBotConfig 时自己写文件
        try:
            path = self._config_path()
            data = {}
            try:
                data = json.loads(path.read_text("utf-8-sig")) or {}
            except Exception:
                pass
            data.update(patch)
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
            for k, v in patch.items():
                self.config[k] = v
            return True
        except Exception as e:  # pragma: no cover
            logger.warning(f"[balance_guard] 配置兜底也失败了: {e}")
            return False

    def _normalize_session(self, raw: str) -> tuple[str, bool, str]:
        """委托纯逻辑层；补全所用的平台由配置提供，不写死任何一家。"""
        return normalize_session(
            raw,
            default_platform=str(self.config.get("default_platform") or "").strip(),
        )

    @property
    def persist_manual_key(self) -> bool:
        """手填 key 是否加密落盘；默认开，关掉就退回「只在内存、重启要重填」。"""
        v = self.config.get("persist_manual_key", True)
        if isinstance(v, str):
            return v.strip().lower() not in ("false", "0", "no", "off", "")
        return bool(v)

    def _restore_manual_key(self) -> None:
        """插件启动或重载时，把上次加密存下的手填 key 解回内存。"""
        if not self.persist_manual_key:
            return
        sealed = str((self._state.get("manual") or {}).get("keySealed") or "")
        if not sealed:
            return
        try:
            self._manual_key_in_memory = unseal_secret(
                sealed, ensure_local_key(self._keyring_path)
            )
        except Exception as e:  # pragma: no cover
            logger.warning(f"[balance_guard] 手填 key 没能恢复，重填一次就好: {type(e).__name__}")
            return
        if self._manual_key_in_memory:
            logger.info(
                f"[balance_guard] 手填 key 已恢复（尾号 {mask_secret(self._manual_key_in_memory)}）"
            )

    # ------------------------------------------------------------------ 状态
    def _load_state(self) -> dict:
        try:
            return json.loads(self._state_path.read_text("utf-8"))
        except Exception:
            return {"last": {}, "last_alert_ts": 0.0, "last_session": "", "history": []}

    def _save_state(self) -> None:
        try:
            self._state_path.write_text(
                json.dumps(self._state, ensure_ascii=False, indent=2), "utf-8"
            )
        except Exception as e:  # pragma: no cover
            logger.warning(f"[balance_guard] 状态存不下来: {e}")

    def _migrate_alert_state(self) -> None:
        """老版本只有一个全局提醒标记；多账户后改成每家各记一份。"""
        if isinstance(self._state.get("alert_state"), dict):
            return
        legacy = {
            "done": bool(self._state.get("low_alert_done")),
            "ts": float(self._state.get("last_alert_ts") or 0),
            "message": str(self._state.get("last_alert_message") or ""),
            "pending": str(self._state.get("pending_alert_message") or ""),
            "fails": int(self._state.get("alert_fail_count") or 0),
        }
        slots: dict = {}
        pid = str((self._state.get("last") or {}).get("provider_id") or "default")
        if any((legacy["done"], legacy["ts"], legacy["message"], legacy["pending"], legacy["fails"])):
            slots[pid] = legacy
        self._state["alert_state"] = slots
        self._save_state()

    def _alert_slot(self, pid: str) -> dict:
        slots = self._state.setdefault("alert_state", {})
        if not isinstance(slots, dict):
            slots = {}
            self._state["alert_state"] = slots
        slot = slots.get(pid)
        if not isinstance(slot, dict):
            slot = {"done": False, "ts": 0.0, "message": "", "pending": "", "fails": 0}
            slots[pid] = slot
        return slot

    # ------------------------------------------------------------------ 认模型
    async def _current_provider(self, umo: str | None = None):
        pm = getattr(self.context, "provider_manager", None)
        if pm is None:
            return None
        if umo and ProviderType is not None:
            try:
                p = await pm.get_using_provider_async(ProviderType.CHAT_COMPLETION, umo)
                if p is not None:
                    return p
            except Exception as e:
                logger.debug(f"[balance_guard] 按会话取 provider 失败: {e}")
        p = getattr(pm, "curr_provider_inst", None)
        if p is not None:
            return p
        insts = getattr(pm, "provider_insts", None) or []
        return insts[0] if insts else None

    def _all_providers(self) -> list:
        pm = getattr(self.context, "provider_manager", None)
        if pm is None:
            return []
        insts = list(getattr(pm, "provider_insts", None) or [])
        curr = getattr(pm, "curr_provider_inst", None)
        if curr is not None and curr not in insts:
            insts.insert(0, curr)
        return insts

    # ------------------------------------------------------------------ 查余额
    async def _query(self, provider) -> dict:
        """按域名认厂商，拿 AstrBot 已配好的 key 去问一次钱。

        返回 {ok, kind, label, total, currency, reason}。
        官方三家都只认 Bearer key；自建/中转站可在页面上手选接口类型。
        """
        base = _base_of(provider)
        key = _key_of(provider)
        hint = str(getattr(provider, "balance_kind", "") or "").strip()
        adapter = _adapter_for(base, hint)
        # 手选接口类型时会跳过域名识别。这时如果用的还是 AstrBot 里配好的那把
        # key，就必须确认目标域名确实是这家的官方地址，否则等于把凭据交出去。
        if (
            adapter is not None
            and hint
            and _adapter_for(base) is None
            and not getattr(provider, "key_is_user_supplied", False)
        ):
            return {
                "ok": False,
                "kind": adapter["kind"],
                "reason": "目标域名不是这家的官方地址，拒绝把已配好的 key 发过去；"
                          "自建/中转站请在页面上填自己的 key",
            }
        if adapter is None:
            if not base:
                return {"ok": False, "kind": "unknown", "reason": "没填 api_base，认不出去哪查"}
            if any(h in base.lower() for h in LOCAL_HOSTS):
                return {"ok": False, "kind": "local", "reason": "跑在自己机子上的，没有余额这回事"}
            return {
                "ok": False,
                "kind": "other",
                "reason": "域名认不出是哪家；自建/中转站请在「手动查一家」里选接口类型",
            }
        kind, label = adapter["kind"], adapter["label"]
        if not key:
            return {"ok": False, "kind": kind, "label": label, "reason": "没读到 key"}
        origin = _origin(redact_base(base))
        if not origin:
            origin = "https://" + adapter["hosts"][0]
        url = origin + adapter["path"]
        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as sess:
                async with sess.get(
                    url, headers={"Authorization": f"Bearer {key}"}
                ) as resp:
                    if resp.status != 200:
                        body = (await resp.text())[:200]
                        return {
                            "ok": False,
                            "kind": kind,
                            "label": label,
                            "reason": f"接口回 {resp.status} {body}",
                        }
                    data = await resp.json()
        except Exception as e:
            return {"ok": False, "kind": kind, "label": label, "reason": f"网络出错 {e}"}
        try:
            parsed = adapter["parse"](data, base)
        except Exception as e:
            return {
                "ok": False,
                "kind": kind,
                "label": label,
                "reason": f"返回格式没认出来：{type(e).__name__}",
            }
        parsed["kind"] = kind
        parsed["label"] = label
        parsed.setdefault("currency", "CNY")
        parsed.setdefault("reason", "")
        return parsed

    # ------------------------------------------------------------------ 记一笔
    def _remember(self, provider, result: dict, *, set_last: bool = True) -> None:
        """每家各存一份最近快照；只有当前主账户才进 hero 那个 last。"""
        pid = _id_of(provider)
        snap = {
            "ts": _now(),
            "epoch": time.time(),
            "provider_id": pid,
            "model": _model_of(provider),
            "base": redact_base(_base_of(provider)),
            "ok": bool(result.get("ok")),
            "total": result.get("total"),
            "currency": result.get("currency"),
            "reason": result.get("reason", ""),
            "kind": result.get("kind", "other"),
            "label": result.get("label", ""),
        }
        accounts = self._state.setdefault("accounts", {})
        if not isinstance(accounts, dict):
            accounts = {}
            self._state["accounts"] = accounts
        accounts[pid] = snap
        if set_last:
            self._state["last"] = snap
        # 没接口/本地的只留快照，不往历史里塞，免得把 500 条上限刷满
        if snap["kind"] not in ("local", "other", "unknown"):
            hist = self._state.setdefault("history", [])
            hist.append(snap)
            del hist[:-500]
        self._save_state()

    def _spent_since(self, current: float | None, provider_id: str = "") -> str:
        """只跟同一家上一次的余额比，别拿别家的数做差。"""
        hist = self._state.get("history") or []
        if len(hist) < 2 or current is None:
            return ""
        prev = None
        for row in reversed(hist[:-1]):
            if provider_id and str(row.get("provider_id")) != provider_id:
                continue
            if row.get("ok") and row.get("total") is not None:
                prev = row
                break
        if prev is None:
            return ""
        try:
            diff = float(prev["total"]) - float(current)
        except Exception:
            return ""
        if diff <= 0:
            return ""
        return f"比上次少了 {diff:.2f}"

    # ------------------------------------------------------------------ 文案
    def _line(self, provider, result: dict) -> str:
        model = _model_of(provider) or "未知模型"
        pid = _id_of(provider)
        if result.get("ok"):
            cur = result.get("currency") or "CNY"
            total = result.get("total")
            tail = self._spent_since(total, pid)
            head = f"{pid} {model} 剩 {total:.2f} {cur}"
            return f"{head}，{tail}" if tail else head
        return f"{pid} {model} 查不到，{result.get('reason', '原因不明')}"

    # ------------------------------------------------------------------ 定时
    async def initialize(self) -> None:
        self._wake = asyncio.Event()
        self._register_page_api()
        self._task = asyncio.create_task(self._loop())
        logger.info(f"[balance_guard] 起来了，每 {self.refresh_minutes} 分钟看一次")

    async def terminate(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None
        self._save_state()

    async def _loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            try:
                await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception as e:  # pragma: no cover
                logger.warning(f"[balance_guard] 这一轮没跑通: {e}")
            # 可被「保存设置」唤醒：改完间隔不用等旧的一轮睡完
            minutes = self.refresh_minutes
            try:
                if self._wake is not None:
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=minutes * 60)
                    except (asyncio.TimeoutError, TimeoutError):
                        pass
                    self._wake.clear()
                else:
                    await asyncio.sleep(minutes * 60)
            except asyncio.CancelledError:
                raise

    async def _tick(self) -> None:
        """每轮把所有挂着的账户都看一遍；提醒仍只盯实际在花钱的那一家。"""
        async with self._lock:
            provs = self._all_providers()
            if not provs:
                return
            current = await self._current_provider(
                self._state.get("last_session") or None
            )
            cur_id = _id_of(current) if current is not None else ""
            seen: set = set()
            did_set_last = False
            current_result = None
            for p in provs:
                # 多个模型条目可能共用同一个 provider_source（同一个账户同一把 key），
                # 按 (地址, key) 去重，别对着同一个钱包重复发请求。
                fp = (_base_of(p), _key_of(p))
                if fp in seen:
                    continue
                seen.add(fp)
                result = await self._query(p)
                is_current = bool(cur_id and _id_of(p) == cur_id)
                self._remember(p, result, set_last=is_current)
                if is_current:
                    did_set_last = True
                    current_result = result
            if not did_set_last:
                snap = (self._state.get("accounts") or {}).get(_id_of(provs[0])) or {}
                self._state["last"] = snap
                self._save_state()
            target = current if current is not None else provs[0]
            if current_result is None:
                current_result = self._state.get("last") or {}
            await self._maybe_alert(target, current_result)

    # ------------------------------------------------------------------ 让她开口
    async def _persona_prompt(self, umo: str) -> str:
        """拿当前人设卡；拿不到时可选地从框架库里兜底读默认那份。

        直读 data_v4.db 依赖框架内部表结构，属于兼容性降级路径，
        可以用配置 persona_fallback=false 整个关掉。
        """
        if not bool(self.config.get("persona_fallback", True)):
            return ""
        pm = getattr(self.context, "persona_manager", None)
        if pm is not None:
            try:
                p = await pm.get_default_persona_v3(umo=umo or "")
                if isinstance(p, dict) and p.get("prompt"):
                    return str(p["prompt"])
                sp = getattr(p, "system_prompt", "") if p is not None else ""
                if sp:
                    return str(sp)
            except Exception as e:
                logger.debug(f"[balance_guard] 读人设没读着，走兜底: {e}")
        try:
            import sqlite3

            db = Path(__file__).resolve().parents[2] / "data_v4.db"
            con = sqlite3.connect(str(db))
            try:
                row = con.execute(
                    "select system_prompt from personas where persona_id='default'"
                ).fetchone()
            finally:
                con.close()
            if row and row[0]:
                return str(row[0])
        except Exception as e:  # pragma: no cover
            logger.debug(f"[balance_guard] 兜底读人设也没读着: {e}")
        return ""

    def _clean_spoken(self, text: str) -> str:
        """委托纯逻辑层；要剥掉的名字前缀由配置提供，不写死人名。"""
        raw = str(self.config.get("bot_name_prefixes") or "")
        names = [x.strip() for x in re.split(r"[,，|]", raw) if x.strip()]
        return clean_spoken(text, names)

    async def _speak_low_balance(self, provider, result: dict, session: str) -> str:
        """把「钱快没了」先递给她，让她用自己的话说一句。失败返回空串。"""
        if not hasattr(provider, "text_chat"):
            return ""
        persona = await self._persona_prompt(session)
        if not persona:
            logger.warning(f"{LOG_TAG} 没拿到人设卡，这轮先不生成提醒")
            return ""
        try:
            total = float(result.get("total") or 0)
        except Exception:
            return ""
        currency = result.get("currency") or "CNY"
        notice = (
            "【后台通知，不是用户发来的消息】\n"
            f"你刚自己看了一眼账户：{_id_of(provider)} 只剩 {total:.2f} {currency}，"
            f"已经低于 {self.low_balance:.2f} 的提醒线，再聊下去可能就要欠费停服了。\n"
            "现在用你自己的话提醒一句：就一两句，口语、别端着、别列条目、"
            "别写「通知」「报告」「余额」这种字样，也别念一长串数字，"
            "把「钱快见底了、该充一下」这个意思带到就行。\n"
            "直接输出你要说的话，不要加解释、前缀、引号或括号说明。"
        )
        try:
            resp = await asyncio.wait_for(
                provider.text_chat(
                    prompt=notice,
                    system_prompt=persona,
                    contexts=[],
                    session_id=session,
                ),
                timeout=ALERT_SPEAK_TIMEOUT,
            )
            return self._clean_spoken(getattr(resp, "completion_text", "") or "")
        except Exception as e:
            logger.warning(f"[balance_guard] 她这句话没生成出来: {type(e).__name__} {e}")
            return ""

    def _note_alert_failure(self, pid: str) -> None:
        """生成或发送没成：记一笔，不置位，下一轮再试。"""
        slot = self._alert_slot(pid)
        slot["fails"] = int(slot.get("fails") or 0) + 1
        self._state["alert_fail_count"] = slot["fails"]  # 老字段同步，方便直接翻 state
        self._save_state()

    async def _maybe_alert(self, provider, result: dict) -> None:
        """余额低于提醒线时先递给她、由她自己开口说一句；每家各只说一次。

        状态按账户分开存在 state.json，重启也不会重复。生成或发送失败不置位，
        下一轮再试。阈值按账户自己的币种比，不做汇率换算。
        想恢复「按小时重复提醒」，把 alert_cooldown_hours 配成大于 0 的数。
        """
        if not result.get("ok"):
            return
        threshold = self.low_balance
        if threshold <= 0:
            return
        try:
            total = float(result.get("total") or 0)
        except Exception:
            return
        pid = _id_of(provider)
        slot = self._alert_slot(pid)
        if total >= threshold:
            # 钱充回来了：撤掉本轮标记和没发出去的草稿，下次再跌破才重新说一次
            if slot.get("done") or slot.get("pending"):
                slot["done"] = False
                slot["pending"] = ""
                slot["fails"] = 0
                self._state["low_alert_done"] = False
                self._state["pending_alert_message"] = ""
                self._state["alert_fail_count"] = 0
                self._save_state()
                logger.info(f"[balance_guard] {pid} 余额回到提醒线以上，提醒已复位")
            return
        now = time.time()
        if slot.get("done"):
            cooldown = self.cooldown_hours
            # 0 = 只发一次；>0 才按间隔重复（旧能力保留，默认关）
            if cooldown <= 0 or now - float(slot.get("ts") or 0) < cooldown * 3600:
                return
        session = str(self.config.get("notify_session") or "").strip() or str(
            self._state.get("last_session") or ""
        )
        if not session:
            return
        # 先把这件事递给她，由她用自己的话说一句；机器模板彻底不用了
        text = str(slot.get("pending") or "")
        if not text:
            text = await self._speak_low_balance(provider, result, session)
            if text:
                # 生成一次就存着，发送失败下轮直接重发，不重复花模型钱
                slot["pending"] = text
                self._save_state()
        if not text:
            self._note_alert_failure(pid)
            logger.warning("[balance_guard] 这轮没让她说出话来，下轮再试")
            return
        try:
            from astrbot.core.message.message_event_result import MessageChain

            ok = await self.context.send_message(session, MessageChain().message(text))
            if ok:
                slot["done"] = True
                slot["ts"] = now
                slot["message"] = text
                slot["pending"] = ""
                slot["fails"] = 0
                # 老字段同步一下，直接翻 state.json 也不会看到过期的值
                self._state["low_alert_done"] = True
                self._state["last_alert_ts"] = now
                self._state["last_alert_message"] = text
                self._state["pending_alert_message"] = ""
                self._state["alert_fail_count"] = 0
                self._save_state()
                logger.info(f"[balance_guard] 她自己开口说了（{pid} 本轮不再重复）: {text}")
            else:
                self._note_alert_failure(pid)
                logger.warning("[balance_guard] 平台没接住这条，下一轮再试")
        except Exception as e:  # pragma: no cover
            self._note_alert_failure(pid)
            logger.warning(f"[balance_guard] 她这句话没发出去: {e}")

    # ------------------------------------------------------------------ 页面接口
    def _register_page_api(self) -> None:
        register = getattr(self.context, "register_web_api", None)
        if register is None:
            logger.warning("[balance_guard] 这版框架不让插件挂页面接口，侧栏用不了")
            return
        register(f"{PAGE_API_PREFIX}/overview", self.api_overview, ["GET"], "余额面板 概览")
        register(f"{PAGE_API_PREFIX}/query", self.api_query, ["POST"], "余额面板 查一次")
        register(f"{PAGE_API_PREFIX}/manual", self.api_manual, ["POST"], "余额面板 存手填")
        register(f"{PAGE_API_PREFIX}/settings", self.api_settings, ["POST"], "余额面板 存提醒与刷新设置")
        register(f"{PAGE_API_PREFIX}/open_topup", self.api_open_topup, ["POST"], "余额面板 打开官方充值页")

    def _brief(self, provider) -> dict:
        """交给 balance_core.brief_provider：统一脱敏、统一精确认域名。"""
        return brief_provider(provider, isinstance(provider, _ManualProvider))

    async def api_overview(self):
        current = await self._current_provider(self._state.get("last_session") or None)
        if current is None:
            # 认不出当前那家，就先把第一家摆上去，总比空着强
            _provs = self._all_providers()
            current = _provs[0] if _provs else None
        hist = list(self._state.get("history") or [])[-240:]
        cur_id = _id_of(current) if current is not None else ""
        slot = (
            self._alert_slot(cur_id)
            if cur_id
            else {"done": False, "ts": 0.0, "message": "", "pending": "", "fails": 0}
        )
        alert_ts = float(slot.get("ts") or 0)
        burn = burn_stats(self._state.get("history") or [], cur_id)
        return {
            "ok": True,
            "current": self._brief(current) if current else None,
            "providers": [self._brief(p) for p in self._all_providers()],
            "accounts": self._state.get("accounts") or {},
            "supported": SUPPORTED_KINDS,
            "last": self._state.get("last") or {},
            "history": list(reversed(hist)),
            "burn": burn,
            "manual": manual_view(self._state.get("manual")),
            "refreshMinutes": self.refresh_minutes,
            "lowBalance": self.low_balance,
            "cooldownHours": self.cooldown_hours,
            "alertOnce": self.cooldown_hours <= 0,
            "alertViaBot": True,
            "alertDone": bool(slot.get("done")),
            "lastAlertMessage": str(slot.get("message") or ""),
            "alertFailCount": int(slot.get("fails") or 0),
            "lastAlertTs": alert_ts,
            "lastAlertText": (
                datetime.fromtimestamp(alert_ts).strftime("%Y-%m-%d %H:%M:%S")
                if alert_ts
                else ""
            ),
            "notifySession": self.notify_session,
            "lastSession": str(self._state.get("last_session") or ""),
        }

    async def api_query(self):
        payload = {}
        if _quart_request is not None:
            try:
                payload = await _quart_request.get_json(silent=True) or {}
            except Exception:
                payload = {}
        pid = str(payload.get("provider_id") or "").strip()[:MAX_FIELD_LEN]
        base = str(payload.get("base") or "").strip()[:MAX_FIELD_LEN]
        key = str(payload.get("key") or "").strip()
        model = str(payload.get("model") or "").strip()[:MAX_FIELD_LEN]
        kind = str(payload.get("kind") or "").strip()

        # 页面可以指定 api_base 查自建/中转站，先挡掉内网、畸形地址和超长字段
        if base:
            ok, reason = validate_api_base(base)
            if not ok:
                return {"ok": False, "reason": reason}
        if kind and kind not in {a["kind"] for a in BALANCE_ADAPTERS}:
            return {"ok": False, "reason": "接口类型不在支持列表里"}
        key = key[:MAX_KEY_LEN]

        provider = None
        if pid:
            for p in self._all_providers():
                if _id_of(p) == pid:
                    provider = p
                    break
        elif not (base or key or model or kind):
            # 页面那颗「查一次」发过来的是空包，这里认当前挂着的那家
            provider = await self._current_provider(
                self._state.get("last_session") or None
            )
        if provider is not None and not (base or key or kind):
            target = provider
        else:
            # 手选了接口类型就包一层：地址和 key 仍沿用已配好的，不要求重填
            fill_base = base or (_base_of(provider) if provider else "")
            fill_key = key or (_key_of(provider) if provider else "")
            if not fill_key and (base or kind):
                # 手填场景下用内存里那把：页面保存时写入，启动时从密文解回来
                fill_key = getattr(self, "_manual_key_in_memory", "") or ""
            fill_model = model or (_model_of(provider) if provider else "")
            if not fill_base:
                return {"ok": False, "reason": "没给 api_base，认不出去哪查"}
            target = _ManualProvider(pid or "手动", fill_model, fill_base, fill_key, kind)

        result = await self._query(target)
        self._remember(target, result)
        return {
            "ok": bool(result.get("ok")),
            "provider": self._brief(target),
            "result": result,
            "line": self._line(target, result),
        }

    async def api_manual(self):
        payload = {}
        if _quart_request is not None:
            try:
                payload = await _quart_request.get_json(silent=True) or {}
            except Exception:
                payload = {}
        safe, err = sanitize_manual(payload)
        if err:
            return {"ok": False, "reason": err}
        raw_key = str(payload.get("key") or "").strip()[:MAX_KEY_LEN]
        clear = bool(payload.get("clear_key"))
        old = dict(self._state.get("manual") or {})

        if clear:
            self._manual_key_in_memory = ""
        elif raw_key:
            self._manual_key_in_memory = raw_key

        effective = self._manual_key_in_memory
        safe["hasKey"] = bool(effective)
        safe["keyTail"] = mask_secret(effective)

        # 明文只在内存里；落盘的是本机密钥加密后的密文，页面只看到末四位。
        # 下次启动 _restore_manual_key() 会把它解回来，不用重新填一次。
        if effective and not clear and self.persist_manual_key:
            sealed = "" if raw_key else str(old.get("keySealed") or "")
            if not sealed:
                try:
                    sealed = seal_secret(effective, ensure_local_key(self._keyring_path))
                except Exception as e:  # pragma: no cover
                    logger.warning(
                        f"[balance_guard] 手填 key 没能加密保存，本次运行仍可用: {type(e).__name__}"
                    )
            if sealed:
                safe["keySealed"] = sealed
        self._state["manual"] = safe
        self._save_state()
        return {
            "ok": True,
            "manual": manual_view(safe),
            "keyPersisted": bool(safe.get("keySealed")),
        }

    async def api_open_topup(self):
        """点「去充值」时由后端唤起桌面默认浏览器。

        插件页被 WebUI 放在 sandbox iframe 里（没有 allow-popups），页面里怎么开窗
        都会被拦；后端进程不受这个限制。只认自己这张官方白名单，不让页面传任意地址。
        dry_run 只给自检用：返回将要打开的地址，不真的开浏览器。
        """
        payload = {}
        if _quart_request is not None:
            try:
                payload = await _quart_request.get_json(silent=True) or {}
            except Exception:
                payload = {}
        kind = str(payload.get("kind") or "").strip()
        base = str(payload.get("base") or "").strip()
        url = topup_url_or_none(kind, base)
        if not url:
            return {"ok": False, "reason": "这家没有统一的充值页，或地址不在官方白名单里"}
        if payload.get("dry_run"):
            return {"ok": True, "url": url, "opened": False, "dry_run": True}
        # 默认直接在本机打开；只有显式把 allow_open_browser 设为 false 才不跳，
        # 那种情况下页面仍会给出可复制的官方地址。
        if not browser_open_allowed(self.config):
            return {
                "ok": False,
                "url": url,
                "reason": "唤起本机浏览器已被配置关闭（allow_open_browser=false）；"
                          "可以直接复制这个地址自己打开",
            }
        # 防连点：1.5 秒内重复请求只认一次，不连开一串标签
        now = time.time()
        last = float(getattr(self, "_last_topup_open", 0) or 0)
        if now - last < 1.5:
            return {"ok": True, "url": url, "opened": False, "throttled": True}
        self._last_topup_open = now
        opened = _open_system_browser(url)
        logger.info(f"[balance_guard] 已在本机默认浏览器打开 {url}")
        return {"ok": True, "url": url, "opened": opened}

    async def api_settings(self):
        """页面上自己填「提醒发到哪个会话」和「隔多久自动刷新」。"""
        payload = {}
        if _quart_request is not None:
            try:
                payload = await _quart_request.get_json(silent=True) or {}
            except Exception:
                payload = {}

        raw_minutes = payload.get("refresh_minutes")
        if raw_minutes is None or str(raw_minutes).strip() == "":
            return {"ok": False, "reason": "自动刷新间隔没填"}
        try:
            minutes = int(float(str(raw_minutes).strip()))
        except Exception:
            return {"ok": False, "reason": "间隔要填数字，单位是分钟"}
        if not 1 <= minutes <= 720:
            return {"ok": False, "reason": "间隔只能是 1 到 720 分钟"}

        raw_session = payload.get("notify_session")
        if raw_session is None:
            raw_session = self.notify_session
        session, fixed, err = self._normalize_session(raw_session)
        if err:
            return {"ok": False, "reason": err}

        raw_low = payload.get("low_balance")
        if raw_low is None or str(raw_low).strip() == "":
            low = self.low_balance
        else:
            try:
                low = float(str(raw_low).strip())
            except Exception:
                return {"ok": False, "reason": "提醒线要填数字，单位跟余额一样"}
            if not 0 <= low <= 1000000:
                return {"ok": False, "reason": "提醒线不能是负数，填 0 就不提醒"}

        if not await self._persist_config(
            {"refresh_minutes": minutes, "notify_session": session, "low_balance": low}
        ):
            return {"ok": False, "reason": "配置没写进去，看看后台日志"}

        # 立刻醒过来按新间隔跑一轮，不用等旧间隔睡完
        if self._wake is not None:
            self._wake.set()

        msg = f"已保存：每 {minutes} 分钟自动刷新，余额低于 {low:g} 就提醒"
        msg += (
            "，提醒会话留空（自动用最近说话的会话）"
            if not session
            else f"，提醒发到 {session}"
        )
        if fixed:
            msg += "；会话格式已自动补全/纠正"
        logger.info(f"[balance_guard] {msg}")
        return {
            "ok": True,
            "refreshMinutes": self.refresh_minutes,
            "lowBalance": self.low_balance,
            "notifySession": self.notify_session,
            "lastSession": str(self._state.get("last_session") or ""),
            "fixed": fixed,
            "message": msg,
        }

    # ------------------------------------------------------------------ 命佤
    @filter.command("余额", alias={"balance"})
    async def cmd_balance(self, event: AstrMessageEvent):
        """看一眼钱还剩多少。加「全部」看所有挂着的服务商。"""
        umo = getattr(event, "unified_msg_origin", "") or ""
        if umo:
            self._state["last_session"] = umo
            self._save_state()
        args = (getattr(event, "message_str", "") or "").strip().split()
        if len(args) > 1 and args[1] in ("全部", "all", "所有"):
            yield event.plain_result(self._all_text())
            return
        provider = await self._current_provider(umo or None)
        if provider is None:
            yield event.plain_result("没认出当前挂的模型，provider 那边是空的")
            return
        result = await self._query(provider)
        self._remember(provider, result)
        yield event.plain_result(self._panel_text(provider, result))

    def _panel_text(self, provider, result: dict) -> str:
        lines = [self._line(provider, result)]
        base = _base_of(provider)
        if base:
            lines.append(f"走的是 {base}")
        if result.get("ok"):
            hist = self._state.get("history") or []
            pid = _id_of(provider)
            prev = None
            for row in reversed(hist[:-1]):
                if str(row.get("provider_id")) == pid and row.get("ok"):
                    prev = row
                    break
            if prev:
                lines.append(f"上次看是 {prev.get('total')}，{prev.get('ts')}")
            th = self.low_balance
            if th > 0 and float(result.get("total") or 0) < th:
                lines.append("过线了，该充了")
        return "\n".join(lines)

    def _all_text(self) -> str:
        provs = self._all_providers()
        if not provs:
            return "一家都没挂上"
        accounts = self._state.get("accounts") or {}
        lines = []
        for p in provs:
            r = accounts.get(_id_of(p)) or {}
            if r.get("ok") and r.get("total") is not None:
                lines.append(
                    f"{_id_of(p)} {_model_of(p)} 剩 {r['total']} {r.get('currency') or 'CNY'}"
                    + (f"（{r['label']}）" if r.get("label") else "")
                )
            else:
                lines.append(f"{_id_of(p)} {_model_of(p)} 没查过或者查不到：{r.get('reason') or '没接口'}")
        return "\n".join(lines)
