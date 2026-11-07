"""astrbot_plugin_balance_board 的纯逻辑层。

设计约定：
* 本模块**不依赖 AstrBot**，只用标准库，可以直接 `import balance_core` 做单元测试；
* 所有「不碰框架就能算清楚」的事都放这里：厂商识别、响应解析、会话格式、
  充值地址白名单、脱敏、SSRF 防护、提醒状态判定；
* `main.py` 只负责插件生命周期、框架 API 与页面路由。

安全要点（与线上原版的行为差异见 docs/GAP-ANALYSIS.md）：
* 厂商识别按 URL 的 **hostname 精确匹配**，不再用子串包含；
* 手填的 key **绝不回显明文**：页面只见末四位掩码；落盘的是本机密钥加密后的
  密文，密钥放在独立的 `.keyring` 文件里，重启自动解密恢复，不用重填；
* 允许外部传入 api_base 时做内网 / 非 HTTPS / 超长拦截；
* 唤起本机浏览器默认开启（地址只从官方白名单取），可用配置显式关闭。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

try:  # 在 AstrBot 里用它的 logger；离线测试时退回标准库
    from astrbot.api import logger  # type: ignore
except Exception:  # pragma: no cover - 离线环境
    logger = logging.getLogger("balance_guard")


# --------------------------------------------------------------------------- 常量
# 想给插件改名，只需要改这一行，再加上 metadata.yaml 的 name、
# @register 的第一个参数和插件目录名（见 docs/MIGRATION.md）。
PLUGIN_ID = "astrbot_plugin_balance_board"

LOG_TAG = f"[{PLUGIN_ID}]"
PAGE_API_PREFIX = f"/{PLUGIN_ID}/page"

TZ_NOTE = "钱是硬约束，先看余额"
ALERT_SPEAK_TIMEOUT = 30.0  # 生成那句话最多等 30 秒，超时就下一轮再试
LOCAL_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "::1", "[::1]")

MAX_FIELD_LEN = 512          # 页面传进来的单个字段长度上限
MAX_SESSION_LEN = 256
MAX_KEY_LEN = 512

SESSION_RE = re.compile(r"^[^:\s]+:[^:\s]+:.+$")
SESSION_UNDERSCORE_RE = re.compile(r"^([A-Za-z0-9.-]+)_([A-Za-z]+)_([^\s:]+)$")

# --------------------------------------------------------------------------- 充值页
# WebUI 把插件页放在 sandbox iframe 里（缺 allow-popups），target=_blank 和
# window.open 都会被浏览器静默拦掉。所以由后端唤起用户桌面上的默认浏览器。
# 只放官方域名，不带 key、不带金额；认不出来的厂商不猜地址。
TOPUP_URLS = {
    "deepseek": "https://platform.deepseek.com/top_up",
    "siliconflow": "https://cloud.siliconflow.cn/expensebill",
    "moonshot": "https://platform.moonshot.cn/console",
}
TOPUP_URL_MOONSHOT_INTL = "https://platform.moonshot.ai/console"
TOPUP_HOSTS = frozenset({
    "platform.deepseek.com",
    "cloud.siliconflow.cn",
    "platform.moonshot.cn",
    "platform.moonshot.ai",
})


def _topup_target(kind: str, base: str = "") -> str:
    """这一家该去哪充值；本地模型 / 自建站返回空串，不猜地址。"""
    if kind == "moonshot" and _hostname(base) == "api.moonshot.ai":
        return TOPUP_URL_MOONSHOT_INTL
    return TOPUP_URLS.get(kind or "", "")


def topup_url_or_none(kind: str, base: str = "") -> str | None:
    """只有白名单里的 https 官方地址才返回，其余一律 None。"""
    url = _topup_target(kind, base)
    if not url:
        return None
    u = urlsplit(url)
    if u.scheme != "https" or u.netloc not in TOPUP_HOSTS:
        return None
    return url


def _open_system_browser(url: str) -> bool:
    """在用户自己的桌面上开默认浏览器，绕开 WebUI iframe 的 sandbox。

    注意：这是**在本机执行的一个有副作用的动作**，调用方必须先用
    `browser_open_allowed()` 确认它没有被配置显式关掉，不能直接调用。
    """

    def _go() -> None:
        try:
            if hasattr(os, "startfile"):  # Windows：交给 shell 关联的默认浏览器
                os.startfile(url)  # type: ignore[attr-defined]
                return
        except Exception:
            pass
        try:
            webbrowser.open_new(url)
        except Exception as exc:
            logger.warning(f"{LOG_TAG} 默认浏览器没叫起来: {exc}")

    threading.Thread(target=_go, name="balance-topup-open", daemon=True).start()
    return True


def browser_open_allowed(config: dict | None) -> bool:
    """点「去充值」默认直接唤起本机浏览器；只有显式关掉才不跳。

    缺省、None、以及任何非「关」的取值都视为允许，保证开箱即用；
    想禁用就把 `allow_open_browser` 设成 false / 0 / "false"。
    """
    try:
        v = (config or {}).get("allow_open_browser", True)
    except Exception:
        return True
    if isinstance(v, str):
        return v.strip().lower() not in ("false", "0", "no", "off", "")
    return bool(v)


# --------------------------------------------------------------------------- URL 工具
def _hostname(base: str) -> str:
    """取小写 hostname；解析失败返回空串。"""
    try:
        return (urlsplit(str(base or "")).hostname or "").lower()
    except Exception:
        return ""


def _origin(base: str) -> str:
    """把 https://api.deepseek.com/v1 削成 https://api.deepseek.com。"""
    try:
        u = urlsplit(str(base or ""))
        return f"{u.scheme}://{u.netloc}" if u.scheme and u.netloc else ""
    except Exception:
        return ""


_PRIVATE_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "169.254.169.254",
    "metadata.google.internal",
})


def validate_api_base(base: str, *, allow_private: bool = False) -> tuple[bool, str]:
    """校验页面传进来的 api_base，挡住 SSRF 与畸形地址。

    返回 (是否可用, 原因)。官方域名与自建中转站都走同一套校验；
    本地模型（allow_private=True）的调用由插件内部发起，不接受页面输入。
    """
    s = str(base or "").strip()
    if not s:
        return False, "没给 api_base，认不出去哪查"
    if len(s) > MAX_FIELD_LEN:
        return False, "api_base 太长了"
    try:
        u = urlsplit(s)
    except Exception:
        return False, "api_base 不是合法地址"
    if u.scheme not in ("http", "https"):
        return False, "api_base 只支持 http/https"
    if not u.netloc or u.username or u.password:
        return False, "api_base 里不能带账号密码"
    host = (u.hostname or "").lower()
    if not host:
        return False, "api_base 没有主机名"
    if not allow_private:
        if host in _PRIVATE_HOSTS or host.startswith("127.") or host.startswith("192.168."):
            return False, "不让查本机或内网地址"
        if host.startswith("10."):
            return False, "不让查本机或内网地址"
        if re.match(r"^172\.(1[6-9]|2\d|3[01])\.", host):
            return False, "不让查本机或内网地址"
        if host.endswith(".local") or host.endswith(".internal"):
            return False, "不让查本机或内网地址"
    return True, ""


def redact_base(base: str) -> str:
    """去掉 api_base 里 query/fragment 中可能夹带的凭据，给前端看用。"""
    try:
        u = urlsplit(str(base or ""))
        if not u.query and not u.fragment:
            return str(base or "")
        return f"{u.scheme}://{u.netloc}{u.path}"
    except Exception:
        return ""


# --------------------------------------------------------------------------- 余额解析
def _parse_deepseek(data: dict, base: str) -> dict:
    infos = data.get("balance_infos") or []
    if not infos:
        return {"ok": False, "reason": "接口没给余额"}
    info = infos[0]
    for item in infos:
        if str(item.get("currency", "")).upper() == "CNY":
            info = item
            break
    try:
        total = float(info.get("total_balance", 0))
    except Exception:
        total = 0.0
    return {
        "ok": True,
        "total": total,
        "currency": str(info.get("currency") or "CNY"),
        "available": bool(data.get("is_available", True)),
        "topped_up": info.get("topped_up_balance"),
    }


def _parse_siliconflow(data: dict, base: str) -> dict:
    d = data.get("data") or {}
    raw = d.get("totalBalance")
    if raw in (None, ""):
        raw = d.get("balance") or 0
    try:
        total = float(raw)
    except Exception:
        total = 0.0
    return {
        "ok": True,
        "total": total,
        "currency": "CNY",
        "gift": d.get("balance"),
        "topped_up": d.get("chargeBalance"),
    }


def _parse_moonshot(data: dict, base: str) -> dict:
    d = data.get("data") or {}
    try:
        total = float(d.get("available_balance", 0))
    except Exception:
        total = 0.0
    # 国内站按人民币结算，国际站按美元；两站的 key 不通用
    usd = _hostname(base) == "api.moonshot.ai"
    return {
        "ok": True,
        "total": total,
        "currency": "USD" if usd else "CNY",
        "voucher": d.get("voucher_balance"),
        "cash": d.get("cash_balance"),
    }


BALANCE_ADAPTERS = [
    {
        "kind": "deepseek",
        "label": "DeepSeek",
        "hosts": ("api.deepseek.com",),
        "path": "/user/balance",
        "parse": _parse_deepseek,
    },
    {
        "kind": "siliconflow",
        "label": "硅基流动",
        "hosts": ("api.siliconflow.cn", "api.siliconflow.com"),
        "path": "/v1/user/info",
        "parse": _parse_siliconflow,
    },
    {
        "kind": "moonshot",
        "label": "Kimi / Moonshot",
        "hosts": ("api.moonshot.cn", "api.moonshot.ai"),
        "path": "/v1/users/me/balance",
        "parse": _parse_moonshot,
    },
]
SUPPORTED_KINDS = [{"kind": a["kind"], "label": a["label"]} for a in BALANCE_ADAPTERS]


def _adapter_for(base: str, kind_hint: str = ""):
    """先按页面上指定的类型，再按 **hostname 精确匹配** 认厂商。

    原版用 `host in api_base` 子串判断，形如
    `https://api.deepseek.com.attacker.tld/v1` 也会被认成 DeepSeek，
    于是会把用户的 DeepSeek key 发到攻击者服务器 —— 这里必须精确匹配。
    """
    hint = str(kind_hint or "").strip()
    if hint:
        for adapter in BALANCE_ADAPTERS:
            if adapter["kind"] == hint:
                return adapter
        return None
    host = _hostname(base)
    if not host:
        return None
    for adapter in BALANCE_ADAPTERS:
        if host in adapter["hosts"]:
            return adapter
    return None


# --------------------------------------------------------------------------- Provider 读字段
def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _cfg_of(provider) -> dict:
    cfg = getattr(provider, "provider_config", None)
    return cfg if isinstance(cfg, dict) else {}


def _key_of(provider) -> str:
    """尽量拿到这家现在用的 key。只在进程内使用，绝不写进返回值或日志。"""
    try:
        k = provider.get_current_key()
        if k:
            return str(k)
    except Exception:
        pass
    try:
        keys = _cfg_of(provider).get("key") or []
        if isinstance(keys, str):
            keys = [keys]
        for k in keys:
            if str(k).strip():
                return str(k).strip()
    except Exception:
        pass
    return ""


def _model_of(provider) -> str:
    try:
        m = provider.get_model()
        if m:
            return str(m)
    except Exception:
        pass
    try:
        return str(provider.model_name or "")
    except Exception:
        return ""


def _id_of(provider) -> str:
    return str(_cfg_of(provider).get("id") or "default")


def _base_of(provider) -> str:
    return str(_cfg_of(provider).get("api_base") or "").rstrip("/")


# --------------------------------------------------------------------------- 脱敏
# --------------------------------------------------------------------------- 本机凭据保管
# 目标：手填的 key 既能「重启后自动恢复」，又不会以明文出现在 state.json、
# 页面返回值或日志里。做法是本机随机密钥 + 带认证的流加密：
#   PBKDF2(本机密钥, salt) 派生 → HMAC-SHA256 生成 keystream → XOR 明文
#   → 再算一个 HMAC tag 防篡改。密文存 state.json，本机密钥单独放 .keyring。
# 只用标准库，不引入 cryptography 之类的依赖；Windows / Linux / macOS 都能跑。
# 边界要说清楚：同时拿到 state.json 和 .keyring 的人仍能解开；但只泄漏/同步
# state.json（最常见的情况）拿不到 key，页面更是从头到尾只见末四位掩码。
KEYRING_FILENAME = ".keyring"
_SEAL_PREFIX = "bg1."
_SEAL_SALT_LEN = 16
_SEAL_NONCE_LEN = 16
_SEAL_TAG_LEN = 16
_PBKDF2_ROUNDS = 120_000


def ensure_local_key(path) -> bytes:
    """取（必要时新建）本机 32 字节随机密钥；文件尽量设成仅本人可读。"""
    p = Path(path)
    try:
        raw = p.read_bytes()
        if len(raw) >= 32:
            return raw[:32]
    except OSError:
        pass
    p.parent.mkdir(parents=True, exist_ok=True)
    material = secrets.token_bytes(32)
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # 另一个进程抢先建好了：优先用它写的那份，免得把人家刚生成的密钥盖掉
        try:
            other = p.read_bytes()
        except OSError:
            other = b""
        if len(other) >= 32:
            return other[:32]
        # 确实读不出可用密钥（空文件或太短）才补写一份
        p.write_bytes(material)
    except OSError as exc:
        raise RuntimeError(f"本机密钥文件建不起来: {exc}") from exc
    else:
        try:
            os.write(fd, material)
        finally:
            os.close(fd)
    try:
        os.chmod(str(p), 0o600)
    except OSError:
        pass
    return material


def _seal_keystream(dk: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.digest(dk, b"bg-ks" + nonce + counter.to_bytes(4, "big"), "sha256")
        counter += 1
    return bytes(out[:length])


def seal_secret(plain: str, key_material: bytes) -> str:
    """加密一段凭据，返回可安全落盘的字符串；空串返回空串。"""
    data = str(plain or "").encode("utf-8")
    if not data:
        return ""
    if not key_material:
        raise ValueError("缺本机密钥")
    salt = secrets.token_bytes(_SEAL_SALT_LEN)
    nonce = secrets.token_bytes(_SEAL_NONCE_LEN)
    dk = hashlib.pbkdf2_hmac("sha256", key_material, salt, _PBKDF2_ROUNDS, dklen=32)
    stream = _seal_keystream(dk, nonce, len(data))
    ct = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.digest(dk, b"bg-tag" + salt + nonce + ct, "sha256")[:_SEAL_TAG_LEN]
    blob = salt + nonce + tag + ct
    b64 = base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return _SEAL_PREFIX + b64


def unseal_secret(token: str, key_material: bytes) -> str:
    """解回明文；格式不对、密钥不对、被篡改过都安静地返回空串。"""
    s = str(token or "")
    if not s.startswith(_SEAL_PREFIX) or not key_material:
        return ""
    body = s[len(_SEAL_PREFIX):]
    try:
        blob = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except Exception:
        return ""
    head = _SEAL_SALT_LEN + _SEAL_NONCE_LEN + _SEAL_TAG_LEN
    if len(blob) < head:
        return ""
    salt = blob[:_SEAL_SALT_LEN]
    nonce = blob[_SEAL_SALT_LEN:_SEAL_SALT_LEN + _SEAL_NONCE_LEN]
    tag = blob[_SEAL_SALT_LEN + _SEAL_NONCE_LEN:head]
    ct = blob[head:]
    try:
        dk = hashlib.pbkdf2_hmac("sha256", key_material, salt, _PBKDF2_ROUNDS, dklen=32)
        expect = hmac.digest(dk, b"bg-tag" + salt + nonce + ct, "sha256")[:_SEAL_TAG_LEN]
        if not hmac.compare_digest(tag, expect):
            return ""
        stream = _seal_keystream(dk, nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, stream)).decode("utf-8")
    except Exception:
        return ""


def mask_secret(key: str) -> str:
    """只留末四位；短 key 一律返回空串，避免暴露过多。"""
    s = str(key or "")
    return s[-4:] if len(s) >= 8 else ""


def brief_provider(provider, manual: bool = False) -> dict:
    """给页面看的 provider 摘要：永远不含完整 key，也不含 api_base 的 query。"""
    key = _key_of(provider)
    base = _base_of(provider)
    hint = str(getattr(provider, "balance_kind", "") or "").strip()
    adapter = _adapter_for(base, hint)
    low = base.lower()
    local = any(h in low for h in LOCAL_HOSTS) if base else False
    return {
        "id": _id_of(provider),
        "model": _model_of(provider),
        "base": redact_base(base),
        "hasKey": bool(key),
        "keyTail": mask_secret(key),
        "known": adapter is not None,
        "kind": adapter["kind"] if adapter else ("local" if local else "other"),
        "label": adapter["label"] if adapter else ("本地模型" if local else "没余额接口"),
        "reuseKey": not manual,
    }


def sanitize_manual(payload: dict) -> tuple[dict, str]:
    """把页面「手动查一家」的表单收敛成可安全落盘的结构。

    * key **明文不写进返回值**，只留 `keyTail` 掩码；
    * 需要真正发请求时由调用方在内存里持有明文 key；
    * 调用方可另外把 `seal_secret()` 得到的密文放进 `safe["keySealed"]` 落盘，
      页面回显时 `manual_view()` 会把它剥掉；
    * 所有字段限长、api_base 过 SSRF 校验、kind 只认白名单。
    """
    raw = payload if isinstance(payload, dict) else {}
    field = lambda k: str(raw.get(k) or "").strip()[:MAX_FIELD_LEN]  # noqa: E731
    base = field("base")
    model = field("model")
    kind = field("kind")
    pid = field("provider_id")
    key = str(raw.get("key") or "").strip()[:MAX_KEY_LEN]

    if base:
        ok, reason = validate_api_base(base)
        if not ok:
            return {}, reason
    if kind and kind not in {a["kind"] for a in BALANCE_ADAPTERS}:
        return {}, "接口类型不在支持列表里"
    safe = {
        "provider_id": pid,
        "base": base,
        "model": model,
        "kind": kind,
        "hasKey": bool(key),
        "keyTail": mask_secret(key),
    }
    return safe, ""


def manual_view(stored: dict | None) -> dict:
    """回显给前端的手填配置：再兜一层，明文 key 和密文都不带出去。

    只多给一个 `keyPersisted` 布尔，让页面能提示「重启后不用重填」。
    """
    d = dict(stored or {})
    d.pop("key", None)
    d["keyPersisted"] = bool(d.pop("keySealed", None))
    if "base" in d:
        d["base"] = redact_base(d.get("base"))
    return d


# --------------------------------------------------------------------------- 会话 / 文案
def normalize_session(
    raw: str,
    *,
    default_platform: str = "",
    default_message_type: str = "FriendMessage",
) -> tuple[str, bool, str]:
    """返回 (规范后的会话, 是否自动纠正过, 错误信息)。

    与线上原版不同：不再写死任何平台。只填纯数字时，只有配置了
    `default_platform` 才会补全；没配就要求填完整 UMO，避免把别平台的
    群号悄悄当成某个特定平台的私聊。
    """
    s = str(raw or "").strip()
    if len(s) > MAX_SESSION_LEN:
        return "", False, "会话地址太长了"
    if not s:
        return "", False, ""
    if SESSION_RE.match(s):
        return s, False, ""
    if s.isdigit():
        if not default_platform:
            return "", False, (
                "只填号码时需要在配置里设 default_platform；"
                "也可以直接填完整会话 平台:消息类型:会话号"
            )
        return f"{default_platform}:{default_message_type}:{s}", True, ""
    m = SESSION_UNDERSCORE_RE.match(s)
    if m:
        return f"{m.group(1)}:{m.group(2)}:{m.group(3)}", True, ""
    return "", False, (
        "会话格式不对，要 平台:消息类型:会话号（用冒号）；"
        "也可以在配置里设 default_platform 后只填号码"
    )


def clean_spoken(text: str, name_prefixes: tuple[str, ...] | list[str] = ()) -> str:
    """把模型生成的话收拾干净：去名字前缀、去包裹引号、只留前两行。

    `name_prefixes` 由配置提供（例如机器人自己的名字），不再写死任何人名。
    """
    t = str(text or "").strip()
    fixed = ["回复", "回答", "答", "输出", "Reply", "Answer"]
    extra = [str(x).strip() for x in (name_prefixes or ()) if str(x).strip()]
    words = fixed + extra
    if words:
        t = re.sub(
            r"^(?:" + "|".join(re.escape(w) for w in words) + r")\s*[:：]\s*",
            "",
            t,
        )
    quotes = "\"'“”‘’"
    if len(t) >= 2 and t[0] in quotes and t[-1] in quotes:
        t = t[1:-1].strip()
    lines: list[str] = []
    for ln in t.splitlines():
        ln = ln.strip()
        # 整段没包住、但某一行被包住的情况也要收拾（模型常这么写）
        if len(ln) >= 2 and ln[0] in quotes and ln[-1] in quotes:
            ln = ln[1:-1].strip()
        ln = ln.strip("`* ")
        if ln:
            lines.append(ln)
    return "\n".join(lines[:2]).strip()


def is_low_balance(total, threshold) -> bool:
    """阈值按账户自己的币种比，不做汇率换算；阈值 <= 0 表示不提醒。"""
    try:
        th = float(threshold or 0)
        val = float(total or 0)
    except (TypeError, ValueError):
        return False
    return th > 0 and val < th


def alert_due(slot: dict, *, now: float, cooldown_hours: float) -> bool:
    """这一轮该不该提醒：默认只说一次，充值回线才复位。"""
    if not slot.get("done"):
        return True
    if cooldown_hours <= 0:
        return False
    return now - float(slot.get("ts") or 0) >= cooldown_hours * 3600


def migrate_alert_state(state: dict) -> dict:
    """老版本只有一个全局提醒标记；多账户后改成每家各记一份。纯函数。"""
    out = dict(state or {})
    if isinstance(out.get("alert_state"), dict):
        return out
    legacy = {
        "done": bool(out.get("low_alert_done")),
        "ts": float(out.get("last_alert_ts") or 0),
        "message": str(out.get("last_alert_message") or ""),
        "pending": str(out.get("pending_alert_message") or ""),
        "fails": int(out.get("alert_fail_count") or 0),
    }
    slots: dict = {}
    pid = str((out.get("last") or {}).get("provider_id") or "default")
    if any((legacy["done"], legacy["ts"], legacy["message"], legacy["pending"], legacy["fails"])):
        slots[pid] = legacy
    out["alert_state"] = slots
    return out


def burn_stats(history, provider_id: str = "", *, now: float | None = None, days: int = 7) -> dict:
    """从历史快照里算这钱花得快不快。纯函数，不碰框架。

    口径：相邻两次查成功之间的余额差，算在**后一次**那一天；余额往上走
    （充了值）记 0，不跟消耗混到一块儿。只用同一家、查成功、带 total 的快照。
    """
    days = max(1, int(days or 7))
    now_ts = time.time() if now is None else float(now)
    empty = {
        "ok": False,
        "today": 0.0,
        "perDay": 0.0,
        "windowSpent": 0.0,
        "left": None,
        "daysLeft": None,
        "currency": "",
        "points": [],
        "windowDays": days,
    }
    rows: list[tuple[float, float, str]] = []
    for row in history or []:
        if not isinstance(row, dict) or not row.get("ok"):
            continue
        if provider_id and str(row.get("provider_id") or "") != str(provider_id):
            continue
        try:
            epoch = float(row.get("epoch") or 0)
            total = float(row.get("total"))
        except (TypeError, ValueError):
            continue
        if epoch <= 0:
            continue
        rows.append((epoch, total, str(row.get("currency") or "")))
    if len(rows) < 2:
        return empty

    rows.sort()
    today = datetime.fromtimestamp(now_ts).date()
    start = today - timedelta(days=days - 1)
    buckets = {start + timedelta(days=i): 0.0 for i in range(days)}

    prev_total = rows[0][1]
    currency = rows[0][2]
    for epoch, total, cur in rows[1:]:
        if cur:
            currency = cur
        day = datetime.fromtimestamp(epoch).date()
        if day in buckets:
            diff = prev_total - total
            if diff > 0:
                buckets[day] += diff
        prev_total = total

    today_spent = round(buckets.get(today, 0.0), 2)
    window_spent = round(sum(buckets.values()), 2)
    # 只拿真花过钱的天算日均，别让没动静的日子把速度摊薄
    active_days = sum(1 for v in buckets.values() if v > 0)
    per_day = round(window_spent / active_days, 2) if active_days else 0.0
    left = round(rows[-1][1], 2)
    days_left = round(left / per_day, 1) if per_day > 0 and left > 0 else None
    return {
        "ok": True,
        "today": today_spent,
        "perDay": per_day,
        "windowSpent": window_spent,
        "left": left,
        "daysLeft": days_left,
        "currency": currency or "CNY",
        "points": [
            {"date": d.strftime("%m-%d"), "spent": round(v, 2)}
            for d, v in sorted(buckets.items())
        ],
        "windowDays": days,
    }


__all__ = [
    "PLUGIN_ID", "LOG_TAG", "PAGE_API_PREFIX", "TZ_NOTE", "ALERT_SPEAK_TIMEOUT",
    "LOCAL_HOSTS", "MAX_FIELD_LEN", "MAX_SESSION_LEN", "MAX_KEY_LEN",
    "SESSION_RE", "SESSION_UNDERSCORE_RE",
    "TOPUP_URLS", "TOPUP_URL_MOONSHOT_INTL", "TOPUP_HOSTS",
    "_topup_target", "topup_url_or_none", "_open_system_browser", "browser_open_allowed",
    "_hostname", "_origin", "validate_api_base", "redact_base",
    "_parse_deepseek", "_parse_siliconflow", "_parse_moonshot",
    "BALANCE_ADAPTERS", "SUPPORTED_KINDS", "_adapter_for",
    "_now", "_cfg_of", "_key_of", "_model_of", "_id_of", "_base_of",
    "mask_secret", "brief_provider", "sanitize_manual", "manual_view",
    "KEYRING_FILENAME", "ensure_local_key", "seal_secret", "unseal_secret",
    "normalize_session", "clean_spoken", "is_low_balance", "alert_due",
    "migrate_alert_state", "burn_stats", "logger",
]
