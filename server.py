Import os
import json
import time
import asyncio
import re
import hashlib
import secrets
from typing import Optional, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from telethon import TelegramClient
from telethon.sessions import StringSession
from telethon.tl.types import Channel
from telethon.errors import (
    SessionPasswordNeededError,
    PhoneCodeInvalidError,
    PhoneCodeExpiredError,
    PasswordHashInvalidError,
    FloodWaitError,
    PhoneNumberInvalidError,
    ChatWriteForbiddenError,
    UserBannedInChannelError,
    SlowModeWaitError,
)

DATA_FILE = "data.json"
PENDING: Dict[str, dict] = {}
MAILING_TASKS: Dict[int, asyncio.Task] = {}
TOKENS: Dict[str, dict] = {}  # token -> {user_id, username, is_admin}


# ═══════════════════════════════════════════════
# DATA HELPERS
# ═══════════════════════════════════════════════
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
                if "users" not in d:
                    d["users"] = []
                if "accounts" not in d:
                    d["accounts"] = []
                if "mailings" not in d:
                    d["mailings"] = []
                return d
        except Exception:
            pass
    # Создаём админа по умолчанию
    return {
        "users": [{
            "id": 1,
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "is_admin": True,
            "created_at": time.time(),
        }],
        "accounts": [],
        "mailings": [],
    }


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def parse_proxy(proxy_str):
    if not proxy_str:
        return None
    try:
        m = re.match(r"(socks5|socks4|http)://(?:([^:]+):([^@]+)@)?([\w\.\-]+):(\d+)", proxy_str.strip())
        if not m:
            return None
        proto, user, pwd, host, port = m.groups()
        proxy_type = {"socks5": 2, "socks4": 1, "http": 3}.get(proto, 2)
        if user and pwd:
            return (proxy_type, host, int(port), True, user, pwd)
        return (proxy_type, host, int(port))
    except Exception:
        return None


# ═══════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════
def get_user_by_token(authorization: Optional[str]) -> dict:
    if not authorization:
        raise HTTPException(401, "Не авторизован")
    token = authorization.replace("Bearer ", "").strip()
    if token not in TOKENS:
        raise HTTPException(401, "Неверный токен")
    return TOKENS[token]


def require_admin(authorization: Optional[str]) -> dict:
    user = get_user_by_token(authorization)
    if not user.get("is_admin"):
        raise HTTPException(403, "Доступ только для администратора")
    return user


# ═══════════════════════════════════════════════
# LIFESPAN
# ═══════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Инициализация: создаём data.json если его нет
    if not os.path.exists(DATA_FILE):
        save_data(load_data())
    yield
    for p in list(PENDING.values()):
        try:
            await p["client"].disconnect()
        except Exception:
            pass
    for t in MAILING_TASKS.values():
        t.cancel()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ═══════════════════════════════════════════════
# STATIC
# ═══════════════════════════════════════════════
@app.get("/")
async def root():
    path = "static/index.html"
    if os.path.exists(path):
        return FileResponse(path)
    return {"error": "static/index.html not found"}


@app.get("/health")
async def health():
    return {"ok": True}


# ═══════════════════════════════════════════════
# MODELS
# ═══════════════════════════════════════════════
class LoginReq(BaseModel):
    username: str
    password: str


class CreateUserReq(BaseModel):
    username: str
    password: str


class SendCodeReq(BaseModel):
    phone: str
    api_id: int
    api_hash: str
    proxy: Optional[str] = None


class ConfirmReq(BaseModel):
    phone: str
    code: str
    password: Optional[str] = None


class CreateMailingReq(BaseModel):
    account_id: int
    name: str
    text: str
    delay: int = 60


# ═══════════════════════════════════════════════
# AUTH ENDPOINTS
# ═══════════════════════════════════════════════
@app.post("/api/login")
async def login(req: LoginReq):
    data = load_data()
    pwd_hash = hash_password(req.password)
    user = next(
        (u for u in data["users"] if u["username"] == req.username and u["password_hash"] == pwd_hash),
        None,
    )
    if not user:
        raise HTTPException(401, "Неверный логин или пароль")

    token = secrets.token_urlsafe(32)
    TOKENS[token] = {
        "user_id": user["id"],
        "username": user["username"],
        "is_admin": user.get("is_admin", False),
    }
    return {
        "ok": True,
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "is_admin": user.get("is_admin", False),
        },
    }


@app.post("/api/logout")
async def logout(authorization: Optional[str] = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        TOKENS.pop(token, None)
    return {"ok": True}


@app.get("/api/me")
async def me(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    return {"ok": True, "user": user}


# ═══════════════════════════════════════════════
# USERS MANAGEMENT (ADMIN)
# ═══════════════════════════════════════════════
@app.get("/api/users")
async def get_users(authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    data = load_data()
    return {
        "ok": True,
        "users": [
            {
                "id": u["id"],
                "username": u["username"],
                "is_admin": u.get("is_admin", False),
                "created_at": u.get("created_at", 0),
            }
            for u in data["users"]
        ],
    }


@app.post("/api/users")
async def create_user(req: CreateUserReq, authorization: Optional[str] = Header(None)):
    require_admin(authorization)
    if not req.username.strip() or not req.password.strip():
        raise HTTPException(400, "Заполните логин и пароль")
    if len(req.password) < 4:
        raise HTTPException(400, "Пароль слишком короткий (минимум 4 символа)")

    data = load_data()
    if any(u["username"] == req.username for u in data["users"]):
        raise HTTPException(400, "Пользователь с таким логином уже существует")

    new_user = {
        "id": int(time.time() * 1000),
        "username": req.username.strip(),
        "password_hash": hash_password(req.password),
        "is_admin": False,
        "created_at": time.time(),
    }
    data["users"].append(new_user)
    save_data(data)
    return {
        "ok": True,
        "user": {
            "id": new_user["id"],
            "username": new_user["username"],
            "is_admin": False,
        },
    }


@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, authorization: Optional[str] = Header(None)):
    admin = require_admin(authorization)
    if user_id == admin["user_id"]:
        raise HTTPException(400, "Нельзя удалить самого себя")
    data = load_data()
    target = next((u for u in data["users"] if u["id"] == user_id), None)
    if not target:
        raise HTTPException(404, "Пользователь не найден")
    if target.get("is_admin"):
        raise HTTPException(400, "Нельзя удалить администратора")

    data["users"] = [u for u in data["users"] if u["id"] != user_id]
    # Удаляем токены этого юзера
    for tk in list(TOKENS.keys()):
        if TOKENS[tk]["user_id"] == user_id:
            TOKENS.pop(tk, None)
    save_data(data)
    return {"ok": True}


# ═══════════════════════════════════════════════
# TELEGRAM: SEND CODE
# ═══════════════════════════════════════════════
@app.post("/api/send-code")
async def send_code(req: SendCodeReq, authorization: Optional[str] = Header(None)):
    get_user_by_token(authorization)

    if req.phone in PENDING:
        try:
            await PENDING[req.phone]["client"].disconnect()
        except Exception:
            pass
        PENDING.pop(req.phone, None)

    proxy = parse_proxy(req.proxy) if req.proxy else None
    client = TelegramClient(
        StringSession(), req.api_id, req.api_hash, proxy=proxy,
        device_model="Nebula Web", system_version="1.0", app_version="1.0",
        connection_retries=3, timeout=30,
    )
    try:
        await client.connect()
        if await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(400, "Этот аккаунт уже авторизован")
        sent = await client.send_code_request(req.phone)
        PENDING[req.phone] = {
            "client": client,
            "phone_hash": sent.phone_code_hash,
            "api_id": req.api_id,
            "api_hash": req.api_hash,
            "proxy": req.proxy,
            "ts": time.time(),
        }
        return {"ok": True, "type": sent.type.__class__.__name__, "message": "Код отправлен"}
    except PhoneNumberInvalidError:
        await client.disconnect()
        raise HTTPException(400, "Неверный формат номера")
    except FloodWaitError as e:
        await client.disconnect()
        raise HTTPException(429, f"Подождите {e.seconds} сек")
    except HTTPException:
        raise
    except Exception as e:
        try:
            await client.disconnect()
        except Exception:
            pass
        raise HTTPException(500, f"Ошибка: {str(e)}")


@app.post("/api/confirm-code")
async def confirm_code(req: ConfirmReq, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)

    if req.phone not in PENDING:
        raise HTTPException(400, "Сначала запросите код")

    sess = PENDING[req.phone]
    client = sess["client"]

    if time.time() - sess["ts"] > 600:
        try:
            await client.disconnect()
        except Exception:
            pass
        PENDING.pop(req.phone, None)
        raise HTTPException(400, "Код устарел")

    try:
        await client.sign_in(phone=req.phone, code=req.code, phone_code_hash=sess["phone_hash"])
    except SessionPasswordNeededError:
        if not req.password:
            return {"ok": False, "need_2fa": True, "message": "Требуется 2FA"}
        try:
            await client.sign_in(password=req.password)
        except PasswordHashInvalidError:
            raise HTTPException(400, "Неверный 2FA пароль")
    except PhoneCodeInvalidError:
        raise HTTPException(400, "Неверный код")
    except PhoneCodeExpiredError:
        try:
            await client.disconnect()
        except Exception:
            pass
        PENDING.pop(req.phone, None)
        raise HTTPException(400, "Код истёк")
    except Exception as e:
        raise HTTPException(500, f"Ошибка: {str(e)}")

    try:
        me_user = await client.get_me()
        session_string = client.session.save()
        supergroups = []
        async for dialog in client.iter_dialogs():
            ent = dialog.entity
            if isinstance(ent, Channel) and getattr(ent, "megagroup", False):
                supergroups.append({
                    "id": dialog.id,
                    "title": dialog.title or "Без названия",
                    "members": getattr(ent, "participants_count", 0) or 0,
                })

        data = load_data()
        data["accounts"] = [a for a in data["accounts"] if a.get("phone") != req.phone]
        account_id = int(time.time() * 1000)
        data["accounts"].append({
            "id": account_id,
            "owner_id": user["user_id"],
            "phone": req.phone,
            "api_id": sess["api_id"],
            "api_hash": sess["api_hash"],
            "proxy": sess["proxy"],
            "session_string": session_string,
            "username": me_user.username or "",
            "first_name": me_user.first_name or "",
            "supergroups": supergroups,
            "created_at": time.time(),
        })
        save_data(data)
        await client.disconnect()
        PENDING.pop(req.phone, None)
        return {"ok": True, "account": {
            "id": account_id, "phone": req.phone,
            "username": me_user.username, "first_name": me_user.first_name,
            "supergroups_count": len(supergroups),
        }}
    except Exception as e:
        raise HTTPException(500, f"Ошибка сбора чатов: {str(e)}")


# ═══════════════════════════════════════════════
# ACCOUNTS
# ═══════════════════════════════════════════════
@app.get("/api/accounts")
async def get_accounts(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    # Админ видит все, обычный юзер — только свои
    if user.get("is_admin"):
        accs = data["accounts"]
    else:
        accs = [a for a in data["accounts"] if a.get("owner_id") == user["user_id"]]
    return {"ok": True, "accounts": [{
        "id": a["id"], "phone": a["phone"],
        "username": a.get("username", ""), "first_name": a.get("first_name", ""),
        "supergroups_count": len(a.get("supergroups", [])),
        "supergroups": a.get("supergroups", []),
        "proxy": bool(a.get("proxy")),
    } for a in accs]}


@app.delete("/api/accounts/{account_id}")
async def delete_account(account_id: int, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    acc = next((a for a in data["accounts"] if a["id"] == account_id), None)
    if not acc:
        raise HTTPException(404, "Не найден")
    if not user.get("is_admin") and acc.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа")

    data["accounts"] = [a for a in data["accounts"] if a["id"] != account_id]
    for m in data["mailings"]:
        if m.get("account_id") == account_id and m["id"] in MAILING_TASKS:
            MAILING_TASKS[m["id"]].cancel()
            MAILING_TASKS.pop(m["id"], None)
    data["mailings"] = [m for m in data["mailings"] if m.get("account_id") != account_id]
    save_data(data)
    return {"ok": True}


@app.post("/api/accounts/{account_id}/refresh")
async def refresh_groups(account_id: int, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    acc = next((a for a in data["accounts"] if a["id"] == account_id), None)
    if not acc:
        raise HTTPException(404, "Не найден")
    if not user.get("is_admin") and acc.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа")

    proxy = parse_proxy(acc.get("proxy")) if acc.get("proxy") else None
    client = TelegramClient(StringSession(acc["session_string"]), acc["api_id"], acc["api_hash"], proxy=proxy)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            await client.disconnect()
            raise HTTPException(401, "Сессия истекла")
        supergroups = []
        async for dialog in client.iter_dialogs():
            ent = dialog.entity
            if isinstance(ent, Channel) and getattr(ent, "megagroup", False):
                supergroups.append({
                    "id": dialog.id, "title": dialog.title or "Без названия",
                    "members": getattr(ent, "participants_count", 0) or 0,
                })
        acc["supergroups"] = supergroups
        save_data(data)
        await client.disconnect()
        return {"ok": True, "count": len(supergroups), "supergroups": supergroups}
    except HTTPException:
        raise
    except Exception as e:
        try:
            await client.disconnect()
        except Exception:
            pass
        raise HTTPException(500, str(e))


# ═══════════════════════════════════════════════
# MAILINGS
# ═══════════════════════════════════════════════
@app.post("/api/mailings")
async def create_mailing(req: CreateMailingReq, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    acc = next((a for a in data["accounts"] if a["id"] == req.account_id), None)
    if not acc:
        raise HTTPException(404, "Аккаунт не найден")
    if not user.get("is_admin") and acc.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа к аккаунту")
    if not acc.get("supergroups"):
        raise HTTPException(400, "Нет супергрупп")

    mailing = {
        "id": int(time.time() * 1000),
        "owner_id": user["user_id"],
        "account_id": req.account_id,
        "name": req.name, "text": req.text, "delay": max(3, req.delay),
        "total": len(acc["supergroups"]), "sent": 0, "failed": 0,
        "status": "stopped", "last_error": "", "created_at": time.time(),
    }
    data["mailings"].append(mailing)
    save_data(data)
    return {"ok": True, "mailing": mailing}


@app.get("/api/mailings")
async def get_mailings(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    if user.get("is_admin"):
        ms = data["mailings"]
    else:
        ms = [m for m in data["mailings"] if m.get("owner_id") == user["user_id"]]
    return {"ok": True, "mailings": ms}


@app.delete("/api/mailings/{mailing_id}")
async def delete_mailing(mailing_id: int, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    m = next((mm for mm in data["mailings"] if mm["id"] == mailing_id), None)
    if not m:
        raise HTTPException(404, "Не найдена")
    if not user.get("is_admin") and m.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа")
    if mailing_id in MAILING_TASKS:
        MAILING_TASKS[mailing_id].cancel()
        MAILING_TASKS.pop(mailing_id, None)
    data["mailings"] = [mm for mm in data["mailings"] if mm["id"] != mailing_id]
    save_data(data)
    return {"ok": True}


async def run_mailing(mailing_id: int):
    data = load_data()
    mailing = next((m for m in data["mailings"] if m["id"] == mailing_id), None)
    if not mailing:
        return
    acc = next((a for a in data["accounts"] if a["id"] == mailing["account_id"]), None)
    if not acc:
        return
    proxy = parse_proxy(acc.get("proxy")) if acc.get("proxy") else None
    client = TelegramClient(StringSession(acc["session_string"]), acc["api_id"], acc["api_hash"], proxy=proxy)
    try:
        await client.connect()
        if not await client.is_user_authorized():
            mailing["status"] = "stopped"
            mailing["last_error"] = "Сессия истекла"
            save_data(data)
            return
        groups = acc.get("supergroups", [])
        mailing["total"] = len(groups)
        mailing["sent"] = 0
        mailing["failed"] = 0
        mailing["last_error"] = ""
        save_data(data)

        for group in groups:
            data = load_data()
            mailing = next((m for m in data["mailings"] if m["id"] == mailing_id), None)
            if not mailing or mailing["status"] != "running":
                break
            try:
                await client.send_message(group["id"], mailing["text"])
                mailing["sent"] += 1
            except FloodWaitError as e:
                mailing["failed"] += 1
                mailing["last_error"] = f"FloodWait {e.seconds}s"
                save_data(data)
                await asyncio.sleep(e.seconds + 1)
                continue
            except (ChatWriteForbiddenError, UserBannedInChannelError):
                mailing["failed"] += 1
                mailing["last_error"] = f"Нет прав: {group['title']}"
            except SlowModeWaitError as e:
                mailing["failed"] += 1
                mailing["last_error"] = f"Slow mode {e.seconds}s"
            except Exception as e:
                mailing["failed"] += 1
                mailing["last_error"] = f"{group['title']}: {str(e)[:80]}"
            save_data(data)
            for _ in range(mailing["delay"]):
                await asyncio.sleep(1)
                d2 = load_data()
                m2 = next((m for m in d2["mailings"] if m["id"] == mailing_id), None)
                if not m2 or m2["status"] != "running":
                    break

        data = load_data()
        mailing = next((m for m in data["mailings"] if m["id"] == mailing_id), None)
        if mailing and mailing["status"] == "running":
            mailing["status"] = "finished"
            save_data(data)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        data = load_data()
        mailing = next((m for m in data["mailings"] if m["id"] == mailing_id), None)
        if mailing:
            mailing["status"] = "stopped"
            mailing["last_error"] = str(e)[:120]
            save_data(data)
    finally:
        try:
            await client.disconnect()
        except Exception:
            pass
        MAILING_TASKS.pop(mailing_id, None)


@app.post("/api/mailings/{mailing_id}/start")
async def start_mailing(mailing_id: int, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    m = next((mm for mm in data["mailings"] if mm["id"] == mailing_id), None)
    if not m:
        raise HTTPException(404, "Не найдена")
    if not user.get("is_admin") and m.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа")
    if mailing_id in MAILING_TASKS and not MAILING_TASKS[mailing_id].done():
        raise HTTPException(400, "Уже запущена")
    m["status"] = "running"
    m["sent"] = 0
    m["failed"] = 0
    m["last_error"] = ""
    save_data(data)
    MAILING_TASKS[mailing_id] = asyncio.create_task(run_mailing(mailing_id))
    return {"ok": True}


@app.post("/api/mailings/{mailing_id}/stop")
async def stop_mailing(mailing_id: int, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    data = load_data()
    m = next((mm for mm in data["mailings"] if mm["id"] == mailing_id), None)
    if not m:
        raise HTTPException(404, "Не найдена")
    if not user.get("is_admin") and m.get("owner_id") != user["user_id"]:
        raise HTTPException(403, "Нет доступа")
    m["status"] = "stopped"
    save_data(data)
    if mailing_id in MAILING_TASKS:
        MAILING_TASKS[mailing_id].cancel()
        MAILING_TASKS.pop(mailing_id, None)
    return {"ok": True}


if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
