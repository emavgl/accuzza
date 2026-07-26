import os
import re
import uuid
import sqlite3
import hashlib
import secrets
import string
from datetime import datetime, timedelta
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, HTTPException, Cookie, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

MASTER_PASSWORD = os.environ["MASTER_PASSWORD"]
DB_PATH = os.environ.get("ACCUZZA_DB_PATH", "/app/data/accuzza.db")
SESSION_EXPIRY_HOURS = 24
CODE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
CODE_LENGTH = 6
CODE_ALPHABET = string.ascii_lowercase + string.digits
PWD_SALT = b"accuzza_v1"
PWD_ITERATIONS = 100000

sessions: dict[str, datetime] = {}


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            url TEXT NOT NULL,
            password_hash TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            click_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_links_code ON links(code)")
    conn.commit()
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Accuzza", lifespan=lifespan)

HTML_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")


def check_session(session_id: Optional[str]) -> bool:
    if not session_id:
        return False
    expiry = sessions.get(session_id)
    if expiry is None:
        return False
    if datetime.now() > expiry:
        del sessions[session_id]
        return False
    return True


def require_session(session_id: Optional[str] = Cookie(None)):
    if not check_session(session_id):
        raise HTTPException(401, "Unauthorized")
    return True


def hash_password(password: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), PWD_SALT, PWD_ITERATIONS).hex()


def generate_code(length: int = CODE_LENGTH) -> str:
    conn = get_db()
    existing = {row["code"] for row in conn.execute("SELECT code FROM links").fetchall()}
    conn.close()
    for _ in range(100):
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(length))
        if code not in existing:
            return code
    raise RuntimeError("Failed to generate unique code")


@app.get("/")
def index():
    with open(HTML_DIR) as f:
        return HTMLResponse(f.read())


class LoginRequest(BaseModel):
    password: str


class LinkCreate(BaseModel):
    url: str
    code: Optional[str] = None
    password: Optional[str] = None


class PasswordSubmit(BaseModel):
    password: str


@app.post("/api/login")
def api_login(req: LoginRequest, response: Response):
    if req.password != MASTER_PASSWORD:
        raise HTTPException(401, "Invalid master password")
    session_id = secrets.token_hex(32)
    sessions[session_id] = datetime.now() + timedelta(hours=SESSION_EXPIRY_HOURS)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_EXPIRY_HOURS * 3600,
    )
    return {"ok": True}


@app.get("/api/check")
def api_check(_=Depends(require_session)):
    return {"ok": True}


@app.get("/api/links")
def api_list_links(_=Depends(require_session)):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, code, url,
               CASE WHEN password_hash IS NOT NULL THEN 1 ELSE 0 END AS has_password,
               created_at, click_count
        FROM links
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return {"links": [dict(r) for r in rows]}


@app.post("/api/links")
def api_create_link(req: LinkCreate, _=Depends(require_session)):
    url = req.url.strip()
    if not url:
        raise HTTPException(400, "URL is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    code = (req.code or "").strip()
    if code:
        if not CODE_PATTERN.match(code):
            raise HTTPException(400, "Code must be 1-32 chars: letters, digits, hyphen, underscore")
        conn = get_db()
        existing = conn.execute("SELECT id FROM links WHERE code = ?", (code,)).fetchone()
        if existing:
            conn.close()
            raise HTTPException(409, "Code already taken")
        conn.close()
    else:
        code = generate_code()

    password_hash = None
    if req.password:
        password_hash = hash_password(req.password)

    conn = get_db()
    conn.execute(
        "INSERT INTO links (code, url, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (code, url, password_hash, datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "code": code}


@app.delete("/api/links/{link_id}")
def api_delete_link(link_id: int, _=Depends(require_session)):
    conn = get_db()
    cur = conn.execute("DELETE FROM links WHERE id = ?", (link_id,))
    deleted = cur.rowcount
    conn.commit()
    conn.close()
    if not deleted:
        raise HTTPException(404, "Link not found")
    return {"ok": True}


PASSWORD_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Protected Link &middot; Accuzza</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f1f5f9;display:flex;justify-content:center;align-items:center;min-height:100dvh;padding:20px}
.box{background:#fff;border-radius:16px;padding:32px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:360px;text-align:center}
h2{font-size:22px;margin:0 0 8px}
p{color:#64748b;font-size:14px;margin:0 0 20px;line-height:1.5}
input{width:100%;padding:12px 14px;font-size:15px;border:1px solid #e2e8f0;border-radius:10px;outline:none;box-sizing:border-box;transition:border-color .15s;font-family:inherit}
input:focus{border-color:#4f46e5}
button{width:100%;padding:12px;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;transition:background .15s;font-family:inherit}
button:hover{background:#3730a3}
.error{color:#ef4444;font-size:13px;margin-top:10px;min-height:18px}
</style>
</head>
<body>
<div class="box">
<h2>Protected Link</h2>
<p>This short link requires a password to access.</p>
<div><input type="text" id="pwd" placeholder="Enter link password" autocomplete="off" style="margin-bottom:12px"></div>
<button onclick="unlock()">Unlock</button>
<div class="error" id="err"></div>
</div>
<script>
async function unlock(){const p=document.getElementById('pwd');const e=document.getElementById('err');if(!p.value){e.textContent='Enter a password';return}
e.textContent='';try{const r=await fetch(window.location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:p.value})});if(r.ok){const d=await r.json();if(d.redirect)window.location.href=d.redirect}else{const d=await r.json();e.textContent=d.detail||'Wrong password'}}
catch(er){e.textContent='Connection error'}}
document.getElementById('pwd').addEventListener('keydown',function(e){if(e.key==='Enter')unlock()})
</script>
</body>
</html>
"""


@app.get("/{code}")
def handle_redirect(code: str):
    if code.startswith("api/") or code in ("", "favicon.ico", "robots.txt"):
        raise HTTPException(404, "Not found")

    conn = get_db()
    row = conn.execute(
        "SELECT id, url, password_hash FROM links WHERE code = ?", (code,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(404, "Link not found")

    if row["password_hash"]:
        return HTMLResponse(PASSWORD_PAGE)

    conn = get_db()
    conn.execute("UPDATE links SET click_count = click_count + 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()

    return RedirectResponse(url=row["url"], status_code=302)


@app.post("/{code}")
def handle_password_submit(code: str, req: PasswordSubmit):
    conn = get_db()
    row = conn.execute(
        "SELECT id, url, password_hash FROM links WHERE code = ?", (code,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(404, "Link not found")
    if not row["password_hash"]:
        conn.close()
        raise HTTPException(404, "Link not found")

    if hash_password(req.password) != row["password_hash"]:
        conn.close()
        raise HTTPException(403, "Wrong password")

    conn.execute("UPDATE links SET click_count = click_count + 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()

    return {"redirect": row["url"]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765)
