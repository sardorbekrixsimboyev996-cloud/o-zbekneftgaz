import asyncio, hashlib, hmac, json, os, re, secrets, sqlite3, time
from contextlib import contextmanager, asynccontextmanager
from pathlib import Path
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

DATA = Path(os.getenv('DATA_DIR', './data'))
DATA.mkdir(parents=True, exist_ok=True)
UPLOADS = DATA / 'uploads'; UPLOADS.mkdir(exist_ok=True)
@contextmanager
def db():
    c = sqlite3.connect(DATA / 'app.db', timeout=30)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    try:
        yield c
        c.commit()
    finally: c.close()

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + ':' + hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

def verify(password, encoded):
    return hmac.compare_digest(password_hash(password, encoded.split(':')[0]), encoded)

def initialize():
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, nickname TEXT UNIQUE NOT NULL, name TEXT NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id), expires REAL);
        CREATE TABLE IF NOT EXISTS metrics(period TEXT PRIMARY KEY, revenue REAL, expenses REAL, profit REAL, gas REAL, oil REAL, investment REAL, updated_at REAL);
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, name TEXT, size INTEGER, owner INTEGER REFERENCES users(id), created_at REAL);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, created_at REAL);
        CREATE TABLE IF NOT EXISTS attempts(nickname TEXT PRIMARY KEY, count INTEGER, started REAL);
        ''')

def audit(c, uid, action):
    c.execute('INSERT INTO audit(user_id,action,created_at) VALUES(?,?,?)',(uid,action,time.time()))

def public(u): return {k:u[k] for k in ('id','nickname','name','role','active')}
def user_for(token):
    with db() as c:
        u=c.execute('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=? AND s.expires>? AND u.active=1',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
    return dict(u) if u else None

bearer=HTTPBearer(auto_error=False)
def current(auth: HTTPAuthorizationCredentials=Depends(bearer)):
    u=user_for(auth.credentials) if auth else None
    if not u: raise HTTPException(401,'Qayta kiring.')
    return u

def admin(u=Depends(current)):
    if u['role']!='admin': raise HTTPException(403,'Faqat administrator uchun.')
    return u

sockets: dict[WebSocket,str] = {}
async def broadcast():
    for ws,token in list(sockets.items()):
        try:
            if not user_for(token): await ws.close(code=4401); sockets.pop(ws,None)
            else: await asyncio.wait_for(ws.send_json({'type':'changed'}), 3)
        except Exception: sockets.pop(ws,None)

def bootstrap_admin():
    # Only the first account is provisioned; existing credentials are never reset.
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        if c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
            return
        nickname = os.getenv('ADMIN_LOGIN', '').strip().lower()
        password = os.getenv('ADMIN_PASSWORD', '')
        if not nickname and not password:
            return
        if not re.fullmatch(r'[a-z0-9_.-]{3,50}', nickname):
            raise RuntimeError('ADMIN_LOGIN must contain 3-50 lowercase letters, digits, _, . or -')
        if not 10 <= len(password) <= 128:
            raise RuntimeError('ADMIN_PASSWORD must contain 10-128 characters')
        name = os.getenv('ADMIN_NAME', nickname).strip()[:100] or nickname
        c.execute('INSERT INTO users(nickname,name,password,role) VALUES(?,?,?,?)',
                  (nickname, name, password_hash(password), 'admin'))
        audit(c, c.execute('SELECT id FROM users WHERE nickname=?', (nickname,)).fetchone()['id'], 'bootstrap_admin')

@asynccontextmanager
async def lifespan(app):
    initialize()
    bootstrap_admin()
    yield
app=FastAPI(title='UNG Analitika API',lifespan=lifespan)

class Login(BaseModel):
    nickname:str=Field(min_length=1,max_length=50)
    password:str=Field(min_length=1,max_length=128)
class UserCreate(Login):
    name:str=Field(min_length=1,max_length=100)
    role:Literal['admin','employee','viewer']='viewer'
class UserEdit(BaseModel):
    active:bool
class Password(BaseModel):
    old_password:str=Field(max_length=128)
    new_password:str=Field(min_length=10,max_length=128)
class Profile(BaseModel):
    name:str=Field(min_length=1,max_length=100)
class Metric(BaseModel):
    period:str=Field(pattern=r'^\d{4}-(0[1-9]|1[0-2])$')
    revenue:float=Field(ge=0,le=1e15,allow_inf_nan=False)
    expenses:float=Field(ge=0,le=1e15,allow_inf_nan=False)
    profit:float=Field(ge=-1e15,le=1e15,allow_inf_nan=False)
    gas:float=Field(ge=0,le=1e12,allow_inf_nan=False)
    oil:float=Field(ge=0,le=1e12,allow_inf_nan=False)
    investment:float=Field(ge=0,le=1e15,allow_inf_nan=False)

@app.get('/health')
def health():
    with db() as c: c.execute('SELECT 1')
    return {'status':'ok'}

@app.post('/auth/login')
def login(body:Login):
    nick=body.nickname.strip().lower(); now=time.time()
    with db() as c:
        a=c.execute('SELECT * FROM attempts WHERE nickname=?',(nick,)).fetchone()
        if a and a['count']>=10 and now-a['started']<900: raise HTTPException(429,'15 daqiqadan keyin qayta urining.')
        u=c.execute('SELECT * FROM users WHERE nickname=?',(nick,)).fetchone()
        valid=u and u['active'] and verify(body.password,u['password'])
        if not valid:
            count=a['count']+1 if a and now-a['started']<900 else 1
            started=a['started'] if count>1 else now
            c.execute('INSERT OR REPLACE INTO attempts VALUES(?,?,?)',(nick,count,started))
        else:
            c.execute('DELETE FROM attempts WHERE nickname=?',(nick,))
            c.execute('DELETE FROM sessions WHERE expires<?',(now,))
            token=secrets.token_urlsafe(32)
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],now+7*86400))
            audit(c,u['id'],'login')
    if not valid: raise HTTPException(401,'Login yoki parol noto‘g‘ri.')
    return {'token':token,'user':public(u)}

@app.post('/auth/logout')
async def logout(auth:HTTPAuthorizationCredentials=Depends(bearer),u=Depends(current)):
    with db() as c: c.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(auth.credentials.encode()).hexdigest(),))
    await broadcast(); return {'ok':True}
@app.get('/me')
def me(u=Depends(current)): return public(u)
@app.patch('/me')
async def profile(body:Profile,u=Depends(current)):
    with db() as c: c.execute('UPDATE users SET name=? WHERE id=?',(body.name.strip(),u['id']))
    await broadcast(); return {'ok':True}
@app.post('/me/password')
async def change_password(body:Password,u=Depends(current)):
    if not verify(body.old_password,u['password']): raise HTTPException(400,'Joriy parol noto‘g‘ri.')
    with db() as c:
        c.execute('UPDATE users SET password=? WHERE id=?',(password_hash(body.new_password),u['id']))
        c.execute('DELETE FROM sessions WHERE user_id=?',(u['id'],))
        audit(c,u['id'],'password_changed')
    await broadcast(); return {'ok':True}
@app.get('/dashboard')
def dashboard(u=Depends(current)):
    with db() as c:
        rows=[dict(r) for r in c.execute('SELECT * FROM metrics ORDER BY period')]
    return {'history':rows,'latest':rows[-1] if rows else None,'server_time':time.time()}
@app.put('/metrics')
async def metrics(body:Metric,u=Depends(admin)):
    with db() as c:
        c.execute('INSERT OR REPLACE INTO metrics VALUES(?,?,?,?,?,?,?,?)',(*body.model_dump().values(),time.time()))
        audit(c,u['id'],'metrics:'+body.period)
    await broadcast(); return {'ok':True}
@app.get('/reports')
def reports(u=Depends(current)):
    with db() as c: return [dict(r) for r in c.execute('SELECT * FROM reports ORDER BY created_at DESC')]
@app.post('/reports')
async def upload(file:UploadFile=File(...),u=Depends(current)):
    if u['role']=='viewer': raise HTTPException(403,'Yuklash huquqi yo‘q.')
    name=Path((file.filename or '').replace('\\','/')).name[:160]
    if Path(name).suffix.lower() not in ('.pdf','.xlsx','.xls','.csv'): raise HTTPException(400,'PDF, Excel yoki CSV tanlang.')
    rid=secrets.token_hex(16); path=UPLOADS/rid; size=0
    try:
        with path.open('wb') as f:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>20*1024*1024: raise HTTPException(413,'Maksimal hajm 20 MB.')
                f.write(chunk)
        if not size: raise HTTPException(400,'Fayl bo‘sh.')
        with db() as c:
            c.execute('INSERT INTO reports VALUES(?,?,?,?,?)',(rid,name,size,u['id'],time.time()))
            audit(c,u['id'],'upload:'+name)
    except BaseException:
        path.unlink(missing_ok=True); raise
    finally: await file.close()
    await broadcast(); return {'id':rid}
@app.get('/reports/{rid}/download')
def download(rid:str,u=Depends(current)):
    with db() as c: r=c.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone()
    if not r or not (UPLOADS/r['id']).is_file(): raise HTTPException(404,'Fayl topilmadi.')
    return FileResponse(UPLOADS/r['id'],filename=r['name'],media_type='application/octet-stream')
@app.delete('/reports/{rid}')
async def delete_report(rid:str,u=Depends(admin)):
    with db() as c:
        r=c.execute('SELECT * FROM reports WHERE id=?',(rid,)).fetchone()
        if not r: raise HTTPException(404,'Topilmadi.')
        c.execute('DELETE FROM reports WHERE id=?',(rid,)); audit(c,u['id'],'delete_report:'+r['name'])
    (UPLOADS/r['id']).unlink(missing_ok=True)
    await broadcast(); return {'ok':True}
@app.get('/admin/users')
def users(u=Depends(admin)):
    with db() as c: return [public(r) for r in c.execute('SELECT * FROM users ORDER BY id')]
@app.post('/admin/users')
async def create_user(body:UserCreate,u=Depends(admin)):
    nick=body.nickname.strip().lower()
    if not re.fullmatch(r'[a-z0-9_.-]{3,50}',nick) or len(body.password)<10: raise HTTPException(400,'Login kamida 3 belgi, parol kamida 10 belgi bo‘lsin.')
    try:
        with db() as c:
            c.execute('INSERT INTO users(nickname,name,password,role) VALUES(?,?,?,?)',(nick,body.name,password_hash(body.password),body.role)); audit(c,u['id'],'create_user:'+nick)
    except sqlite3.IntegrityError: raise HTTPException(409,'Bu login band.')
    await broadcast(); return {'ok':True}
@app.patch('/admin/users/{uid}')
async def edit_user(uid:int,body:UserEdit,u=Depends(admin)):
    if uid==u['id']: raise HTTPException(400,'O‘zingizni bloklay olmaysiz.')
    with db() as c:
        if not c.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone(): raise HTTPException(404,'Topilmadi.')
        c.execute('UPDATE users SET active=? WHERE id=?',(body.active,uid))
        if not body.active: c.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
        audit(c,u['id'],f'user_active:{uid}:{body.active}')
    await broadcast(); return {'ok':True}
@app.get('/admin/audit')
def audit_list(u=Depends(admin)):
    with db() as c: return [dict(r) for r in c.execute('SELECT a.*,u.nickname FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100')]

@app.websocket('/ws')
async def events(ws:WebSocket):
    await ws.accept()
    try:
        msg=await asyncio.wait_for(ws.receive_json(),10)
        token=msg.get('token','') if isinstance(msg,dict) else ''
        if not isinstance(token,str) or not token or not user_for(token): await ws.close(code=4401); return
        sockets[ws]=token
        await ws.send_json({'type':'connected'})
        while True:
            try: await asyncio.wait_for(ws.receive_text(),30)
            except asyncio.TimeoutError: pass
            if not user_for(token): await ws.close(code=4401); return
            await ws.send_json({'type':'ping'})
    except (WebSocketDisconnect, asyncio.TimeoutError, RuntimeError, ValueError): pass
    finally: sockets.pop(ws,None)
