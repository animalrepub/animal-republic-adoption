import os, json, secrets, time, base64, uuid
import psycopg
from psycopg.rows import dict_row
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, session, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash

BASE=Path(__file__).resolve().parent
app=Flask(__name__,static_folder='static',static_url_path='/static')
secret=os.environ.get('APP_SECRET_KEY')
if not secret:
    raise RuntimeError('APP_SECRET_KEY 환경변수를 설정하세요.')
app.secret_key=secret
app.config.update(SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','1')=='1',MAX_CONTENT_LENGTH=7*1024*1024)
FAIL={}

# A small compatibility wrapper keeps the existing SQL parameter syntax and endpoints.
class Database:
    def __init__(self):
        url=os.environ.get('DATABASE_URL')
        if not url: raise RuntimeError('Render Environment에 DATABASE_URL을 설정하세요.')
        self.conn=psycopg.connect(url, row_factory=dict_row, connect_timeout=15)
    def __enter__(self): return self
    def __exit__(self,typ,val,tb):
        try:
            if typ: self.conn.rollback()
            else: self.conn.commit()
        finally: self.conn.close()
    def execute(self,sql,params=None):
        sql=sql.replace('?','%s').replace('ORDER BY rowid','ORDER BY id')
        return self.conn.execute(sql,params)
    def executemany(self,sql,params):
        with self.conn.cursor() as cur:
            cur.executemany(sql.replace('?','%s'),params)
        return self

    
def connect():return Database()

def init_db():
    with connect() as c:
        c.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS cats (id TEXT PRIMARY KEY, name TEXT NOT NULL, age TEXT, sex TEXT, personality TEXT, neuter TEXT, status TEXT, visible INTEGER, photo TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS applications (id TEXT PRIMARY KEY, name TEXT NOT NULL, cat TEXT, date TEXT, time TEXT, note TEXT, status TEXT, answers TEXT, created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP)')
        if not c.execute("SELECT 1 FROM settings WHERE key='password_hash'").fetchone():
            pw=os.environ.get('INITIAL_ADMIN_PASSWORD','')
            if len(pw)<12:raise RuntimeError('INITIAL_ADMIN_PASSWORD를 12자 이상으로 설정하세요.')
            c.execute('INSERT INTO settings VALUES (?,?)',('password_hash',generate_password_hash(pw)))
            c.execute('INSERT INTO settings VALUES (?,?)',('password_version','1'))
        if not c.execute('SELECT 1 FROM cats').fetchone():
            rows=[('cat1','신비','6살 추정','정보 미등록','사람을 좋아하지만 다른 고양이는 싫어해요.','중성화X','입양 가능',1,'/static/images/sinbi.jpg'),('cat2','베포','4살','정보 미등록','사람도 고양이도 모두 좋아해요.','중성화O','입양 가능',1,'/static/images/bepo.jpg'),('cat3','삼색이','6살','정보 미등록','사람과 고양이 모두 좋아하지만 사람의 관심을 독차지하고 싶어해요.','중성화X','입양 가능',1,'/static/images/samsaegi.jpg')]
            c.executemany('INSERT INTO cats VALUES (?,?,?,?,?,?,?,?,?)',rows)

def setting(c,k):
    row=c.execute('SELECT value FROM settings WHERE key=?',(k,)).fetchone();return row['value'] if row else None

def authorized(c):return session.get('admin') and session.get('version')==setting(c,'password_version')
def guard(f):
    @wraps(f)
    def wrapper(*args,**kwargs):
        with connect() as c:
            if not authorized(c):return jsonify(error='관리자 인증이 필요합니다. 다시 비밀번호를 입력하세요.'),401
        return f(*args,**kwargs)
    return wrapper

def csrf_guard():
    if request.method in ('POST','PUT','PATCH','DELETE') and request.path.startswith('/api/'):
        if request.headers.get('X-CSRF-Token')!=session.get('csrf') or not session.get('csrf'):
            return jsonify(error='보안 토큰이 유효하지 않습니다. 새로고침 후 다시 시도하세요.'),403
app.before_request(csrf_guard)

@app.get('/')
def index():return send_from_directory(BASE/'static','index.html')
@app.get('/api/bootstrap')
def bootstrap():
    session.setdefault('csrf',secrets.token_urlsafe(32))
    with connect() as c:
        cats=[dict(r) for r in c.execute('SELECT * FROM cats WHERE visible=1 ORDER BY rowid')]
        return jsonify(csrf=session['csrf'],admin=bool(authorized(c)),cats=cats)

@app.post('/api/admin/unlock')
def unlock():
    data=request.get_json(silent=True) or {};pw=data.get('password','')
    ip=request.remote_addr or 'unknown';now=time.monotonic();hits=[t for t in FAIL.get(ip,[]) if now-t<900];FAIL[ip]=hits
    if len(hits)>=8:return jsonify(error='입력 횟수가 많습니다. 15분 후 다시 시도하세요.'),429
    with connect() as c:
        if not isinstance(pw,str) or not check_password_hash(setting(c,'password_hash'),pw):
            FAIL[ip].append(now);return jsonify(error='비밀번호가 올바르지 않습니다.'),401
        FAIL.pop(ip,None);session.clear();session['admin']=True;session['version']=setting(c,'password_version');session['csrf']=secrets.token_urlsafe(32)
        return jsonify(ok=True,csrf=session['csrf'])

@app.post('/api/admin/lock')
def lock():session.clear();session['csrf']=secrets.token_urlsafe(32);return jsonify(ok=True,csrf=session['csrf'])

@app.post('/api/admin/password')
@guard
def change_password():
    data=request.get_json(silent=True) or {};old=data.get('old','');new=data.get('new','')
    if not isinstance(new,str) or len(new)<12 or len(new)>128:return jsonify(error='새 비밀번호는 12~128자로 입력해 주세요.'),400
    with connect() as c:
        if not check_password_hash(setting(c,'password_hash'),old):return jsonify(error='기존 비밀번호가 틀립니다.'),403
        version=str(int(setting(c,'password_version'))+1)
        c.execute('UPDATE settings SET value=? WHERE key=?',(generate_password_hash(new),'password_hash'))
        c.execute('UPDATE settings SET value=? WHERE key=?',(version,'password_version'))
    session.clear();session['csrf']=secrets.token_urlsafe(32)
    return jsonify(ok=True,csrf=session['csrf'],message='공통 비밀번호가 변경되었습니다. 모든 관리자 기기에서 다시 입력해야 합니다.')

@app.get('/api/admin/data')
@guard
def admin_data():
    with connect() as c:
        return jsonify(cats=[dict(r) for r in c.execute('SELECT * FROM cats ORDER BY id')],applications=[{**dict(r),'answers':json.loads(r['answers'])} for r in c.execute('SELECT * FROM applications ORDER BY created_at DESC')])

@app.post('/api/admin/cats')
@guard
def save_cat():
    d=request.get_json(silent=True) or {}
    name=str(d.get('name','')).strip()
    if not name or len(name)>80:return jsonify(error='고양이 이름을 확인해 주세요.'),400
    status=d.get('status','입양 가능');neuter=d.get('neuter','정보 미등록')
    if status not in ('입양 가능','상담 중','입양 완료') or neuter not in ('중성화O','중성화X','정보 미등록'):return jsonify(error='선택값이 유효하지 않습니다.'),400
    id=str(d.get('id') or uuid.uuid4().hex)
    photo=str(d.get('photo') or '')
    if not (photo.startswith('/static/images/') or photo.startswith('data:image/jpeg;base64,') or photo.startswith('data:image/png;base64,') or photo.startswith('data:image/webp;base64,') or not photo):return jsonify(error='사진 형식이 올바르지 않습니다.'),400
    if len(photo)>4_000_000:return jsonify(error='사진이 너무 큽니다.'),400
    vals=(id,name,str(d.get('age',''))[:80],str(d.get('sex','정보 미등록'))[:40],str(d.get('personality',''))[:2000],neuter,status,int(bool(d.get('visible',True))),photo)
    with connect() as c:
        c.execute('INSERT INTO cats VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,age=excluded.age,sex=excluded.sex,personality=excluded.personality,neuter=excluded.neuter,status=excluded.status,visible=excluded.visible,photo=excluded.photo',vals)
    return jsonify(ok=True,id=id)

@app.delete('/api/admin/cats/<id>')
@guard
def delete_cat(id):
    with connect() as c:c.execute('DELETE FROM cats WHERE id=?',(id,))
    return jsonify(ok=True)

@app.post('/api/applications')
def apply():
    d=request.get_json(silent=True) or {};a=d.get('answers') or {};date=d.get('date','');tm=d.get('time','')
    if not isinstance(a,dict) or not str(a.get('2','')).strip() or not str(a.get('4','')).strip() or not date or not tm:return jsonify(error='필수 설문과 상담 희망 일정을 입력해 주세요.'),400
    if len(json.dumps(a,ensure_ascii=False))>20000:return jsonify(error='설문 입력이 너무 깁니다.'),400
    if a.get('1')!='동의 합니다.':return jsonify(error='개인정보 수집·이용 동의가 필요합니다.'),400
    with connect() as c:
        c.execute('INSERT INTO applications(id,name,cat,date,time,note,status,answers) VALUES(?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,str(a['2'])[:80],str(a.get('19',''))[:80],str(date)[:20],str(tm)[:10],str(d.get('note',''))[:2000],'승인 대기',json.dumps(a,ensure_ascii=False)))
    return jsonify(ok=True,message='상담 신청이 접수되었습니다. 예약은 관리자 확인 후 확정됩니다.')

@app.patch('/api/admin/applications/<id>')
@guard
def application_status(id):
    d=request.get_json(silent=True) or {};status=d.get('status')
    if status not in ('승인 대기','승인 완료','상담 완료','취소'):return jsonify(error='상태가 유효하지 않습니다.'),400
    with connect() as c:c.execute('UPDATE applications SET status=? WHERE id=?',(status,id))
    return jsonify(ok=True)

if __name__=='__main__':
    init_db();app.run(host='127.0.0.1',port=int(os.environ.get('PORT','5000')),debug=False)
