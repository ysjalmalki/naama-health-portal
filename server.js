'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {DatabaseSync}=require('node:sqlite');
const PORT=Number(process.env.PORT||3000), PASS=process.env.ADMIN_PASSWORD, COOKIE_SECURE=process.env.NODE_ENV==='production';
if(!PASS||PASS.length<16) {console.error('Set ADMIN_PASSWORD to a unique password of at least 16 characters');process.exit(1)}
const dataDir=process.env.DATA_DIR||path.join(__dirname,'data');fs.mkdirSync(dataDir,{recursive:true,mode:0o700});
const db=new DatabaseSync(path.join(dataDir,'portal.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS works(id INTEGER PRIMARY KEY AUTOINCREMENT,display_name TEXT NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL DEFAULT ''); INSERT OR IGNORE INTO announcements(id,body) VALUES(1,'');`);
const sessions=new Map(), attempts=new Map();
const html=(s)=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function send(res,status,body,type='application/json; charset=utf-8',extra={}){res.writeHead(status,{'Content-Type':type,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'strict-origin-when-cross-origin','Content-Security-Policy':"default-src 'self' https: data: 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",...extra});res.end(body)}
function json(res,status,obj){send(res,status,JSON.stringify(obj))}
function cookie(req){const m=(req.headers.cookie||'').match(/(?:^|;\s*)naama_session=([a-f0-9]{64})(?:;|$)/);return m?.[1]}
function auth(req){const t=cookie(req),s=t&&sessions.get(t);if(!s)return false;if(s.exp<Date.now()){sessions.delete(t);return false}return true}
function sameOrigin(req){const origin=req.headers.origin; if(!origin)return false;try{return new URL(origin).host===req.headers.host && new URL(origin).protocol===(COOKIE_SECURE?'https:':'http:')}catch{return false}}
function readBody(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(Buffer.byteLength(b)>12000){reject(new Error('too large'));req.destroy()}});req.on('end',()=>{try{resolve(JSON.parse(b))}catch{reject(new Error('bad json'))}});req.on('error',reject)})}
function rate(key,limit,period){let a=attempts.get(key);if(!a||a.until<Date.now())a={n:0,until:Date.now()+period};a.n++;attempts.set(key,a);return a.n<=limit}
function loginPage(){return `<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>دخول الموجه الصحي</title><style>body{font-family:Tahoma,Arial;background:linear-gradient(120deg,#e0f7fa,#fff0d9);display:grid;place-items:center;min-height:100vh;margin:0}.card{background:white;padding:35px;border-radius:24px;width:min(400px,85vw);box-shadow:0 15px 40px #1354}input,button{font:inherit;width:100%;padding:13px;margin-top:12px;box-sizing:border-box;border-radius:12px}input{border:1px solid #bbb}button{border:0;background:#087d86;color:white;cursor:pointer}a{color:#087d86}</style><div class="card"><h1>🔐 لوحة الموجّه الصحي</h1><p>مدرسة نعامة الابتدائية</p><form id="f"><input type="password" id="p" placeholder="كلمة المرور" autocomplete="current-password" required><button>دخول</button></form><p id="msg" role="alert"></p><a href="/">العودة للبوابة</a></div><script>document.getElementById('f').onsubmit=async e=>{e.preventDefault();let r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});if(r.ok)location.href='/admin';else document.getElementById('msg').textContent='تعذر الدخول، تحقق من كلمة المرور أو حاول لاحقًا'}</script></html>`}
const publicFile=fs.readFileSync(path.join(__dirname,'public','index.html'));
const adminFile=fs.readFileSync(path.join(__dirname,'private','admin.html'));
const server=http.createServer(async(req,res)=>{try{
const u=new URL(req.url,'http://localhost');const p=u.pathname,ip=req.socket.remoteAddress||'unknown';
if(req.method==='GET'&&p==='/')return send(res,200,publicFile,'text/html; charset=utf-8');
if(req.method==='GET'&&p==='/login')return send(res,200,loginPage(),'text/html; charset=utf-8');
if(req.method==='GET'&&p==='/admin'){if(!auth(req)){res.writeHead(303,{Location:'/login'});return res.end()}return send(res,200,adminFile,'text/html; charset=utf-8')}
if(req.method==='GET'&&p==='/api/works'){const rows=db.prepare("SELECT id,display_name,title,description,created_at FROM works WHERE status='approved' ORDER BY id DESC LIMIT 100").all();return json(res,200,{works:rows})}
if(req.method==='GET'&&p==='/api/announcement'){return json(res,200,{body:db.prepare('SELECT body FROM announcements WHERE id=1').get().body})}
if(req.method==='GET'&&p==='/api/admin/works'){if(!auth(req))return json(res,401,{error:'unauthorized'});return json(res,200,{works:db.prepare('SELECT * FROM works ORDER BY id DESC LIMIT 500').all()})}
if(req.method==='POST'&&p.startsWith('/api/')){
if(!sameOrigin(req))return json(res,403,{error:'origin rejected'});
if(p==='/api/login'){if(!rate('login:'+ip,8,15*60*1000))return json(res,429,{error:'try later'});const b=await readBody(req);const a=crypto.createHash('sha256').update(String(b.password||'')).digest(),c=crypto.createHash('sha256').update(PASS).digest();if(!crypto.timingSafeEqual(a,c))return json(res,401,{error:'invalid'});const token=crypto.randomBytes(32).toString('hex');sessions.set(token,{exp:Date.now()+2*60*60*1000});return send(res,200,JSON.stringify({ok:true}),'application/json; charset=utf-8',{'Set-Cookie':`naama_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=7200${COOKIE_SECURE?'; Secure':''}`})}
if(p==='/api/works'){if(!rate('work:'+ip,5,60*60*1000))return json(res,429,{error:'too many submissions'});const b=await readBody(req),name=String(b.display_name||'').trim(),title=String(b.title||'').trim(),desc=String(b.description||'').trim();if(!name||!title||!desc||name.length>40||title.length>100||desc.length>1000)return json(res,400,{error:'invalid fields'});db.prepare('INSERT INTO works(display_name,title,description) VALUES(?,?,?)').run(name,title,desc);return json(res,201,{ok:true,message:'تم إرسال العمل للمراجعة قبل النشر'})}
if(!auth(req))return json(res,401,{error:'unauthorized'});
if(p==='/api/logout'){sessions.delete(cookie(req));return send(res,200,JSON.stringify({ok:true}),'application/json; charset=utf-8',{'Set-Cookie':`naama_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${COOKIE_SECURE?'; Secure':''}`})}
if(p==='/api/admin/moderate'){const b=await readBody(req);if(!Number.isSafeInteger(b.id)||!['approved','rejected','pending'].includes(b.status))return json(res,400,{error:'invalid'});db.prepare('UPDATE works SET status=? WHERE id=?').run(b.status,b.id);return json(res,200,{ok:true})}
if(p==='/api/admin/announcement'){const b=await readBody(req),body=String(b.body||'');if(body.length>1000)return json(res,400,{error:'too long'});db.prepare('UPDATE announcements SET body=? WHERE id=1').run(body);return json(res,200,{ok:true})}
}
return json(res,404,{error:'not found'});
}catch(e){console.error(e);if(!res.headersSent)json(res,400,{error:'invalid request'})}});
server.listen(PORT,'0.0.0.0',()=>console.log(`Naama health portal on port ${PORT}`));
