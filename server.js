const express=require('express'),Database=require('better-sqlite3'),crypto=require('crypto'),path=require('path');
const PORT=process.env.PORT||3000,ADMIN_PASSWORD=process.env.ADMIN_PASSWORD;
const SECRET=process.env.SECRET||crypto.randomBytes(32).toString('hex');
if(!ADMIN_PASSWORD){console.error('ضع ADMIN_PASSWORD في متغيرات البيئة');process.exit(1)}
const db=new Database(process.env.DB_PATH||path.join(__dirname,'data.db'));
db.exec(`create table if not exists kv(k text primary key,v text);
create table if not exists employees(id integer primary key autoincrement,name text,branch text,salt text,hash text);
create table if not exists results(id integer primary key autoincrement,emp_id integer,name text,branch text,score integer,ok integer,ts integer);`);
const DEF={branches:['الفرع الرئيسي','الفرع الثاني'],
slides:Array.from({length:5},(_,i)=>({t:'الشريحة '+(i+1),b:'اكتب هنا شرح المنهاج من لوحة التحكم.'})),
qs:Array.from({length:10},(_,i)=>({q:'سؤال تجريبي رقم '+(i+1),o:['الخيار الأول','الخيار الثاني','الخيار الثالث','الخيار الرابع'],a:0}))};
const getCfg=()=>{const r=db.prepare('select v from kv where k=?').get('cfg');return r?JSON.parse(r.v):DEF};
const setCfg=c=>db.prepare('insert or replace into kv values(?,?)').run('cfg',JSON.stringify(c));
const hmac=s=>crypto.createHmac('sha256',SECRET).update(s).digest('base64url');
const sign=p=>{const b=Buffer.from(JSON.stringify({...p,exp:Date.now()+8*3600e3})).toString('base64url');return b+'.'+hmac(b)};
const safeEq=(a,b)=>{a=Buffer.from(String(a));b=Buffer.from(String(b));return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const verify=t=>{try{const[b,s]=String(t).split('.');if(!safeEq(s,hmac(b)))return null;const p=JSON.parse(Buffer.from(b,'base64url'));return p.exp>Date.now()?p:null}catch{return null}};
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,32).toString('hex');
const auth=role=>(req,res,next)=>{const p=verify((req.headers.authorization||'').slice(7));if(!p||p.role!==role)return res.status(401).json({error:'انتهت الجلسة، سجّل الدخول مجدداً'});req.u=p;next()};
const tries=new Map();
const limit=(req,res,next)=>{const k=req.ip,n=(tries.get(k)||[]).filter(t=>Date.now()-t<6e5);if(n.length>=10)return res.status(429).json({error:'محاولات كثيرة، انتظر عشر دقائق'});n.push(Date.now());tries.set(k,n);next()};
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'1mb'}));app.use(express.static(path.join(__dirname,'public')));
const bad=(res,m)=>res.status(400).json({error:m});

app.get('/api/branches',(q,r)=>r.json(getCfg().branches));
app.post('/api/login',limit,(req,res)=>{const{name,branch,password}=req.body||{};
 const rows=db.prepare('select * from employees where name=? and branch=?').all(String(name||'').trim(),String(branch||''));
 const e=rows.find(x=>safeEq(x.hash,hashPw(String(password||''),x.salt)));
 if(!e)return res.status(401).json({error:'الاسم أو الفرع أو كلمة المرور غير صحيحة'});
 res.json({token:sign({role:'emp',id:e.id}),name:e.name})});
app.get('/api/course',auth('emp'),(q,res)=>{const c=getCfg();res.json({slides:c.slides,qs:c.qs.map(({q,o})=>({q,o}))})});
app.post('/api/submit',auth('emp'),(req,res)=>{const c=getCfg(),a=req.body.answers;
 if(!Array.isArray(a)||a.length!==c.qs.length)return bad(res,'إجابات غير مكتملة');
 const e=db.prepare('select * from employees where id=?').get(req.u.id);if(!e)return res.status(401).json({error:'الحساب غير موجود'});
 const right=c.qs.filter((x,i)=>a[i]===x.a).length,score=Math.round(right/c.qs.length*100),ok=score>=60?1:0;
 db.prepare('insert into results(emp_id,name,branch,score,ok,ts) values(?,?,?,?,?,?)').run(e.id,e.name,e.branch,score,ok,Date.now());
 res.json({score,ok:!!ok,right,total:c.qs.length})});
app.get('/api/my-results',auth('emp'),(req,res)=>res.json(db.prepare('select score,ok,ts from results where emp_id=? order by ts desc').all(req.u.id)));

app.post('/api/admin/login',limit,(req,res)=>{if(!safeEq(req.body?.password||'',ADMIN_PASSWORD))return res.status(401).json({error:'كلمة مرور المسؤول غير صحيحة'});res.json({token:sign({role:'admin'})})});
const A=auth('admin');
app.get('/api/admin/data',A,(q,res)=>res.json({cfg:getCfg(),employees:db.prepare('select id,name,branch from employees order by id desc').all(),results:db.prepare('select * from results order by ts desc').all()}));
app.put('/api/admin/config',A,(req,res)=>{const{branches,slides,qs}=req.body||{};
 if(!Array.isArray(branches)||!Array.isArray(slides)||!Array.isArray(qs))return bad(res,'بيانات غير صالحة');setCfg({branches,slides,qs});res.json({ok:true})});
app.post('/api/admin/employees',A,(req,res)=>{const{name,branch,password}=req.body||{};if(!name?.trim()||!branch||!password)return bad(res,'أكمل كل الحقول');
 const salt=crypto.randomBytes(16).toString('hex');db.prepare('insert into employees(name,branch,salt,hash) values(?,?,?,?)').run(name.trim(),branch,salt,hashPw(password,salt));res.json({ok:true})});
app.put('/api/admin/employees/:id/password',A,(req,res)=>{if(!req.body?.password)return bad(res,'أدخل كلمة المرور');
 const salt=crypto.randomBytes(16).toString('hex');db.prepare('update employees set salt=?,hash=? where id=?').run(salt,hashPw(req.body.password,salt),req.params.id);res.json({ok:true})});
app.delete('/api/admin/employees/:id',A,(req,res)=>{db.prepare('delete from results where emp_id=?').run(req.params.id);db.prepare('delete from employees where id=?').run(req.params.id);res.json({ok:true})});
app.delete('/api/admin/results/:id',A,(req,res)=>{db.prepare('delete from results where id=?').run(req.params.id);res.json({ok:true})});
app.listen(PORT,()=>console.log('يعمل على المنفذ '+PORT));
