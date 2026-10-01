
const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const OWNER_USER_ID = "e013f1a6-7c8a-4536-8530-5ed1c5746810";
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, "data.json");
const UPLOADS = path.join(ROOT, "uploads");
fs.mkdirSync(UPLOADS, { recursive: true });
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({users:[],posts:[],messages:[],reports:[]}, null, 2));

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use("/uploads", express.static(UPLOADS));
app.use(express.static(path.join(ROOT,"public")));

const upload = multer({
  dest: UPLOADS,
  limits:{fileSize:2*1024*1024},
  fileFilter:(req,file,cb)=>{
    const ok=/^image\/(png|jpeg|webp|gif)$/.test(file.mimetype);
    cb(ok?null:new Error("Можно загружать только изображения"),ok);
  }
});

function readData(){
  try{
    const d=JSON.parse(fs.readFileSync(DATA_FILE,"utf8"));
    d.users ||= []; d.posts ||= []; d.messages ||= []; d.reports ||= [];
    return d;
  }catch{return {users:[],posts:[],messages:[],reports:[]}}
}
function writeData(d){fs.writeFileSync(DATA_FILE,JSON.stringify(d,null,2),"utf8")}
function id(){return crypto.randomUUID()}
function token(){return crypto.randomBytes(32).toString("hex")}
function cleanText(s,max=500){return String(s||"").trim().replace(/\s+/g," ").slice(0,max)}
function safeText(s){return !/(https?:\/\/|www\.|t\.me\/|wa\.me\/|instagram\.com|vk\.com|discord\.gg|@\w{3,})/i.test(String(s||""))}
function findUser(d,userId){return d.users.find(u=>u.id===userId)}
function publicUser(u){return {id:u.id,name:u.name,avatar:u.avatar||null,role:u.role||"Ученик",createdAt:u.createdAt}}
function validPassword(p){return typeof p === "string" && p.length >= 6 && p.length <= 200}
async function hashPassword(p){return bcrypt.hash(p,12)}
async function checkPassword(p,h){return !!h && bcrypt.compare(p,h)}
function auth(req,res,next){
  const t=req.headers.authorization?.replace(/^Bearer\s+/i,"");
  const u=t && readData().users.find(x=>x.sessionToken===t);
  if(!u)return res.status(401).json({error:"Требуется вход в аккаунт"});
  req.user=u; next();
}
function owner(req,res,next){
  if(!req.user || req.user.id !== OWNER_USER_ID){
    return res.status(403).json({error:"Только владелец сайта может менять роли"});
  }
  next();
}
function moderator(req,res,next){
  if(!["Модератор","Администратор"].includes(req.user.role))return res.status(403).json({error:"Нет доступа к модерации"});
  next();
}

app.get("/api/state",(req,res)=>{
  const d=readData();
  res.json({
    users:d.users.map(publicUser),
    posts:d.posts.slice(-100).reverse(),
    messages:d.messages.slice(-300)
  });
});

app.post("/api/register",upload.single("avatar"),async (req,res)=>{
  const d=readData(), name=cleanText(req.body.name,30), password=String(req.body.password||"");
  if(name.length<2)return res.status(400).json({error:"Имя должно быть не короче 2 символов"});
  if(!safeText(name))return res.status(400).json({error:"Недопустимое имя"});
  if(!validPassword(password))return res.status(400).json({error:"Пароль должен быть от 6 до 200 символов"});
  if(d.users.some(u=>u.name.toLowerCase()===name.toLowerCase()))return res.status(400).json({error:"Такое имя уже занято"});
  const u={id:id(),name,role:"Ученик",passwordHash:await hashPassword(password),sessionToken:token(),avatar:req.file?`/uploads/${req.file.filename}`:null,createdAt:new Date().toISOString()};
  d.users.push(u);writeData(d);
  res.json({user:publicUser(u),token:u.sessionToken});
});

app.post("/api/login",async (req,res)=>{
  const d=readData(), name=cleanText(req.body.name,30), password=String(req.body.password||"");
  const u=d.users.find(x=>x.name.toLowerCase()===name.toLowerCase());
  if(!u)return res.status(401).json({error:"Неверное имя или пароль"});
  if(!u.passwordHash)return res.status(409).json({error:"Для этого старого аккаунта ещё не установлен пароль. Войдите в старую сессию и установите пароль в профиле."});
  if(!(await checkPassword(password,u.passwordHash)))return res.status(401).json({error:"Неверное имя или пароль"});
  u.sessionToken=token();
  writeData(d);
  res.json({user:publicUser(u),token:u.sessionToken});
});

app.get("/api/me",auth,(req,res)=>res.json({user:publicUser(req.user),needsPassword:!req.user.passwordHash}));

app.post("/api/me/password",auth,async (req,res)=>{
  const d=readData(), u=findUser(d,req.user.id);
  const current=String(req.body.currentPassword||""), next=String(req.body.newPassword||"");
  if(!validPassword(next))return res.status(400).json({error:"Новый пароль должен быть от 6 до 200 символов"});
  if(u.passwordHash && !(await checkPassword(current,u.passwordHash)))return res.status(401).json({error:"Текущий пароль указан неверно"});
  u.passwordHash=await hashPassword(next);
  u.sessionToken=token();
  writeData(d);
  res.json({user:publicUser(u),token:u.sessionToken});
});

app.put("/api/me",auth,upload.single("avatar"),(req,res)=>{
  const d=readData(), u=findUser(d,req.user.id), name=cleanText(req.body.name,30);
  if(name.length<2)return res.status(400).json({error:"Имя должно быть не короче 2 символов"});
  if(d.users.some(x=>x.id!==u.id&&x.name.toLowerCase()===name.toLowerCase()))return res.status(409).json({error:"Такое имя уже занято"});
  u.name=name;
  if(req.file)u.avatar=`/uploads/${req.file.filename}`;
  writeData(d);res.json({user:publicUser(u)});
});

app.post("/api/posts",auth,(req,res)=>{
  const d=readData(), text=cleanText(req.body.text,700);
  if(!text)return res.status(400).json({error:"Напиши сообщение"});
  if(!safeText(text))return res.status(400).json({error:"Ссылки и контакты здесь запрещены"});
  const recipient=cleanText(req.body.recipient,40)||"Всем";
  const visibility=req.body.visibility==="profile"?"profile":"anonymous";
  const post={id:id(),userId:req.user.id,author:visibility==="profile"?publicUser(req.user):{name:"Аноним",avatar:null,role:""},visibility,recipient,category:cleanText(req.body.category,20)||"Другое",text,likes:0,reports:0,hidden:false,createdAt:new Date().toISOString()};
  d.posts.push(post);writeData(d);res.json({post});
});

app.post("/api/chat",auth,(req,res)=>{
  const d=readData(), text=cleanText(req.body.text,500);
  if(!text)return res.status(400).json({error:"Напиши сообщение"});
  if(!safeText(text))return res.status(400).json({error:"Ссылки и контакты здесь запрещены"});
  const visibility=req.body.visibility==="profile"?"profile":"anonymous";
  const msg={id:id(),userId:req.user.id,author:visibility==="profile"?publicUser(req.user):{name:"Аноним",avatar:null,role:""},visibility,text,reports:0,hidden:false,createdAt:new Date().toISOString()};
  d.messages.push(msg);writeData(d);res.json({message:msg});
});

app.post("/api/report",auth,(req,res)=>{
  const d=readData(), kind=req.body.kind==="chat"?"chat":"post";
  const list=kind==="chat"?d.messages:d.posts, item=list.find(x=>x.id===req.body.id);
  if(!item)return res.status(404).json({error:"Сообщение не найдено"});
  item.reports=(item.reports||0)+1;
  d.reports.push({id:id(),kind,targetId:item.id,reason:cleanText(req.body.reason,300),reporterId:req.user.id,createdAt:new Date().toISOString(),status:"open"});
  if(item.reports>=3)item.hidden=true;
  writeData(d);res.json({ok:true});
});

app.post("/api/like",auth,(req,res)=>{
  const d=readData(), post=d.posts.find(x=>x.id===req.body.id);
  if(!post)return res.status(404).json({error:"Пост не найден"});
  post.likes=(post.likes||0)+1;writeData(d);res.json({likes:post.likes});
});

app.get("/api/mod/reports",auth,moderator,(req,res)=>{
  const d=readData();
  const reports=d.reports.filter(r=>r.status==="open").map(r=>({
    ...r,
    target:(r.kind==="chat"?d.messages:d.posts).find(x=>x.id===r.targetId)||null
  }));
  res.json({reports});
});

app.post("/api/mod/hide",auth,moderator,(req,res)=>{
  const d=readData(), list=req.body.kind==="chat"?d.messages:d.posts, item=list.find(x=>x.id===req.body.id);
  if(!item)return res.status(404).json({error:"Сообщение не найдено"});
  item.hidden=true;
  d.reports.filter(r=>r.targetId===item.id).forEach(r=>r.status="resolved");
  writeData(d);res.json({ok:true});
});

app.post("/api/mod/restore",auth,moderator,(req,res)=>{
  const d=readData(), list=req.body.kind==="chat"?d.messages:d.posts, item=list.find(x=>x.id===req.body.id);
  if(!item)return res.status(404).json({error:"Сообщение не найдено"});
  item.hidden=false;
  d.reports.filter(r=>r.targetId===item.id).forEach(r=>r.status="resolved");
  writeData(d);res.json({ok:true});
});

// Только владелец может назначать роли. Роль из запроса никогда не принимается при регистрации.
app.get("/api/admin/users",auth,owner,(req,res)=>{
  const d=readData();res.json(d.users.map(publicUser));
});
app.post("/api/admin/users/:id/role",auth,owner,(req,res)=>{
  const d=readData(), u=findUser(d,req.params.id), role=req.body.role;
  if(!u)return res.status(404).json({error:"Пользователь не найден"});
  if(!["Ученик","Старшеклассник","Модератор","Администратор"].includes(role))return res.status(400).json({error:"Недопустимая роль"});
  u.role=role;writeData(d);res.json({user:publicUser(u)});
});

app.get("/api/admin/reports",auth,owner,(req,res)=>{
  const d=readData();res.json({reports:d.reports,users:d.users.map(publicUser)});
});

app.listen(PORT,"0.0.0.0",()=>console.log(`School92 Sakura v5 running on http://localhost:${PORT}`));
