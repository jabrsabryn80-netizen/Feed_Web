require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const QRCode = require("qrcode");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set a random JWT_SECRET of at least 32 characters.");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("Set DATABASE_URL to your hosted PostgreSQL connection string.");
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','teacher','student')),
      course TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY, teacher_id BIGINT NOT NULL REFERENCES users(id),
      course TEXT NOT NULL, group_name TEXT NOT NULL, token_hash TEXT NOT NULL,
      expires_at BIGINT NOT NULL, is_open BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS attendance (
      id BIGSERIAL PRIMARY KEY, session_id TEXT NOT NULL REFERENCES sessions(id),
      student_id BIGINT NOT NULL REFERENCES users(id), checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(session_id, student_id)
    );
    CREATE INDEX IF NOT EXISTS attendance_student_idx ON attendance(student_id);
    CREATE INDEX IF NOT EXISTS sessions_teacher_idx ON sessions(teacher_id);
  `);
}
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 12, standardHeaders: true, legacyHeaders: false });
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

function normalizePhone(v) { return String(v || "").replace(/[^\d+]/g, "").trim(); }
function safeUser(u) { return { id: Number(u.id), name: u.name, phone: u.phone, role: u.role, course: u.course || null }; }
function hashToken(t) { return crypto.createHash("sha256").update(t).digest("hex"); }
function issueCookie(res, user) {
  const token = jwt.sign({ sub: String(user.id), role: user.role }, JWT_SECRET, { expiresIn: "8h" });
  res.cookie("attendance_token", token, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8*60*60*1000 });
}
async function auth(req, res, next) {
  try {
    const token = req.cookies.attendance_token;
    if (!token) return res.status(401).json({ error: "سجّل الدخول أولاً." });
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query("SELECT id,name,phone,role,course FROM users WHERE id=$1", [payload.sub]);
    if (!result.rowCount) return res.status(401).json({ error: "الحساب غير موجود." });
    req.user = result.rows[0]; next();
  } catch { return res.status(401).json({ error: "انتهت الجلسة. سجّل الدخول مرة أخرى." }); }
}
function allow(...roles) { return (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:"ليس لديك صلاحية لتنفيذ هذا الإجراء."}); }

app.get("/api/status", async (req,res) => {
  try { const r=await pool.query("SELECT COUNT(*)::int n FROM users WHERE role='admin'"); res.json({setupRequired:r.rows[0].n===0}); }
  catch(e) { console.error(e); res.status(500).json({error:"تعذر الاتصال بقاعدة البيانات."}); }
});
app.post("/api/setup", authLimiter, async (req,res) => {
  try {
    const exists=await pool.query("SELECT COUNT(*)::int n FROM users WHERE role='admin'");
    if(exists.rows[0].n) return res.status(409).json({error:"تم إعداد المدير الرئيسي بالفعل."});
    const {name,phone,password}=req.body||{}, p=normalizePhone(phone);
    if(!name?.trim() || p.length<8 || !password || password.length<10) return res.status(400).json({error:"أدخل الاسم ورقم موبايل صحيح وكلمة مرور لا تقل عن 10 أحرف."});
    const r=await pool.query("INSERT INTO users(name,phone,password_hash,role) VALUES($1,$2,$3,'admin') RETURNING id,name,phone,role,course",[name.trim(),p,await bcrypt.hash(password,12)]);
    issueCookie(res,r.rows[0]); res.status(201).json({user:safeUser(r.rows[0])});
  } catch(e) { console.error(e); res.status(500).json({error:"تعذر إنشاء حساب المدير."}); }
});
app.post("/api/auth/login",authLimiter,async(req,res)=>{
  try {
    const {phone,password}=req.body||{};
    const r=await pool.query("SELECT * FROM users WHERE phone=$1",[normalizePhone(phone)]);
    const user=r.rows[0];
    if(!user || !await bcrypt.compare(String(password||""),user.password_hash)) return res.status(401).json({error:"رقم الموبايل أو كلمة المرور غير صحيحة."});
    issueCookie(res,user); res.json({user:safeUser(user)});
  } catch(e) { console.error(e); res.status(500).json({error:"حدث خطأ أثناء تسجيل الدخول."}); }
});
app.post("/api/auth/logout",(req,res)=>{res.clearCookie("attendance_token");res.json({ok:true});});
app.get("/api/me",auth,(req,res)=>res.json({user:safeUser(req.user)}));

app.post("/api/students/register",authLimiter,async(req,res)=>{
  try {
    const {name,phone,password}=req.body||{},p=normalizePhone(phone);
    if(!name?.trim() || p.length<8 || !password || password.length<10) return res.status(400).json({error:"أدخل الاسم ورقم موبايل صحيح وكلمة مرور لا تقل عن 10 أحرف."});
    const r=await pool.query("INSERT INTO users(name,phone,password_hash,role) VALUES($1,$2,$3,'student') RETURNING id,name,phone,role,course",[name.trim(),p,await bcrypt.hash(password,12)]);
    res.status(201).json({user:safeUser(r.rows[0])});
  } catch(e) { if(e.code==="23505") return res.status(409).json({error:"رقم الموبايل مسجل بالفعل."}); console.error(e); res.status(500).json({error:"تعذر إنشاء الحساب."}); }
});
app.post("/api/admin/teachers",auth,allow("admin"),async(req,res)=>{
  try {
    const {name,phone,password,course}=req.body||{},p=normalizePhone(phone);
    if(!name?.trim() || p.length<8 || !password || password.length<10 || !course?.trim()) return res.status(400).json({error:"أكمل الاسم ورقم الموبايل والمقرر، واجعل كلمة المرور 10 أحرف على الأقل."});
    const r=await pool.query("INSERT INTO users(name,phone,password_hash,role,course) VALUES($1,$2,$3,'teacher',$4) RETURNING id,name,phone,role,course",[name.trim(),p,await bcrypt.hash(password,12),course.trim()]);
    res.status(201).json({teacher:safeUser(r.rows[0])});
  } catch(e) { if(e.code==="23505") return res.status(409).json({error:"رقم الموبايل مستخدم بالفعل."}); console.error(e); res.status(500).json({error:"تعذر إضافة المدرس."}); }
});
app.get("/api/admin/teachers",auth,allow("admin"),async(req,res)=>{
  const r=await pool.query("SELECT id,name,phone,course,created_at FROM users WHERE role='teacher' ORDER BY name"); res.json({teachers:r.rows});
});
app.delete("/api/admin/teachers/:id",auth,allow("admin"),async(req,res)=>{
  const id=Number(req.params.id);
  const used=await pool.query("SELECT COUNT(*)::int n FROM sessions WHERE teacher_id=$1",[id]);
  if(used.rows[0].n) return res.status(409).json({error:"للمدرس جلسات محفوظة؛ لا يمكن حذفه حتى لا تضيع سجلات الحضور."});
  const r=await pool.query("DELETE FROM users WHERE id=$1 AND role='teacher'",[id]);
  if(!r.rowCount) return res.status(404).json({error:"المدرس غير موجود."});
  res.json({ok:true});
});
app.get("/api/dashboard",auth,async(req,res)=>{
  const u=req.user;
  if(u.role==="student"){
    const r=await pool.query("SELECT a.id,s.course,s.group_name,a.checked_at,s.created_at session_created FROM attendance a JOIN sessions s ON s.id=a.session_id WHERE a.student_id=$1 ORDER BY a.id DESC",[u.id]);
    return res.json({stats:{myAttendance:r.rowCount},attendance:r.rows});
  }
  const where=u.role==="teacher"?"WHERE s.teacher_id=$1":"";
  const params=u.role==="teacher"?[u.id]:[];
  const sessions=await pool.query(`SELECT s.id,s.course,s.group_name,s.created_at,s.expires_at,s.is_open,u.name teacher_name,(SELECT COUNT(*)::int FROM attendance a WHERE a.session_id=s.id) attendance_count FROM sessions s JOIN users u ON u.id=s.teacher_id ${where} ORDER BY s.created_at DESC LIMIT 100`,params);
  const attendance=await pool.query(`SELECT a.id,u.name student_name,u.phone,s.course,s.group_name,s.created_at session_created,a.checked_at FROM attendance a JOIN users u ON u.id=a.student_id JOIN sessions s ON s.id=a.session_id ${u.role==="teacher"?"WHERE s.teacher_id=$1":""} ORDER BY a.id DESC LIMIT 300`,params);
  const counts=await pool.query("SELECT COUNT(*) FILTER(WHERE role='student')::int students,COUNT(*) FILTER(WHERE role='teacher')::int teachers FROM users");
  res.json({stats:{students:counts.rows[0].students,teachers:counts.rows[0].teachers,attendance:attendance.rowCount},sessions:sessions.rows,attendance:attendance.rows});
});
app.post("/api/sessions",auth,allow("admin","teacher"),async(req,res)=>{
  try {
    const {course,groupName}=req.body||{};
    if(!course?.trim() || !groupName?.trim()) return res.status(400).json({error:"أدخل اسم المقرر والمجموعة."});
    const id=crypto.randomUUID(),raw=crypto.randomBytes(24).toString("base64url"),expires=Date.now()+5*60*1000;
    await pool.query("INSERT INTO sessions(id,teacher_id,course,group_name,token_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6)",[id,uId(req.user.id),course.trim(),groupName.trim(),hashToken(raw),expires]);
    const qrDataUrl=await QRCode.toDataURL(JSON.stringify({sessionId:id,token:raw}),{errorCorrectionLevel:"M",margin:2,width:280});
    res.status(201).json({session:{id,course:course.trim(),groupName:groupName.trim(),expiresAt:expires,qrDataUrl,teacher:req.user.name}});
  } catch(e) { console.error(e); res.status(500).json({error:"تعذر فتح جلسة الحضور."}); }
});
function uId(id){return Number(id);}
app.post("/api/sessions/:id/close",auth,allow("admin","teacher"),async(req,res)=>{
  const r=await pool.query("SELECT * FROM sessions WHERE id=$1",[req.params.id]),s=r.rows[0];
  if(!s) return res.status(404).json({error:"الجلسة غير موجودة."});
  if(req.user.role!=="admin" && Number(s.teacher_id)!==Number(req.user.id)) return res.status(403).json({error:"هذه الجلسة ليست تابعة لحسابك."});
  await pool.query("UPDATE sessions SET is_open=FALSE WHERE id=$1",[s.id]); res.json({ok:true});
});
app.post("/api/attendance/scan",auth,allow("student"),async(req,res)=>{
  const {sessionId,token}=req.body||{};
  const r=await pool.query("SELECT * FROM sessions WHERE id=$1",[String(sessionId||"")]),s=r.rows[0];
  if(!s || !s.is_open || Number(s.expires_at)<Date.now() || hashToken(String(token||""))!==s.token_hash) return res.status(400).json({error:"رمز QR غير صالح أو انتهت صلاحيته."});
  try { await pool.query("INSERT INTO attendance(session_id,student_id) VALUES($1,$2)",[s.id,req.user.id]); }
  catch(e) { if(e.code==="23505") return res.status(409).json({error:"تم تسجيل حضورك في هذه المحاضرة بالفعل."}); console.error(e); return res.status(500).json({error:"تعذر تسجيل الحضور."}); }
  res.status(201).json({ok:true,message:"تم تسجيل حضورك بنجاح."});
});
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
initDb().then(()=>app.listen(PORT,()=>console.log(`Attendance app listening on ${PORT}`))).catch(e=>{console.error("Database initialization failed:",e);process.exit(1);});
