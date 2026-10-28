import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import cron from 'node-cron';
import nodemailer from 'nodemailer';
import ical from 'ical-generator';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { User, StudentData } from './models.js';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('SESSION_SECRET must be set to a random value of at least 32 characters.'); process.exit(1);
}
app.disable('x-powered-by');
app.set('trust proxy', isProd ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(session({
  name: 'slm.sid', secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: 'sessions', ttl: 60 * 60 * 24 * 7 }),
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false }));
app.use('/api', (req, res, next) => {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    const allowed = process.env.APP_ORIGIN;
    if (origin && allowed && origin !== allowed) return res.status(403).json({ error: 'Origin not allowed.' });
  }
  next();
});
app.use(passport.initialize());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase();
        const googleId = profile.id;
        const emailVerified = profile._json?.email_verified === true;

        if (!email || !emailVerified) {
          return done(null, false);
        }

        let user = await User.findOne({ googleId });

        if (!user) {
          const existingUser = await User.findOne({ email });

          // Do not automatically link an existing account.
          if (existingUser) {
            return done(null, false);
          }

          user = await User.create({
            googleId,
            name: profile.displayName || email.split('@')[0],
            email,
            photo: profile.photos?.[0]?.value || ''
          });

          await StudentData.create({
            userId: user._id,
            ...defaultData()
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

const safeUser = user => ({ id: String(user._id), name: user.name, email: user.email, college: user.college, course: user.course, department: user.department, year: user.year, photo: user.photo || '' });
const defaultData = () => ({ theme: 'light', tasks: [], assignments: [], exams: [], timetable: [], attendance: [], expenses: [], goals: [], notes: [], settings: { emailReminders: false, reminderWindow: '1' } });
function requireAuth(req, res, next) { if (!req.session.userId) return res.status(401).json({ error: 'Please log in.' }); next(); }
function validateEmail(email) { return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254; }
function cleanData(input) {
  const allowedArrays = ['tasks','assignments','exams','timetable','attendance','expenses','goals','notes'];
  const output = defaultData();
  output.theme = input?.theme === 'dark' ? 'dark' : 'light';
  for (const key of allowedArrays) {
    if (input?.[key] !== undefined && !Array.isArray(input[key])) throw new Error(`${key} must be an array.`);
    output[key] = (input?.[key] || []).slice(0, 5000);
  }
  if (input?.settings && typeof input.settings === 'object') {
    output.settings.emailReminders = Boolean(input.settings.emailReminders);
    output.settings.reminderWindow = ['1','2','3','7'].includes(String(input.settings.reminderWindow)) ? String(input.settings.reminderWindow) : '1';
  }
  return output;
}
// Start Google Login
app.get('/auth/google', (req, res, next) => {
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    prompt: 'select_account'
  })(req, res, next);
});

// Google OAuth callback
app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    session: false,
    failureRedirect: '/index.html?error=google_login_failed'
  }),
  (req, res, next) => {
    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.userId = String(req.user._id);

      req.session.save(err2 => {
        if (err2) return next(err2);
        res.redirect('/index.html');
      });
    });
  }
);

app.post('/api/auth/register', async (req, res, next) => {
  try {
    const { name, email, password, college = '', course = '', department = '', year = '' } = req.body || {};
    if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 100) return res.status(400).json({ error: 'Enter a name between 2 and 100 characters.' });
    if (!validateEmail(String(email || '').toLowerCase())) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (typeof password !== 'string' || password.length < 10 || password.length > 128 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password)) return res.status(400).json({ error: 'Use 10+ characters with uppercase, lowercase, a number and a symbol.' });
    if (await User.exists({ email: String(email).toLowerCase().trim() })) return res.status(409).json({ error: 'An account with this email already exists.' });
    const user = await User.create({ name: name.trim(), email: String(email).toLowerCase().trim(), passwordHash: await bcrypt.hash(password, 12), college: String(college).slice(0,180), course: String(course).slice(0,100), department: String(department).slice(0,120), year: String(year).slice(0,40) });
    await StudentData.create({ userId: user._id, ...defaultData() });
    req.session.userId = String(user._id);
    req.session.save(err => err ? next(err) : res.status(201).json({ user: safeUser(user) }));
  } catch (e) { if (e?.code === 11000) return res.status(409).json({ error: 'An account with this email already exists.' }); next(e); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase(); const password = req.body?.password;
    if (!validateEmail(email) || typeof password !== 'string') return res.status(400).json({ error: 'Enter your email and password.' });
    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Incorrect email or password.' });
    req.session.regenerate(err => { if (err) return next(err); req.session.userId = String(user._id); req.session.save(err2 => err2 ? next(err2) : res.json({ user: safeUser(user) })); });
  } catch (e) { next(e); }
});
app.post('/api/auth/logout', (req, res, next) => req.session.destroy(err => { if (err) return next(err); res.clearCookie('slm.sid', { httpOnly: true, secure: isProd, sameSite: 'lax' }); res.status(204).end(); }));
app.get('/api/auth/me', requireAuth, async (req, res, next) => { try { const user = await User.findById(req.session.userId); if (!user) { req.session.destroy(()=>{}); return res.status(401).json({ error: 'Session expired.' }); } res.json({ user: safeUser(user) }); } catch(e) { next(e); } });

app.put('/api/profile', requireAuth, async (req, res, next) => { try {
  const fields = {}; for (const key of ['name','college','course','department','year','photo']) if (req.body?.[key] !== undefined) fields[key] = String(req.body[key]).trim().slice(0, key === 'name' ? 100 : key === 'photo' ? 250000 : 180);
  if (fields.name !== undefined && fields.name.length < 2) return res.status(400).json({ error: 'Name must contain at least 2 characters.' });
  const user = await User.findByIdAndUpdate(req.session.userId, { $set: fields }, { new: true, runValidators: true });
  if (!user) return res.status(401).json({ error: 'Please log in.' }); res.json({ user: safeUser(user) });
} catch(e) { next(e); } });

app.get('/api/data', requireAuth, async (req, res, next) => { try { const data = await StudentData.findOne({ userId: req.session.userId }).lean(); res.json({ data: data ? cleanData(data) : defaultData() }); } catch(e) { next(e); } });
app.put('/api/data', requireAuth, async (req, res, next) => { try { const data = cleanData(req.body || {}); await StudentData.findOneAndUpdate({ userId: req.session.userId }, { $set: { ...data, updatedAt: new Date() }, $setOnInsert: { userId: req.session.userId } }, { upsert: true, new: true, runValidators: true }); res.json({ ok: true, updatedAt: new Date().toISOString() }); } catch(e) { if (e.message?.includes('must be an array')) return res.status(400).json({ error: e.message }); next(e); } });
app.get('/api/analytics', requireAuth, async (req, res, next) => { try {
  const d = await StudentData.findOne({ userId: req.session.userId }).lean() || defaultData();
  const tasks = d.tasks || [], assignments = d.assignments || [], expenses = d.expenses || [], attendance = d.attendance || [];
  const month = new Date().toISOString().slice(0,7); const monthlyExpenses = expenses.filter(x => String(x.date || '').slice(0,7) === month).reduce((s,x)=>s+Math.max(0,Number(x.amount)||0),0);
  const totalClasses = attendance.reduce((s,x)=>s+Math.max(0,Number(x.total)||0),0), attended = attendance.reduce((s,x)=>s+Math.max(0,Number(x.attended)||0),0);
  res.json({ tasks: tasks.length, completedTasks: tasks.filter(x=>x.completed || x.done).length, pendingAssignments: assignments.filter(x=>!x.completed).length, monthlyExpenses, attendancePercent: totalClasses ? Math.round(attended/totalClasses*100) : 0, upcomingExams: (d.exams||[]).filter(x=>x.date && x.date >= new Date().toISOString().slice(0,10)).length });
 } catch(e) { next(e); } });
app.get('/api/calendar.ics', requireAuth, async (req, res, next) => { try {
  const d = await StudentData.findOne({ userId: req.session.userId }).lean() || defaultData(); const cal = ical({ name: 'Student Life Manager' });
  for (const t of [...(d.tasks||[]).map(x=>({...x,_kind:'Task',_title:x.name||x.title,_date:x.dueDate})), ...(d.assignments||[]).map(x=>({...x,_kind:'Assignment',_title:x.title||x.name,_date:x.dueDate})), ...(d.exams||[]).map(x=>({...x,_kind:'Exam',_title:x.subject||x.title,_date:x.date}))]) {
    if (!t._date || !t._title || t.completed) continue; const date = new Date(`${t._date}T09:00:00`); if (Number.isNaN(date.getTime())) continue;
    cal.createEvent({ start: date, end: new Date(date.getTime()+30*60000), summary: `${t._kind}: ${String(t._title).slice(0,180)}`, description: `Imported from Student Life Manager` });
  }
  res.setHeader('Content-Type','text/calendar; charset=utf-8'); res.setHeader('Content-Disposition','attachment; filename="student-life-manager.ics"'); res.send(cal.toString());
 } catch(e) { next(e); } });

const mailReady = () => Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS && process.env.SMTP_FROM);
async function sendDueReminders() {
  if (!mailReady()) return;
  const transporter = nodemailer.createTransport({ host: process.env.SMTP_HOST, port: Number(process.env.SMTP_PORT || 587), secure: String(process.env.SMTP_SECURE) === 'true', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
  const all = await StudentData.find({ 'settings.emailReminders': true }).populate('userId', 'email name').lean(); const today = new Date(); today.setHours(0,0,0,0);
  for (const d of all) {
    if (!d.userId?.email) continue; const days = Number(d.settings?.reminderWindow || 1); const limit = new Date(today); limit.setDate(limit.getDate()+days);
    const due = [...(d.tasks||[]).map(x=>({title:x.name||x.title,date:x.dueDate,done:x.completed||x.done,type:'Task'})), ...(d.assignments||[]).map(x=>({title:x.title||x.name,date:x.dueDate,done:x.completed,type:'Assignment'})), ...(d.exams||[]).map(x=>({title:x.subject||x.title,date:x.date,done:false,type:'Exam'}))].filter(x=>x.title && x.date && !x.done && new Date(`${x.date}T00:00:00`) >= today && new Date(`${x.date}T00:00:00`) <= limit);
    if (!due.length) continue;
    try { await transporter.sendMail({ from: process.env.SMTP_FROM, to: d.userId.email, subject: 'Your upcoming Student Life Manager deadlines', text: `Hi ${d.userId.name},\n\nHere are your upcoming items:\n${due.map(x=>`- ${x.type}: ${x.title} (${x.date})`).join('\n')}\n\nKeep going!\nStudent Life Manager` }); } catch (e) { console.error('Reminder email failed:', e.message); }
  }
}
cron.schedule('0 8 * * *', () => sendDueReminders().catch(e=>console.error('Reminder job failed:',e.message)));

app.use(express.static(path.join(__dirname, '../public'), { extensions: ['html'] }));
app.get('*', (req,res,next) => { if (req.path.startsWith('/api/')) return next(); res.sendFile(path.join(__dirname, '../public/index.html')); });
app.use((err, req, res, next) => { console.error(err); if (res.headersSent) return next(err); res.status(500).json({ error: 'Unexpected server error.' }); });

await mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/student_life_manager');
app.listen(port, () => console.log(`Student Life Manager running at http://localhost:${port}`));
