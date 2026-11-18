import express from 'express';
import cors from 'cors';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

dotenv.config();
console.log('[boot] modules loaded');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const TOKEN_SECRET = process.env.TOKEN_SECRET || 'portfolio-secret-change-me-in-production';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
console.log('[boot] folders ready');
console.log('[boot] loading...');

function defaultDb() {
  return {
    admin: {
      username: process.env.ADMIN_USER || 'admin',
      passwordHash: hashPass(process.env.ADMIN_PASS || 'admin123')
    },
    users: [],
    content: null,
    posts: [],
    comments: [],
    media: [],
    contacts: []
  };
}

function ensureDb() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify(defaultDb(), null, 2), 'utf8');
    return;
  }
  // migrate missing keys
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  let changed = false;
  const base = defaultDb();
  for (const k of Object.keys(base)) {
    if (db[k] === undefined) {
      db[k] = base[k];
      changed = true;
    }
  }
  if (!db.admin) {
    db.admin = base.admin;
    changed = true;
  }
  if (changed) writeDb(db);
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function writeDb(db) {
  ensureDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8');
}

function hashPass(pass, salt = null) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(pass), s, 32).toString('hex');
  return `scrypt:${s}:${derived}`;
}

function verifyPass(pass, stored) {
  if (!stored) return false;
  if (!String(stored).startsWith('scrypt:')) {
    const legacy = crypto.createHash('sha256').update(String(pass)).digest('hex');
    return legacy === stored;
  }
  const parts = String(stored).split(':');
  if (parts.length !== 3) return false;
  const salt = parts[1];
  const expected = parts[2];
  const derived = crypto.scryptSync(String(pass), salt, 32).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

function b64encode(s) { return Buffer.from(s).toString('base64url'); }
function b64decode(s) { return Buffer.from(s, 'base64url').toString('utf8'); }

function createToken(subject, role = 'user') {
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payload = b64encode(JSON.stringify({ sub: subject, role, exp }));
  const sig = b64encode(crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest());
  return `${payload}.${sig}`;
}

function parseToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = b64encode(crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest());
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(b64decode(payload));
    if (!data?.sub || !data?.exp || Date.now() > data.exp) return null;
    return data;
  } catch {
    return null;
  }
}

function getBearer(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

function authAny(req, res, next) {
  const data = parseToken(getBearer(req));
  if (!data) return res.status(401).json({ success: false, error: 'لطفاً وارد شوید' });
  req.auth = data;
  next();
}

function authStaff(req, res, next) {
  const data = parseToken(getBearer(req));
  if (!data) return res.status(401).json({ success: false, error: 'لطفاً دوباره وارد شوید' });
  if (!['admin', 'author'].includes(data.role)) {
    return res.status(403).json({ success: false, error: 'دسترسی ندارید' });
  }
  req.auth = data;
  next();
}

function authAdmin(req, res, next) {
  const data = parseToken(getBearer(req));
  if (!data) return res.status(401).json({ success: false, error: 'لطفاً دوباره وارد شوید' });
  if (data.role !== 'admin') return res.status(403).json({ success: false, error: 'فقط مدیر' });
  req.auth = data;
  next();
}

let _upload = null;
async function getUpload() {
  if (_upload) return _upload;
  const multer = (await import('multer')).default;
  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').slice(0, 10);
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
    }
  });
  _upload = multer({
    storage,
    limits: { fileSize: 8 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
      if (/^image\//.test(file.mimetype)) cb(null, true);
      else cb(new Error('فقط تصویر مجاز است'));
    }
  });
  return _upload;
}

console.log('[boot] ensureDb...');
ensureDb();
(() => {
  const db = readDb();
  let changed = false;
  if (!db.admin || !db.admin.username || !db.admin.passwordHash) {
    db.admin = {
      username: process.env.ADMIN_USER || 'admin',
      passwordHash: hashPass(process.env.ADMIN_PASS || 'admin123')
    };
    changed = true;
  }
  const resetFlag = path.join(DATA_DIR, 'RESET_ADMIN');
  if (fs.existsSync(resetFlag)) {
    db.admin = {
      username: process.env.ADMIN_USER || 'admin',
      passwordHash: hashPass(process.env.ADMIN_PASS || 'admin123')
    };
    changed = true;
    try { fs.unlinkSync(resetFlag); } catch {}
    console.log('[boot] admin reset -> admin / admin123');
  }
  if (changed) writeDb(db);
})();
console.log('[boot] db ready:', DB_FILE);

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

const distDir = path.join(__dirname, 'dist');
if (fs.existsSync(distDir)) app.use(express.static(distDir));

const hits = new Map();
function rateLimit(key, max = 20, windowMs = 60000) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  hits.set(key, arr);
  return true;
}

// ---------- Auth ----------
app.post('/api/login', (req, res) => {
  const ip = req.ip || 'x';
  if (!rateLimit('login:' + ip, 15)) return res.status(429).json({ success: false, error: 'تلاش زیاد. کمی صبر کنید.' });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, error: 'نام کاربری و رمز لازم است' });

  const db = readDb();
  if (username === db.admin.username && verifyPass(password, db.admin.passwordHash)) {
    const token = createToken('admin:' + db.admin.username, 'admin');
    return res.json({ success: true, role: 'admin', token, user: { username: db.admin.username, name: db.admin.username, role: 'admin' } });
  }

  const user = (db.users || []).find(u => u.username === username);
  if (!user || !verifyPass(password, user.passwordHash)) {
    return res.status(401).json({ success: false, error: 'نام کاربری یا رمز اشتباه است' });
  }
  const role = user.role || 'user';
  const token = createToken('user:' + user.id, role);
  res.json({
    success: true,
    role,
    token,
    user: { id: user.id, username: user.username, name: user.name, email: user.email, role }
  });
});

app.post('/api/register', (req, res) => {
  const ip = req.ip || 'x';
  if (!rateLimit('reg:' + ip, 8)) return res.status(429).json({ success: false, error: 'تلاش زیاد' });
  const { username, password, email, name } = req.body || {};
  if (!username || !password) return res.status(400).json({ success: false, error: 'نام کاربری و رمز لازم است' });
  if (String(username).length < 3) return res.status(400).json({ success: false, error: 'نام کاربری خیلی کوتاه است' });
  if (String(password).length < 6) return res.status(400).json({ success: false, error: 'رمز حداقل ۶ کاراکتر' });

  const db = readDb();
  if (username === db.admin.username) return res.status(400).json({ success: false, error: 'این نام کاربری مجاز نیست' });
  if ((db.users || []).some(u => u.username === username)) {
    return res.status(400).json({ success: false, error: 'این نام کاربری قبلاً ثبت شده' });
  }
  const id = crypto.randomUUID();
  const user = {
    id,
    username: String(username).trim(),
    email: String(email || '').trim(),
    name: String(name || username).trim(),
    passwordHash: hashPass(password),
    role: 'user',
    createdAt: new Date().toISOString()
  };
  db.users = db.users || [];
  db.users.push(user);
  writeDb(db);
  const token = createToken('user:' + id, 'user');
  res.json({ success: true, role: 'user', token, user: { id, username: user.username, name: user.name, email: user.email, role: 'user' } });
});

app.get('/api/check-auth', (req, res) => {
  const data = parseToken(getBearer(req));
  if (!data) return res.json({ success: false });
  if (data.role === 'admin') {
    return res.json({ success: true, role: 'admin', user: { username: String(data.sub).replace(/^admin:/, ''), role: 'admin' } });
  }
  const id = String(data.sub).replace(/^user:/, '');
  const db = readDb();
  const user = (db.users || []).find(u => u.id === id);
  if (!user) return res.json({ success: false });
  res.json({
    success: true,
    role: user.role || 'user',
    user: { id: user.id, username: user.username, name: user.name, email: user.email, role: user.role || 'user' }
  });
});

app.put('/api/admin/account', authAdmin, (req, res) => {
  const { username, currentPassword, newPassword } = req.body || {};
  const db = readDb();
  if (!verifyPass(currentPassword || '', db.admin.passwordHash)) {
    return res.status(400).json({ success: false, error: 'رمز فعلی اشتباه است' });
  }
  if (username) db.admin.username = String(username).trim();
  if (newPassword) {
    if (String(newPassword).length < 6) return res.status(400).json({ success: false, error: 'رمز جدید کوتاه است' });
    db.admin.passwordHash = hashPass(newPassword);
  }
  writeDb(db);
  res.json({ success: true });
});

app.put('/api/profile', authAny, (req, res) => {
  if (req.auth.role === 'admin') return res.status(400).json({ success: false, error: 'از بخش حساب ادمین استفاده کنید' });
  const id = String(req.auth.sub).replace(/^user:/, '');
  const db = readDb();
  const idx = (db.users || []).findIndex(u => u.id === id);
  if (idx < 0) return res.status(404).json({ success: false, error: 'کاربر پیدا نشد' });
  const user = db.users[idx];
  const { name, username, email, currentPassword, newPassword } = req.body || {};
  if (newPassword) {
    if (!verifyPass(currentPassword || '', user.passwordHash)) {
      return res.status(400).json({ success: false, error: 'رمز فعلی اشتباه است' });
    }
    if (String(newPassword).length < 6) return res.status(400).json({ success: false, error: 'رمز جدید کوتاه است' });
    user.passwordHash = hashPass(newPassword);
  }
  if (username && username !== user.username) {
    if ((db.users || []).some(u => u.username === username && u.id !== id)) {
      return res.status(400).json({ success: false, error: 'نام کاربری تکراری است' });
    }
    user.username = username;
  }
  if (name !== undefined) user.name = name;
  if (email !== undefined) user.email = email;
  db.users[idx] = user;
  writeDb(db);
  res.json({ success: true, user: { id: user.id, username: user.username, name: user.name, email: user.email, role: user.role || 'user' } });
});

app.get('/api/admin/users', authAdmin, (_req, res) => {
  const db = readDb();
  const users = (db.users || []).map(u => ({
    id: u.id, username: u.username, email: u.email, name: u.name, role: u.role || 'user', createdAt: u.createdAt
  }));
  res.json({ success: true, users });
});

app.put('/api/admin/users/:id/role', authAdmin, (req, res) => {
  const role = req.body?.role;
  if (!['user', 'author'].includes(role)) return res.status(400).json({ success: false, error: 'نقش نامعتبر' });
  const db = readDb();
  const user = (db.users || []).find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ success: false, error: 'کاربر پیدا نشد' });
  user.role = role;
  writeDb(db);
  res.json({ success: true });
});

// ---------- Content ----------
app.get('/api/content', (_req, res) => {
  const db = readDb();
  res.json({ success: true, content: db.content || null });
});

app.put('/api/content', authAdmin, (req, res) => {
  const db = readDb();
  db.content = req.body?.content || req.body || {};
  writeDb(db);
  res.json({ success: true });
});

// ---------- Posts ----------
app.get('/api/posts', (req, res) => {
  const q = String(req.query.q || '').trim().toLowerCase();
  const category = String(req.query.category || '').trim();
  const tag = String(req.query.tag || '').trim();
  let posts = [...(readDb().posts || [])];
  if (q) {
    posts = posts.filter(p =>
      (p.title || '').toLowerCase().includes(q) ||
      (p.excerpt || '').toLowerCase().includes(q) ||
      (p.content || '').toLowerCase().includes(q) ||
      (p.tags || []).join(',').toLowerCase().includes(q)
    );
  }
  if (category) posts = posts.filter(p => (p.categories || []).includes(category));
  if (tag) posts = posts.filter(p => (p.tags || []).includes(tag));
  posts.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ success: true, posts });
});

app.post('/api/posts', authStaff, (req, res) => {
  const p = req.body || {};
  if (!p.id || !p.title) return res.status(400).json({ success: false, error: 'داده نامعتبر' });
  const db = readDb();
  db.posts = db.posts || [];

  if (p.featured) {
    db.posts = db.posts.map(x => ({ ...x, featured: false }));
  }

  let authorName = p.authorName || 'مدیر';
  if (req.auth.role !== 'admin') {
    const uid = String(req.auth.sub).replace(/^user:/, '');
    const u = (db.users || []).find(x => x.id === uid);
    authorName = u?.name || u?.username || 'نویسنده';
  }

  const idx = db.posts.findIndex(x => x.id === p.id);
  const normalized = {
    id: p.id,
    title: p.title,
    slug: p.slug,
    content: p.content || '',
    excerpt: p.excerpt || '',
    status: p.status || 'draft',
    visibility: p.visibility || 'public',
    categories: p.categories || [],
    tags: p.tags || [],
    featuredImage: p.featuredImage || '',
    featured: !!p.featured,
    seoTitle: p.seoTitle || '',
    seoDescription: p.seoDescription || '',
    views: idx >= 0 ? (db.posts[idx].views || 0) : (p.views || 0),
    authorId: req.auth.role === 'admin' ? null : String(req.auth.sub).replace(/^user:/, ''),
    authorName,
    date: idx >= 0 ? db.posts[idx].date : (p.date || new Date().toISOString()),
    updatedAt: new Date().toISOString()
  };

  if (idx >= 0) db.posts[idx] = { ...db.posts[idx], ...normalized };
  else db.posts.unshift(normalized);

  writeDb(db);
  res.json({ success: true, posts: db.posts });
});

app.delete('/api/posts/:id', authStaff, (req, res) => {
  const db = readDb();
  db.posts = (db.posts || []).filter(p => p.id !== req.params.id);
  db.comments = (db.comments || []).filter(c => c.postId !== req.params.id);
  writeDb(db);
  res.json({ success: true, posts: db.posts });
});

app.post('/api/posts/:id/view', (req, res) => {
  const db = readDb();
  const post = (db.posts || []).find(p => p.id === req.params.id);
  if (post) {
    post.views = (Number(post.views) || 0) + 1;
    writeDb(db);
  }
  res.json({ success: true, views: post?.views || 0, posts: db.posts || [] });
});

// ---------- Comments ----------
app.get('/api/posts/:id/comments', (req, res) => {
  const db = readDb();
  let comments = (db.comments || []).filter(c => c.postId === req.params.id);
  if (req.query.all !== '1') comments = comments.filter(c => c.status === 'approved');
  comments.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, comments });
});

app.post('/api/posts/:id/comments', authAny, (req, res) => {
  const body = String(req.body?.body || '').trim();
  if (body.length < 2) return res.status(400).json({ success: false, error: 'متن نظر کوتاه است' });
  const db = readDb();
  const post = (db.posts || []).find(p => p.id === req.params.id && p.status === 'published');
  if (!post) return res.status(404).json({ success: false, error: 'مطلب پیدا نشد' });

  let authorName = 'کاربر';
  let userId = null;
  if (req.auth.role === 'admin') {
    authorName = db.admin.username || 'مدیر';
  } else {
    userId = String(req.auth.sub).replace(/^user:/, '');
    const u = (db.users || []).find(x => x.id === userId);
    authorName = u?.name || u?.username || 'کاربر';
  }

  const comment = {
    id: crypto.randomUUID(),
    postId: req.params.id,
    userId,
    authorName,
    body,
    status: 'pending',
    createdAt: new Date().toISOString()
  };
  db.comments = db.comments || [];
  db.comments.unshift(comment);
  writeDb(db);
  res.json({ success: true, message: 'نظر ثبت شد و پس از تأیید نمایش داده می‌شود' });
});

app.get('/api/admin/comments', authAdmin, (_req, res) => {
  const db = readDb();
  const postsMap = Object.fromEntries((db.posts || []).map(p => [p.id, p.title]));
  const comments = (db.comments || [])
    .map(c => ({ ...c, postTitle: postsMap[c.postId] || c.postId }))
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ success: true, comments });
});

app.put('/api/admin/comments/:id', authAdmin, (req, res) => {
  const status = req.body?.status;
  if (!['approved', 'pending', 'spam'].includes(status)) {
    return res.status(400).json({ success: false, error: 'وضعیت نامعتبر' });
  }
  const db = readDb();
  const c = (db.comments || []).find(x => x.id === req.params.id);
  if (!c) return res.status(404).json({ success: false, error: 'نظر پیدا نشد' });
  c.status = status;
  writeDb(db);
  res.json({ success: true });
});

app.delete('/api/admin/comments/:id', authAdmin, (req, res) => {
  const db = readDb();
  db.comments = (db.comments || []).filter(c => c.id !== req.params.id);
  writeDb(db);
  res.json({ success: true });
});

// ---------- Media ----------
app.post('/api/upload', authStaff, async (req, res) => {
  let upload;
  try {
    upload = await getUpload();
  } catch (e) {
    return res.status(500).json({ success: false, error: 'ماژول آپلود نصب نیست. npm install multer' });
  }
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ success: false, error: err.message || 'خطا در آپلود' });
    if (!req.file) return res.status(400).json({ success: false, error: 'فایلی ارسال نشد' });
    const db = readDb();
    const item = {
      id: crypto.randomUUID(),
      filename: req.file.filename,
      originalName: req.file.originalname,
      mime: req.file.mimetype,
      size: req.file.size,
      url: '/uploads/' + req.file.filename,
      uploadedBy: String(req.auth.sub),
      createdAt: new Date().toISOString()
    };
    db.media = db.media || [];
    db.media.unshift(item);
    writeDb(db);
    res.json({ success: true, url: item.url, id: item.id, media: item });
  });
});

app.get('/api/media', authStaff, (_req, res) => {
  const db = readDb();
  res.json({ success: true, media: db.media || [] });
});

app.delete('/api/media/:id', authAdmin, (req, res) => {
  const db = readDb();
  const m = (db.media || []).find(x => x.id === req.params.id);
  if (m) {
    const fp = path.join(UPLOAD_DIR, m.filename);
    if (fs.existsSync(fp)) try { fs.unlinkSync(fp); } catch {}
    db.media = db.media.filter(x => x.id !== req.params.id);
    writeDb(db);
  }
  res.json({ success: true });
});

// ---------- Stats ----------
app.get('/api/admin/stats', authAdmin, (_req, res) => {
  const db = readDb();
  const posts = db.posts || [];
  const comments = db.comments || [];
  const users = db.users || [];
  const contacts = db.contacts || [];
  const published = posts.filter(p => p.status === 'published');
  const totalViews = posts.reduce((s, p) => s + (Number(p.views) || 0), 0);
  const topPosts = [...published]
    .sort((a, b) => (Number(b.views) || 0) - (Number(a.views) || 0))
    .slice(0, 5)
    .map(p => ({ id: p.id, title: p.title, slug: p.slug, views: p.views || 0 }));

  res.json({
    success: true,
    stats: {
      postsCount: posts.length,
      published: published.length,
      usersCount: users.length,
      commentsCount: comments.length,
      pendingComments: comments.filter(c => c.status === 'pending').length,
      contactsCount: contacts.length,
      totalViews,
      topPosts
    }
  });
});

// ---------- Contact ----------
app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body || {};
  if (!name || !email || !message) {
    return res.status(400).json({ success: false, error: 'لطفاً همه فیلدها را پر کنید' });
  }
  const db = readDb();
  db.contacts = db.contacts || [];
  db.contacts.unshift({
    id: crypto.randomUUID(),
    name,
    email,
    message,
    createdAt: new Date().toISOString()
  });
  writeDb(db);

  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.log('CONTACT DEMO', { name, email, message });
    return res.json({ success: true, demo: true });
  }
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
    });
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      replyTo: email,
      subject: `پیام جدید از ${name}`,
      text: `نام: ${name}\nایمیل: ${email}\n\n${message}`
    });
    res.json({ success: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'خطا در ارسال پیام' });
  }
});

// ---------- SEO ----------
app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send('User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n');
});

app.get('/sitemap.xml', (req, res) => {
  const base = `${req.protocol}://${req.get('host')}`;
  const posts = (readDb().posts || []).filter(p => p.status === 'published');
  const urls = ['', '/blog', '/about', '/contact', ...posts.map(p => `/blog/${p.slug}`)];
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map(u => `  <url><loc>${base}${u}</loc></url>`).join('\n')}
</urlset>`;
  res.type('application/xml').send(xml);
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, db: 'json-file', time: new Date().toISOString() });
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ success: false, error: 'API not found' });
  const indexPath = path.join(distDir, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.status(200).type('html').send(`<!doctype html><html lang="fa" dir="rtl"><body style="font-family:sans-serif;padding:40px">
  <h2>API Server ✓</h2><p>فرانت: <code>npm run dev</code></p></body></html>`);
});

const server = app.listen(PORT, '127.0.0.1', () => {
  const db = readDb();
  console.log('');
  console.log('========================================');
  console.log(`Server running on http://127.0.0.1:${PORT}`);
  console.log(`Health: http://127.0.0.1:${PORT}/api/health`);
  console.log(`DB file: ${DB_FILE}`);
  console.log(`Admin: ${db.admin?.username || 'admin'}`);
  console.log('========================================');
  console.log('');
});

server.on('error', (err) => {
  console.error('[server error]', err.message);
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is busy. Close the other process or change PORT in .env`);
  }
  process.exit(1);
});
