const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const mongoose = require('mongoose');

const app = express();

for (const envFile of [path.join(__dirname, '.env'), path.join(__dirname, 'mango.env')]) {
    if (fs.existsSync(envFile)) {
        fs.readFileSync(envFile, 'utf8').split(/\r?\n/).forEach((line) => {
            const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
            if (match && !process.env[match[1]]) {
                process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
            }
        });
    }
}

const PORT = Number(process.env.PORT) || 3000;

const sessions = new Map();
const sessionLifetimeMs = 8 * 60 * 60 * 1000;
const loginAttempts = new Map();
const studentLoginAttempts = new Map();
const loginWindowMs = 15 * 60 * 1000;
const maxLoginAttempts = 8;
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const adminPasswordHash = process.env.NODE_ENV === 'test' ? undefined : process.env.ADMIN_PASSWORD_HASH;
const adminPassword = process.env.NODE_ENV === 'test' ? process.env.ADMIN_PASSWORD : process.env.ADMIN_PASSWORD;
const secureCookie = process.env.NODE_ENV === 'production' ? '; Secure' : '';
const studentSessionLifetimeMs = 10 * 24 * 60 * 60 * 1000;

function cleanText(value, maxLength = 500) {
    return String(value ?? '').replace(/<[^>]*>/g, '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, maxLength);
}

function publicRecord(record) {
    const value = record.toObject ? record.toObject() : { ...record };
    for (const key of ['title', 'content', 'program', 'subject', 'class', 'section', 'uploadDate']) {
        if (value[key] !== undefined) value[key] = cleanText(value[key], key === 'content' ? 20000 : 500);
    }
    if (value.filename !== undefined) value.filename = safeFilename(value.filename) || '';
    if (value.imageFilename !== undefined) value.imageFilename = safeFilename(value.imageFilename) || '';
    return value;
}
setInterval(() => {
    const now = Date.now();
    for (const [token, session] of sessions) {
        if (session.expiresAt < now) sessions.delete(token);
    }
    for (const [token, session] of studentSessions) {
        if (session.expiresAt < now) studentSessions.delete(token);
    }
    for (const [key, attempt] of loginAttempts) {
        if (attempt.blockedUntil < now && now - attempt.firstAttempt > loginWindowMs) loginAttempts.delete(key);
    }
    for (const [key, attempt] of studentLoginAttempts) {
        if (attempt.blockedUntil < now && now - attempt.firstAttempt > loginWindowMs) studentLoginAttempts.delete(key);
    }
}, 10 * 60 * 1000).unref();

function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (error, derivedKey) => {
            if (error) return reject(error);
            resolve(derivedKey);
        });
    });
}

async function verifyPassword(password, storedHash) {
    if (!storedHash || !storedHash.includes(':')) return false;
    const [salt, expectedHex] = storedHash.split(':');
    const expected = Buffer.from(expectedHex, 'hex');
    const actual = await hashPassword(password, salt);
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function getSession(req) {
    const token = req.headers.cookie?.match(/(?:^|;\s*)zoo_session=([^;]+)/)?.[1];
    const session = token ? sessions.get(token) : null;
    if (!session || session.expiresAt < Date.now()) {
        if (token) sessions.delete(token);
        return null;
    }

    session.expiresAt = Date.now() + sessionLifetimeMs;
    return session;
}

function clientAddress(req) {
    return String(req.ip || req.socket.remoteAddress || 'unknown').slice(0, 128);
}

function sameOrigin(req) {
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    if (origin) {
        return origin === `${req.protocol}://${req.get('host')}`;
    }
    if (referer) {
        try {
            return new URL(referer).origin === `${req.protocol}://${req.get('host')}`;
        } catch {
            return false;
        }
    }
    return false;
}

function csrfProtection(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method) || (!getSession(req) && !getStudentSession(req))) return next();
    if (!sameOrigin(req)) return res.status(403).json({ error: 'CSRF validation failed' });
    next();
}

function requireAdmin(req, res, next) {
    if (!getSession(req)?.isAdmin) {
        return res.status(401).json({ error: 'Admin authentication required' });
    }
    next();
}

function getStudentSession(req) {
    const token = req.headers.cookie?.match(/(?:^|;\s*)zoo_student_session=([^;]+)/)?.[1];
    const session = token ? studentSessions.get(token) : null;
    if (!session || session.expiresAt < Date.now()) {
        if (token) studentSessions.delete(token);
        return null;
    }
    session.expiresAt = Date.now() + studentSessionLifetimeMs;
    return session;
}

async function requireStudent(req, res, next) {
    const session = getStudentSession(req);
    if (!session?.studentId || !(await Student.exists({ _id: session.studentId, active: { $ne: false } }))) {
        return res.status(401).json({ error: 'Student login required' });
    }
    next();
}

function safeFilename(filename) {
    const name = path.basename(String(filename || ''));
    return name && name === String(filename) && !/[<>:"/\\|?*\x00-\x1f]/.test(name) ? name : null;
}

function sendDownload(directory, filename, res) {
    const safeName = safeFilename(filename);
    if (!safeName) return res.status(400).json({ error: 'Invalid filename' });
    const filePath = path.join(directory, safeName);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
        return res.status(404).json({ error: 'File not found' });
    }
    return res.download(filePath, safeName);
}

function sendMedia(directory, filename, res) {
    const safeName = safeFilename(filename);
    if (!safeName) return res.status(400).end();
    const filePath = path.join(directory, safeName);
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) return res.status(404).end();
    return res.sendFile(filePath);
}

async function publishedFile(model, filename) {
    const safeName = safeFilename(filename);
    if (!safeName) return null;
    return model.findOne({
        filename: safeName,
        $or: [{ published: true }, { published: { $exists: false } }]
    }).lean();
}

// MongoDB connection
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/zoo-education';

// Define mongoose schemas and models
const reportSchema = new mongoose.Schema({
    // Define fields as per expected report data structure
}, { strict: false, timestamps: true });

const blogPostSchema = new mongoose.Schema({
    title: { type: String, required: true, maxlength: 160 },
    content: { type: String, required: true, maxlength: 20000 },
    imageFilename: String,
    postTime: Number,
    likes: { type: Number, default: 0 },
    comments: [{
        name: String,
        text: String,
        date: { type: Date, default: Date.now }
    }]
}, { timestamps: true });

const assignmentPostSchema = new mongoose.Schema({
    program: String,
    subject: String,
    title: String,
    uploadDate: String,
    filename: String,
    published: { type: Boolean, default: true },
}, { timestamps: true });

const bookPostSchema = new mongoose.Schema({
    class: String,
    program: String,
    subject: String,
    title: String,
    filename: String,
    published: { type: Boolean, default: true },
}, { timestamps: true });

const entryTestPostSchema = new mongoose.Schema({
    class: String,
    subject: String,
    title: String,
    section: String,
    filename: String,
    published: { type: Boolean, default: true },
}, { timestamps: true });

const pastPaperPostSchema = new mongoose.Schema({
    class: String,
    subject: String,
    title: String,
    filename: String,
    published: { type: Boolean, default: true },
}, { timestamps: true });

const quizSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true, maxlength: 160 },
    questions: { type: mongoose.Schema.Types.Mixed, required: true },
    published: { type: Boolean, default: true }
}, { timestamps: true });

const Report = mongoose.model('Report', reportSchema);
const BlogPost = mongoose.model('BlogPost', blogPostSchema);
const AssignmentPost = mongoose.model('AssignmentPost', assignmentPostSchema);
const BookPost = mongoose.model('BookPost', bookPostSchema);
const EntryTestPost = mongoose.model('EntryTestPost', entryTestPostSchema);
const PastPaperPost = mongoose.model('PastPaperPost', pastPaperPostSchema);
const Quiz = mongoose.model('Quiz', quizSchema);

const studentSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, maxlength: 80 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
    passwordHash: { type: String, required: true, select: false },
    totalScore: { type: Number, default: 0, min: 0 },
    testsCompleted: { type: Number, default: 0, min: 0 },
    active: { type: Boolean, default: true },
    lastLoginAt: { type: Date, default: Date.now }
}, { timestamps: true });
const studentScoreSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true },
    score: { type: Number, required: true, min: 0 },
    maxScore: { type: Number, required: true, min: 1 },
    percentage: { type: Number, required: true, min: 0, max: 100 },
    quizTitle: { type: String, trim: true, maxlength: 160 }
}, { timestamps: true });
const studentMessageSchema = new mongoose.Schema({
    student: { type: mongoose.Schema.Types.ObjectId, ref: 'Student', required: true },
    studentName: { type: String, required: true, trim: true, maxlength: 80 },
    message: { type: String, required: true, trim: true, maxlength: 500 }
}, { timestamps: true });
const Student = mongoose.model('Student', studentSchema);
const StudentScore = mongoose.model('StudentScore', studentScoreSchema);
const StudentMessage = mongoose.model('StudentMessage', studentMessageSchema);
const studentSessions = new Map();

// Ensure upload directories exist
const uploadRoot = path.join(__dirname, 'storage');
const blogUploadDir = path.join(uploadRoot, 'blog');
const assignmentUploadDir = path.join(uploadRoot, 'assignments');
const booksUploadDir = path.join(uploadRoot, 'books');
const entryTestUploadDir = path.join(uploadRoot, 'entry-test');
const pastPapersUploadDir = path.join(uploadRoot, 'past-papers');

const adminCollections = {
    blogs: { model: BlogPost, fields: ['title', 'content', 'imageFilename', 'postTime'], directory: blogUploadDir },
    assignments: { model: AssignmentPost, fields: ['program', 'subject', 'title', 'uploadDate', 'filename'], directory: assignmentUploadDir },
    books: { model: BookPost, fields: ['class', 'program', 'subject', 'title', 'filename'], directory: booksUploadDir },
    'entry-test': { model: EntryTestPost, fields: ['class', 'subject', 'title', 'section', 'filename'], directory: entryTestUploadDir },
    'past-papers': { model: PastPaperPost, fields: ['class', 'subject', 'title', 'filename'], directory: pastPapersUploadDir },
    quizzes: { model: Quiz, fields: ['title', 'questions'], directory: null }
};

if (!fs.existsSync(blogUploadDir)) {
    fs.mkdirSync(blogUploadDir, { recursive: true });
}
if (!fs.existsSync(assignmentUploadDir)) {
    fs.mkdirSync(assignmentUploadDir, { recursive: true });
}
if (!fs.existsSync(booksUploadDir)) {
    fs.mkdirSync(booksUploadDir, { recursive: true });
}
if (!fs.existsSync(entryTestUploadDir)) {
    fs.mkdirSync(entryTestUploadDir, { recursive: true });
}
if (!fs.existsSync(pastPapersUploadDir)) {
    fs.mkdirSync(pastPapersUploadDir, { recursive: true });
}

// Multer storage configurations
const generatedUploadName = (file) => `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`;

const storageBlog = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, blogUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, generatedUploadName(file));
    }
});

const storageAssignment = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, assignmentUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, generatedUploadName(file));
    }
});

const storageBook = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, booksUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, generatedUploadName(file));
    }
});

const storageEntryTest = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, entryTestUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, generatedUploadName(file));
    }
});

const storagePastPapers = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, pastPapersUploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, generatedUploadName(file));
    }
});

const fileFilter = (req, file, cb) => {
    const allowedMimes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    const allowedExts = ['.pdf', '.docx'];
    if (allowedMimes.includes(file.mimetype) && allowedExts.includes(path.extname(file.originalname).toLowerCase())) {
        cb(null, true);
    } else {
        cb(new Error('Only PDF and DOCX files are allowed'), false);
    }
};

async function validateUploadedFile(req, res, next) {
    if (!req.file) return next();
    try {
        const handle = await fs.promises.open(req.file.path, 'r');
        const header = Buffer.alloc(8);
        await handle.read(header, 0, header.length, 0);
        await handle.close();
        const extension = path.extname(req.file.originalname).toLowerCase();
        const valid = extension === '.pdf'
            ? header.subarray(0, 5).toString() === '%PDF-'
            : extension === '.docx'
                ? header.subarray(0, 4).toString('hex') === '504b0304'
                : false;
        if (!valid) {
            await fs.promises.unlink(req.file.path).catch(() => {});
            return res.status(400).json({ error: 'File content does not match its type' });
        }
        next();
    } catch (error) {
        await fs.promises.unlink(req.file.path).catch(() => {});
        next(error);
    }
}

const uploadLimits = { fileSize: 10 * 1024 * 1024, files: 1 };
const uploadBlog = multer({ storage: storageBlog, fileFilter: fileFilter, limits: uploadLimits });
const uploadAssignment = multer({ storage: storageAssignment, fileFilter: fileFilter, limits: uploadLimits });
const uploadBook = multer({ storage: storageBook, fileFilter: fileFilter, limits: uploadLimits });
const uploadEntryTest = multer({ storage: storageEntryTest, fileFilter: fileFilter, limits: uploadLimits });
const uploadPastPapers = multer({ storage: storagePastPapers, fileFilter: fileFilter, limits: uploadLimits });

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb', strict: true }));
app.use(express.urlencoded({ extended: true, limit: '1mb', parameterLimit: 200 }));

app.get('/health', (req, res) => {
    const databaseReady = mongoose.connection.readyState === 1;
    res.status(databaseReady ? 200 : 503).json({
        status: databaseReady ? 'ok' : 'degraded',
        database: databaseReady ? 'connected' : 'disconnected'
    });
});

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Content-Security-Policy', "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; connect-src 'self'");
    if (/\.(env|js|json|lock|md)$/i.test(req.path) || req.path.includes('-uploads/') || req.path.startsWith('/storage/')) {
        return res.status(404).end();
    }
    next();
});

app.use(csrfProtection);

app.get('/admin.html', (req, res) => {
    if (!getSession(req)?.isAdmin) return res.redirect('/login.html');
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/login.html', (req, res) => {
    if (getSession(req)?.isAdmin) return res.redirect('/admin.html');
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.use(express.static(path.join(__dirname)));

app.post('/api/auth/login', async (req, res) => {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const attemptKey = `${clientAddress(req)}:${username.toLowerCase().slice(0, 100)}`;
    const attempts = loginAttempts.get(attemptKey);
    if (attempts && attempts.blockedUntil > Date.now()) {
        res.setHeader('Retry-After', Math.ceil((attempts.blockedUntil - Date.now()) / 1000));
        return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
    }
    let validPassword = false;
    if (adminPasswordHash) {
        validPassword = await verifyPassword(password, adminPasswordHash);
    } else if (adminPassword) {
        const supplied = Buffer.from(password);
        const expected = Buffer.from(adminPassword);
        validPassword = supplied.length === expected.length && crypto.timingSafeEqual(supplied, expected);
    }
    if (username !== adminUsername || !validPassword) {
        const current = loginAttempts.get(attemptKey) || { count: 0, blockedUntil: 0, firstAttempt: Date.now() };
        if (Date.now() - current.firstAttempt > loginWindowMs) {
            current.count = 0;
            current.firstAttempt = Date.now();
        }
        current.count += 1;
        if (current.count >= maxLoginAttempts) {
            current.blockedUntil = Date.now() + Math.min(loginWindowMs, 1000 * 2 ** (current.count - maxLoginAttempts));
        }
        loginAttempts.set(attemptKey, current);
        return res.status(401).json({ error: 'Invalid username or password' });
    }
    loginAttempts.delete(attemptKey);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { isAdmin: true, expiresAt: Date.now() + sessionLifetimeMs });
    res.setHeader('Set-Cookie', `zoo_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${sessionLifetimeMs / 1000}${secureCookie}`);
    res.json({ message: 'Signed in successfully' });
});

app.post('/api/auth/logout', (req, res) => {
    const token = req.headers.cookie?.match(/(?:^|;\s*)zoo_session=([^;]+)/)?.[1];
    if (token) sessions.delete(token);
    res.setHeader('Set-Cookie', `zoo_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie}`);
    res.json({ message: 'Signed out' });
});

app.get('/api/auth/session', (req, res) => {
    res.json({ authenticated: Boolean(getSession(req)?.isAdmin) });
});

app.post('/api/student/auth/register', async (req, res) => {
    const name = cleanText(req.body?.name, 80);
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Enter a valid name, email, and password of at least 8 characters' });
    }
    if (await Student.exists({ email })) return res.status(409).json({ error: 'An account with this email already exists' });
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = `${salt}:${(await hashPassword(password, salt)).toString('hex')}`;
    const student = await Student.create({ name, email, passwordHash });
    const token = crypto.randomBytes(32).toString('hex');
    studentSessions.set(token, { studentId: String(student._id), expiresAt: Date.now() + studentSessionLifetimeMs });
    res.setHeader('Set-Cookie', `zoo_student_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${studentSessionLifetimeMs / 1000}${secureCookie}`);
    res.status(201).json({ student: { name: student.name, email: student.email } });
});

app.post('/api/student/auth/login', async (req, res) => {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const attemptKey = `${clientAddress(req)}:${email.slice(0, 254)}`;
    const attempts = studentLoginAttempts.get(attemptKey);
    if (attempts && attempts.blockedUntil > Date.now()) {
        res.setHeader('Retry-After', Math.ceil((attempts.blockedUntil - Date.now()) / 1000));
        return res.status(429).json({ error: 'Too many sign-in attempts. Try again later.' });
    }
    const student = await Student.findOne({ email, active: { $ne: false } }).select('+passwordHash');
    if (!student || !(await verifyPassword(password, student.passwordHash))) {
        const current = attempts || { count: 0, blockedUntil: 0, firstAttempt: Date.now() };
        if (Date.now() - current.firstAttempt > loginWindowMs) {
            current.count = 0;
            current.firstAttempt = Date.now();
        }
        current.count += 1;
        if (current.count >= maxLoginAttempts) current.blockedUntil = Date.now() + Math.min(loginWindowMs, 1000 * 2 ** (current.count - maxLoginAttempts));
        studentLoginAttempts.set(attemptKey, current);
        return res.status(401).json({ error: 'Invalid student email or password' });
    }
    studentLoginAttempts.delete(attemptKey);
    student.lastLoginAt = new Date();
    await student.save();
    const token = crypto.randomBytes(32).toString('hex');
    studentSessions.set(token, { studentId: String(student._id), expiresAt: Date.now() + studentSessionLifetimeMs });
    res.setHeader('Set-Cookie', `zoo_student_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${studentSessionLifetimeMs / 1000}${secureCookie}`);
    res.json({ student: { name: student.name, email: student.email } });
});

app.post('/api/student/auth/logout', (req, res) => {
    const token = req.headers.cookie?.match(/(?:^|;\s*)zoo_student_session=([^;]+)/)?.[1];
    if (token) studentSessions.delete(token);
    res.setHeader('Set-Cookie', `zoo_student_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie}`);
    res.json({ message: 'Signed out' });
});

app.get('/api/student/auth/session', requireStudent, async (req, res) => {
    const student = await Student.findById(getStudentSession(req).studentId).select('name email totalScore testsCompleted');
    if (!student) return res.status(401).json({ error: 'Student account not found' });
    res.json({ student });
});

app.get('/api/students/leaderboard', async (req, res) => {
    const students = await Student.find().select('name totalScore testsCompleted').sort({ totalScore: -1, testsCompleted: -1, name: 1 }).limit(10).lean();
    res.json(students.map((student, index) => ({ rank: index + 1, ...student })));
});

app.get('/api/student/messages', async (req, res) => {
    const messages = await StudentMessage.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json(messages.reverse().map((message) => ({ name: message.studentName, message: message.message, createdAt: message.createdAt })));
});

app.post('/api/student/messages', requireStudent, async (req, res) => {
    const message = cleanText(req.body?.message, 500);
    if (!message) return res.status(400).json({ error: 'Message cannot be empty' });
    const session = getStudentSession(req);
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const sent = await StudentMessage.countDocuments({ student: session.studentId, createdAt: { $gte: since } });
    if (sent >= 5) return res.status(429).json({ error: 'Daily message limit reached. You can send 5 messages every 24 hours.' });
    const student = await Student.findById(session.studentId).select('name');
    if (!student) return res.status(401).json({ error: 'Student account not found' });
    const saved = await StudentMessage.create({ student: student._id, studentName: student.name, message });
    res.status(201).json({ name: saved.studentName, message: saved.message, createdAt: saved.createdAt });
});

app.post('/api/student/scores', requireStudent, async (req, res) => {
    const score = Number(req.body?.score);
    const maxScore = Number(req.body?.maxScore);
    const quizTitle = cleanText(req.body?.quizTitle || 'Practice test', 160);
    if (!Number.isInteger(score) || !Number.isInteger(maxScore) || maxScore < 1 || score < 0 || score > maxScore) {
        return res.status(400).json({ error: 'Invalid score' });
    }
    const session = getStudentSession(req);
    const percentage = Math.round((score / maxScore) * 10000) / 100;
    await StudentScore.create({ student: session.studentId, score, maxScore, percentage, quizTitle });
    const student = await Student.findByIdAndUpdate(session.studentId, { $inc: { totalScore: score, testsCompleted: 1 } }, { new: true }).select('name email totalScore testsCompleted');
    res.status(201).json({ student, percentage });
});

app.get('/api/admin/content', requireAdmin, async (req, res) => {
    const [blogs, assignments, books, entryTest, pastPapers, quizzes] = await Promise.all([
        BlogPost.find().sort({ createdAt: -1 }).limit(100).lean(),
        AssignmentPost.find().sort({ createdAt: -1 }).limit(100).lean(),
        BookPost.find().sort({ createdAt: -1 }).limit(100).lean(),
        EntryTestPost.find().sort({ createdAt: -1 }).limit(100).lean(),
        PastPaperPost.find().sort({ createdAt: -1 }).limit(100).lean(),
        Quiz.find().sort({ createdAt: -1 }).limit(100).lean()
    ]);
    res.json({
        blogs: blogs.map(publicRecord),
        assignments: assignments.map(publicRecord),
        books: books.map(publicRecord),
        entryTest: entryTest.map(publicRecord),
        pastPapers: pastPapers.map(publicRecord),
        quizzes
    });
});

app.get('/api/admin/students', requireAdmin, async (req, res) => {
        const search = cleanText(req.query?.search, 100);
        const status = String(req.query?.status || '').trim();
        const query = {};
        if (search) query.$or = [
            { name: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } }
        ];
        if (status === 'active') query.active = { $ne: false };
        if (status === 'blocked') query.active = false;
        const students = await Student.find(query)
            .select('name email totalScore testsCompleted active lastLoginAt createdAt')
            .sort({ createdAt: -1 })
            .limit(200)
            .lean();
        res.json(students);
});

app.patch('/api/admin/students/:id/access', requireAdmin, async (req, res) => {
        if (!mongoose.Types.ObjectId.isValid(req.params.id) || typeof req.body?.active !== 'boolean') {
            return res.status(400).json({ error: 'Invalid student access request' });
        }
        const student = await Student.findByIdAndUpdate(
            req.params.id,
            { active: req.body.active },
            { new: true, projection: 'name email totalScore testsCompleted active lastLoginAt createdAt' }
        ).lean();
        if (!student) return res.status(404).json({ error: 'Student not found' });
        if (!student.active) {
            for (const [token, session] of studentSessions) {
                if (session.studentId === String(student._id)) studentSessions.delete(token);
            }
        }
        res.json(student);
});

app.post('/api/admin/:resource', requireAdmin, async (req, res) => {
    const collection = adminCollections[req.params.resource];
    if (!collection) return res.status(404).json({ error: 'Unknown content type' });
    const data = {};
    collection.fields.forEach((field) => {
        if (req.body?.[field] !== undefined) {
            data[field] = field === 'questions' ? req.body[field] : cleanText(req.body[field], field === 'content' ? 20000 : 500);
        }
    });
    if (collection.model === Quiz) {
        if (!String(data.title || '').trim() || !Array.isArray(data.questions)) {
            return res.status(400).json({ error: 'Quiz title and questions are required' });
        }
    } else if (collection.model === BlogPost) {
        if (!String(data.title || '').trim() || !String(data.content || '').trim()) {
            return res.status(400).json({ error: 'Blog title and content are required' });
        }
    } else if (!String(data.title || '').trim() || !String(data.filename || '').trim()) {
        return res.status(400).json({ error: 'Title and uploaded file are required' });
    }
    if (collection.model === BlogPost) data.postTime = Date.now();
    data.published = req.body?.published !== false;
    res.status(201).json(await collection.model.create(data));
});

app.patch('/api/admin/:resource/:id', requireAdmin, async (req, res) => {
    const collection = adminCollections[req.params.resource];
    if (!collection || !mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(404).json({ error: 'Content not found' });
    }
    const updates = {};
    collection.fields.forEach((field) => {
        if (req.body?.[field] !== undefined) {
            updates[field] = field === 'questions' ? req.body[field] : cleanText(req.body[field], field === 'content' ? 20000 : 500);
        }
    });
    if (typeof req.body?.published === 'boolean') updates.published = req.body.published;
    const record = await collection.model.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
    if (!record) return res.status(404).json({ error: 'Content not found' });
    res.json(record);
});

app.delete('/api/admin/:resource/:id', requireAdmin, async (req, res) => {
    const collection = adminCollections[req.params.resource];
    if (!collection || !mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(404).json({ error: 'Content not found' });
    }
    const record = await collection.model.findByIdAndDelete(req.params.id);
    if (!record) return res.status(404).json({ error: 'Content not found' });
    if (collection.directory && record.filename) {
        const filePath = path.join(collection.directory, path.basename(record.filename));
        if (filePath.startsWith(collection.directory) && fs.existsSync(filePath)) fs.unlinkSync(filePath);
    }
    res.json({ message: 'Content deleted' });
});

app.post('/api/admin/blogs', requireAdmin, async (req, res) => {
    const title = String(req.body?.title || '').trim();
    const content = String(req.body?.content || '').trim();
    if (!title || !content || title.length > 160 || content.length > 20000) {
        return res.status(400).json({ error: 'A valid title and content are required' });
    }
    res.status(201).json(await BlogPost.create({ title, content, imageFilename: '', postTime: Date.now() }));
});

app.post('/api/admin/quizzes', requireAdmin, async (req, res) => {
    const title = String(req.body?.title || '').trim();
    if (!title || title.length > 160 || !Array.isArray(req.body?.questions)) {
        return res.status(400).json({ error: 'Quiz title and questions are required' });
    }
    res.status(201).json(await Quiz.create({ title, questions: req.body.questions }));
});

// Upload endpoint for blog files
app.post('/upload/blog', requireAdmin, uploadBlog.single('file'), validateUploadedFile, (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Blog file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for assignment files
app.post('/upload/assignment', requireAdmin, uploadAssignment.single('file'), validateUploadedFile, (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Assignment file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for book files
app.post('/upload/book', requireAdmin, uploadBook.single('file'), validateUploadedFile, (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }
    res.json({ message: 'Book file uploaded successfully', filename: req.file.filename });
});

// Upload endpoint for entry-test files
app.post('/upload/material', requireAdmin, (req, res) => {
    uploadEntryTest.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: 'Invalid upload request' });
        } else if (err) {
            return res.status(400).json({ error: 'Invalid upload request' });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        validateUploadedFile(req, res, () => {
            res.json({ message: 'Entry test material uploaded successfully', filename: req.file.filename });
        });
    });
});

// New API endpoint to list all relevant files
app.get('/api/all-files', requireAdmin, (req, res) => {
    const baseDir = __dirname;
    const foldersToScan = [
        'B-A-A-R',
        'Books & Notes',
        'Past Papers',
        'Quick mcqs',
        path.join('storage', 'blog'),
        path.join('storage', 'assignments'),
        path.join('storage', 'books'),
        path.join('storage', 'entry-test'),
        path.join('storage', 'past-papers')
    ];

    const allFiles = [];

    foldersToScan.forEach(folder => {
        const folderPath = path.join(baseDir, folder);
        if (fs.existsSync(folderPath)) {
            const files = fs.readdirSync(folderPath);
            files.forEach(file => {
                const filePath = path.join(folderPath, file);
                const stat = fs.statSync(filePath);
                if (stat.isFile()) {
                    // For main folders, only include .html files
                    if (
                        folder === 'B-A-A-R' ||
                        folder === 'Books & Notes' ||
                        folder === 'Past Papers' ||
                        folder === 'Quick mcqs'
                    ) {
                        if (path.extname(file).toLowerCase() === '.html') {
                            allFiles.push({
                                name: file,
                                path: path.join(folder, file).replace(/\\/g, '/')
                            });
                        }
                    } else {
                        // For blog-uploads and assignment-uploads, include all files
                        allFiles.push({
                            name: file,
                            path: path.join(folder, file).replace(/\\/g, '/')
                        });
                    }
                }
            });
        }
    });

    res.json(allFiles);
});

// POST /submit-report endpoint to save report data to MongoDB
app.post('/submit-report', async (req, res) => {
    const reportData = req.body;
    console.log('Received report:', reportData);

    try {
        const report = new Report(reportData);
        await report.save();

        res.json({ message: 'Report received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving report to database:', err);
        res.status(500).json({ error: 'Failed to save report to database' });
    }
});

// File paths for storing posts
const blogPostsFile = path.join(__dirname, 'B-A-A-R', 'blog-posts.json');
const assignmentPostsFile = path.join(__dirname, 'B-A-A-R', 'assignment-posts.json');

// POST /submit-blog-post endpoint to save blog post data to MongoDB
app.post('/submit-blog-post', requireAdmin, async (req, res) => {
    const blogPostData = req.body;
    console.log('Received blog post:', {
        ...blogPostData,
        password: blogPostData?.password ? '***' : undefined,
    });

    const title = String(blogPostData?.title || '').trim();
    const content = String(blogPostData?.content || '').trim();
    if (!title || !content || title.length > 160 || content.length > 20000) {
        return res.status(400).json({ error: 'A valid title and content are required' });
    }
    const safeBlogPostData = { title, content, imageFilename: '', postTime: Date.now() };

    try {
        const blogPost = new BlogPost(safeBlogPostData);
        await blogPost.save();

        // Keep saving to JSON file as fallback
        const blogPosts = fs.existsSync(blogPostsFile) ? JSON.parse(fs.readFileSync(blogPostsFile, 'utf-8')) : [];
        blogPosts.unshift(safeBlogPostData);
        fs.writeFileSync(blogPostsFile, JSON.stringify(blogPosts, null, 2), 'utf-8');

        res.json({ message: 'Blog post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving blog post to database:', err);
        res.status(500).json({ error: 'Failed to save blog post to database' });
    }
});


// GET /api/blog-posts endpoint to fetch all blog posts from MongoDB
app.get('/api/blog-posts', async (req, res) => {
    try {
        const blogPosts = await BlogPost.find({ $or: [{ published: true }, { published: { $exists: false } }] });
        res.json(blogPosts.map(publicRecord));
    } catch (err) {
        console.error('Error fetching blog posts:', err);
        res.status(500).json({ error: 'Failed to fetch blog posts' });
    }
});

const { Types } = require('mongoose');

// POST /like-blog-post/:id endpoint to increment likes for a blog post
app.post('/like-blog-post/:id', async (req, res) => {
    try {
        const postId = req.params.id;
        if (!Types.ObjectId.isValid(postId)) {
            return res.status(400).json({ error: 'Invalid blog post ID' });
        }
        const updatedPost = await BlogPost.findByIdAndUpdate(
            postId,
            { $inc: { likes: 1 } },
            { new: true }
        );
        if (!updatedPost) {
            return res.status(404).json({ error: 'Blog post not found' });
        }
        res.json({ message: 'Like added successfully', likes: updatedPost.likes });
    } catch (err) {
        console.error('Error liking blog post:', err);
        res.status(500).json({ error: 'Failed to like blog post' });
    }
});

// POST /submit-assignment-post endpoint to save assignment post data to MongoDB
app.post('/submit-assignment-post', requireAdmin, async (req, res) => {
    const assignmentPostData = req.body;
    console.log('Received assignment post:', assignmentPostData);

    try {
        const assignmentPost = new AssignmentPost(assignmentPostData);
        await assignmentPost.save();

        // Keep saving to JSON file as fallback
        const assignmentPosts = fs.existsSync(assignmentPostsFile) ? JSON.parse(fs.readFileSync(assignmentPostsFile, 'utf-8')) : [];
        assignmentPosts.unshift(assignmentPostData);
        fs.writeFileSync(assignmentPostsFile, JSON.stringify(assignmentPosts, null, 2), 'utf-8');

        res.json({ message: 'Assignment post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving assignment post to database:', err);
        res.status(500).json({ error: 'Failed to save assignment post to database' });
    }
});

// GET /api/assignment-posts endpoint to fetch all assignment posts from MongoDB
app.get('/api/assignment-posts', async (req, res) => {
    try {
        const assignmentPosts = await AssignmentPost.find({ $or: [{ published: true }, { published: { $exists: false } }] });
        res.json(assignmentPosts.map(publicRecord));
    } catch (err) {
        console.error('Error fetching assignment posts:', err);
        res.status(500).json({ error: 'Failed to fetch assignment posts' });
    }
});

// POST /submit-book-post endpoint to save book post data to MongoDB
app.post('/submit-book-post', requireAdmin, async (req, res) => {
    const bookPostData = req.body;
    console.log('Received book post:', bookPostData);

    try {
        const bookPost = new BookPost(bookPostData);
        await bookPost.save();

        res.json({ message: 'Book post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving book post to database:', err);
        res.status(500).json({ error: 'Failed to save book post to database' });
    }
});

// POST /submit-material-post endpoint to save entry-test post data to MongoDB
app.post('/submit-material-post', requireAdmin, async (req, res) => {
    const materialPostData = req.body;
    console.log('Received material post:', materialPostData);

    try {
        const entryTestPost = new EntryTestPost(materialPostData);
        await entryTestPost.save();

        res.json({ message: 'Material post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving material post to database:', err);
        res.status(500).json({ error: 'Failed to save material post to database' });
    }
});

// GET /api/book-posts endpoint to fetch all book posts from DB
app.get('/api/book-posts', async (req, res) => {
    try {
        const bookPosts = await BookPost.find({ $or: [{ published: true }, { published: { $exists: false } }] });
        res.json(bookPosts.map(publicRecord));
    } catch (err) {
        console.error('Error fetching book posts:', err);
        res.status(500).json({ error: 'Failed to fetch book posts' });
    }
});

// GET /api/entry-test-posts endpoint to fetch all entry test posts from DB
app.get('/api/entry-test-posts', async (req, res) => {
    try {
        const entryTestPosts = await EntryTestPost.find({ $or: [{ published: true }, { published: { $exists: false } }] });
        res.json(entryTestPosts.map(publicRecord));
    } catch (err) {
        console.error('Error fetching entry test posts:', err);
        res.status(500).json({ error: 'Failed to fetch entry test posts' });
    }
});

app.get('/api/quizzes', async (req, res) => {
    try {
        res.json(await Quiz.find({ $or: [{ published: true }, { published: { $exists: false } }] }).select('title questions createdAt').sort({ createdAt: -1 }));
    } catch (err) {
        console.error('Error fetching quizzes:', err);
        res.status(500).json({ error: 'Failed to fetch quizzes' });
    }
});

// Download endpoint for book files
app.get('/download/book/:filename', async (req, res, next) => {
    try {
        if (!safeFilename(req.params.filename)) return res.status(400).json({ error: 'Invalid filename' });
        if (!await publishedFile(BookPost, req.params.filename)) return res.status(404).json({ error: 'File not found' });
        sendDownload(booksUploadDir, req.params.filename, res);
    } catch (error) { next(error); }
});

app.get('/download/assignment/:filename', async (req, res, next) => {
    try {
        if (!safeFilename(req.params.filename)) return res.status(400).json({ error: 'Invalid filename' });
        if (!await publishedFile(AssignmentPost, req.params.filename)) return res.status(404).json({ error: 'File not found' });
        sendDownload(assignmentUploadDir, req.params.filename, res);
    } catch (error) { next(error); }
});

app.get('/media/blog/:filename', async (req, res, next) => {
    try {
        if (!safeFilename(req.params.filename)) return res.status(400).end();
        if (!await publishedFile(BlogPost, req.params.filename)) return res.status(404).end();
        sendMedia(blogUploadDir, req.params.filename, res);
    } catch (error) {
        next(error);
    }
});

// Download endpoint for entry-test files
app.get('/download/entry-test/:filename', async (req, res, next) => {
    try {
        if (!safeFilename(req.params.filename)) return res.status(400).json({ error: 'Invalid filename' });
        if (!await publishedFile(EntryTestPost, req.params.filename)) return res.status(404).json({ error: 'File not found' });
        sendDownload(entryTestUploadDir, req.params.filename, res);
    } catch (error) { next(error); }
});

// Upload endpoint for past papers files
app.post('/upload/past-paper', requireAdmin, (req, res) => {
    uploadPastPapers.single('file')(req, res, function (err) {
        if (err instanceof multer.MulterError) {
            return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: 'Invalid upload request' });
        } else if (err) {
            return res.status(400).json({ error: 'Invalid upload request' });
        }
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        validateUploadedFile(req, res, () => {
            res.json({ message: 'Past paper uploaded successfully', filename: req.file.filename });
        });
    });
});

// POST /submit-past-paper-post endpoint to save past paper post data to MongoDB
app.post('/submit-past-paper-post', requireAdmin, async (req, res) => {
    const pastPaperPostData = req.body;
    console.log('Received past paper post:', pastPaperPostData);

    try {
        const pastPaperPost = new PastPaperPost(pastPaperPostData);
        await pastPaperPost.save();

        res.json({ message: 'Past paper post received and saved to database successfully' });
    } catch (err) {
        console.error('Error saving past paper post to database:', err);
        res.status(500).json({ error: 'Failed to save past paper post to database' });
    }
});

// GET /api/past-paper-posts endpoint to fetch past paper posts from DB, optionally filtered by class
app.get('/api/past-paper-posts', async (req, res) => {
    try {
        const { class: classFilter } = req.query;
        const query = classFilter
            ? { class: classFilter, $or: [{ published: true }, { published: { $exists: false } }] }
            : { $or: [{ published: true }, { published: { $exists: false } }] };
        const pastPaperPosts = await PastPaperPost.find(query);
        res.json(pastPaperPosts.map(publicRecord));
    } catch (err) {
        console.error('Error fetching past paper posts:', err);
        res.status(500).json({ error: 'Failed to fetch past paper posts' });
    }
});

// Download endpoint for past paper files
app.get('/download/past-paper/:filename', async (req, res, next) => {
    try {
        if (!safeFilename(req.params.filename)) return res.status(400).json({ error: 'Invalid filename' });
        if (!await publishedFile(PastPaperPost, req.params.filename)) return res.status(404).json({ error: 'File not found' });
        sendDownload(pastPapersUploadDir, req.params.filename, res);
    } catch (error) { next(error); }
});

app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err instanceof multer.MulterError) {
        const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
        return res.status(status).json({ error: 'Invalid upload request' });
    }
    if (err.type === 'entity.too.large' || err.status === 413) {
        return res.status(413).json({ error: 'Request body is too large' });
    }
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({ error: 'Invalid JSON payload' });
    }
    console.error('Unhandled request error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

function startServer() {
    mongoose.connect(mongoUri, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    }).then(() => {
        console.log('Connected to MongoDB');
    }).catch((err) => {
        console.error('Failed to connect to MongoDB', err);
    });

    return app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
}

if (require.main === module) {
    startServer();
}

module.exports = { app, startServer };
