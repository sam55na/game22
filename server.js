require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123456';

// ===== إعداد قاعدة البيانات =====
function createPool() {
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl) {
        try {
            const parsed = new URL(dbUrl);
            console.log('🔗 استخدام رابط قاعدة البيانات من البيئة');
            return new Pool({
                host: parsed.hostname,
                port: parseInt(parsed.port) || 5432,
                user: parsed.username,
                password: parsed.password,
                database: parsed.pathname.slice(1),
                ssl: { rejectUnauthorized: false },
                connectionTimeoutMillis: 10000,
                max: 20
            });
        } catch (e) {
            console.error('❌ خطأ في تحليل رابط قاعدة البيانات:', e.message);
            console.error('📝 الرابط المستخدم:', dbUrl);
        }
    }
    console.log('📝 استخدام إعدادات قاعدة البيانات اليدوية');
    return new Pool({
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'postgres',
        database: process.env.DB_NAME || 'user_system',
        ssl: process.env.DB_SSL_MODE === 'require' ? { rejectUnauthorized: false } : false,
        connectionTimeoutMillis: 10000,
        max: 20
    });
}

const pool = createPool();

// ===== تهيئة قاعدة البيانات =====
async function initDB() {
    const client = await pool.connect();
    try {
        console.log('🔄 جاري تهيئة قاعدة البيانات...');
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                balance DECIMAL(15,2) DEFAULT 1000.00,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_username ON users(username);
        `);
        console.log('✅ قاعدة البيانات جاهزة');
        
        // مستخدم تجريبي
        const check = await client.query('SELECT * FROM users WHERE username = $1', ['admin']);
        if (check.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query('INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, $3)', ['admin', hash, 9999.99]);
            console.log('👤 مستخدم تجريبي: admin / admin123');
        }
    } catch (e) {
        console.error('❌ خطأ في تهيئة قاعدة البيانات:', e.message);
        console.error('📝 تفاصيل الخطأ:', e.stack);
    } finally {
        client.release();
    }
}

// ===== دوال المساعدة =====
const db = {
    findUser: async (username) => {
        try {
            const res = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
            return res.rows[0] || null;
        } catch (e) {
            console.error('❌ خطأ في البحث عن المستخدم:', e.message);
            throw e;
        }
    },
    createUser: async (username, passwordHash) => {
        try {
            const res = await pool.query(
                'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, balance',
                [username.toLowerCase().trim(), passwordHash]
            );
            return res.rows[0];
        } catch (e) {
            console.error('❌ خطأ في إنشاء المستخدم:', e.message);
            throw e;
        }
    },
    updateLogin: async (username) => {
        try {
            await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = $1', [username.toLowerCase().trim()]);
        } catch (e) {
            console.error('❌ خطأ في تحديث آخر تسجيل دخول:', e.message);
            throw e;
        }
    },
    getUser: async (username) => {
        try {
            const res = await pool.query('SELECT username, balance FROM users WHERE username = $1', [username.toLowerCase().trim()]);
            return res.rows[0] || null;
        } catch (e) {
            console.error('❌ خطأ في جلب بيانات المستخدم:', e.message);
            throw e;
        }
    }
};

// ===== إعداد Express =====
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ===== الصفحة الرئيسية =====
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===== API: إنشاء حساب (مع طباعة أخطاء تفصيلية) =====
app.post('/api/register', async (req, res) => {
    console.log('\n📝 [طلب إنشاء حساب]');
    console.log('📦 البيانات المستلمة:', req.body);
    
    try {
        const { username, password } = req.body;
        
        // التحقق من صحة الإدخال
        if (!username || !password) {
            console.log('❌ فشل: حقول فارغة');
            return res.status(400).json({ 
                error: 'يرجى ملء جميع الحقول',
                details: { username: !!username, password: !!password }
            });
        }
        
        if (username.length < 3) {
            console.log(`❌ فشل: اسم المستخدم قصير جداً (${username.length} أحرف)`);
            return res.status(400).json({ 
                error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل',
                details: { usernameLength: username.length }
            });
        }
        
        if (password.length < 6) {
            console.log(`❌ فشل: كلمة المرور قصيرة جداً (${password.length} أحرف)`);
            return res.status(400).json({ 
                error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل',
                details: { passwordLength: password.length }
            });
        }
        
        // التحقق من وجود المستخدم
        console.log(`🔍 البحث عن المستخدم: ${username}`);
        const existing = await db.findUser(username);
        if (existing) {
            console.log(`❌ فشل: المستخدم ${username} موجود بالفعل`);
            return res.status(409).json({ 
                error: 'اسم المستخدم موجود مسبقاً',
                details: { username }
            });
        }
        
        // تشفير كلمة المرور
        console.log('🔐 تشفير كلمة المرور...');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // إنشاء المستخدم
        console.log(`💾 إنشاء المستخدم: ${username}`);
        const newUser = await db.createUser(username, hashedPassword);
        
        console.log(`✅ تم إنشاء المستخدم بنجاح: ${username} (ID: ${newUser.id})`);
        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            user: {
                username: newUser.username,
                balance: parseFloat(newUser.balance)
            }
        });
    } catch (error) {
        console.error('❌ خطأ غير متوقع في التسجيل:');
        console.error('📝 الرسالة:', error.message);
        console.error('📝 التفاصيل:', error.stack);
        res.status(500).json({ 
            error: 'حدث خطأ في الخادم',
            details: {
                message: error.message,
                stack: error.stack
            }
        });
    }
});

// ===== API: تسجيل الدخول =====
app.post('/api/login', async (req, res) => {
    console.log('\n📝 [طلب تسجيل دخول]');
    console.log('📦 البيانات المستلمة:', req.body);
    
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            console.log('❌ فشل: حقول فارغة');
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        
        console.log(`🔍 البحث عن المستخدم: ${username}`);
        const user = await db.findUser(username);
        if (!user) {
            console.log(`❌ فشل: المستخدم ${username} غير موجود`);
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
        console.log(`🔐 التحقق من كلمة المرور للمستخدم: ${username}`);
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            console.log(`❌ فشل: كلمة مرور غير صحيحة للمستخدم ${username}`);
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
        console.log(`✅ تسجيل دخول ناجح: ${username}`);
        await db.updateLogin(username);
        
        const token = jwt.sign(
            { username: user.username, balance: parseFloat(user.balance), id: user.id },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                username: user.username,
                balance: parseFloat(user.balance)
            }
        });
    } catch (error) {
        console.error('❌ خطأ غير متوقع في تسجيل الدخول:');
        console.error('📝 الرسالة:', error.message);
        console.error('📝 التفاصيل:', error.stack);
        res.status(500).json({ 
            error: 'حدث خطأ في الخادم',
            details: error.message
        });
    }
});

// ===== API: التحقق من التوكن =====
app.post('/api/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.getUser(decoded.username);
        
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        
        res.json({
            username: user.username,
            balance: parseFloat(user.balance)
        });
    } catch (error) {
        console.error('❌ خطأ في التحقق:', error.message);
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'توكن غير صالح' });
        }
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== معالجة المسارات غير الموجودة =====
app.use((req, res) => {
    console.log(`⚠️ مسار غير موجود: ${req.method} ${req.url}`);
    res.status(404).json({ error: 'المسار غير موجود' });
});

// ===== تشغيل الخادم =====
async function start() {
    await initDB();
    app.listen(PORT, () => {
        console.log(`\n🚀 الخادم يعمل على http://localhost:${PORT}`);
        console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}\n`);
        console.log('📝 [ملاحظة] سيتم طباعة جميع طلبات إنشاء الحساب في وحدة التحكم مع تفاصيل الأخطاء\n');
    });
}

start();
