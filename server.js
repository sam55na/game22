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
            console.error('❌ خطأ في رابط قاعدة البيانات:', e.message);
        }
    }
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
    } finally {
        client.release();
    }
}

// ===== دوال المساعدة =====
const db = {
    findUser: async (username) => {
        const res = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
        return res.rows[0] || null;
    },
    createUser: async (username, passwordHash) => {
        const res = await pool.query(
            'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, balance',
            [username.toLowerCase().trim(), passwordHash]
        );
        return res.rows[0];
    },
    updateLogin: async (username) => {
        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = $1', [username.toLowerCase().trim()]);
    },
    getUser: async (username) => {
        const res = await pool.query('SELECT username, balance FROM users WHERE username = $1', [username.toLowerCase().trim()]);
        return res.rows[0] || null;
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

// ===== API: إنشاء حساب =====
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // التحقق
        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        if (username.length < 3) {
            return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
        }
        
        // التحقق من التكرار
        const existing = await db.findUser(username);
        if (existing) {
            return res.status(409).json({ error: 'اسم المستخدم موجود مسبقاً' });
        }
        
        // تشفير كلمة المرور
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // إنشاء المستخدم
        const newUser = await db.createUser(username, hashedPassword);
        
        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            user: {
                username: newUser.username,
                balance: parseFloat(newUser.balance)
            }
        });
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== API: تسجيل الدخول =====
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        
        const user = await db.findUser(username);
        if (!user) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
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
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
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
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'توكن غير صالح' });
        }
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== معالجة المسارات غير الموجودة =====
app.use((req, res) => {
    res.status(404).json({ error: 'المسار غير موجود' });
});

// ===== تشغيل الخادم =====
async function start() {
    await initDB();
    app.listen(PORT, () => {
        console.log(`\n🚀 الخادم يعمل على http://localhost:${PORT}`);
        console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}\n`);
    });
}

start();
