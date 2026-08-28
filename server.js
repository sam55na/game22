require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_this_in_production';

// ===== إعداد قاعدة البيانات =====
function parseDatabaseUrl(url) {
    if (!url) return null;
    try {
        const parsed = new URL(url);
        const sslMode = parsed.searchParams.get('ssl') || parsed.searchParams.get('sslmode') || 'prefer';
        let sslConfig = false;
        if (sslMode === 'require' || sslMode === 'true' || sslMode === 'verify-full') {
            sslConfig = { rejectUnauthorized: false };
        } else if (sslMode === 'prefer') {
            sslConfig = { rejectUnauthorized: false };
        }
        return {
            host: parsed.hostname,
            port: parseInt(parsed.port) || 5432,
            user: parsed.username,
            password: parsed.password,
            database: parsed.pathname.slice(1),
            ssl: sslConfig,
            connectionTimeoutMillis: 10000,
            idleTimeoutMillis: 30000,
            max: 20
        };
    } catch (error) {
        console.error('❌ خطأ في تحليل رابط قاعدة البيانات:', error.message);
        return null;
    }
}

function createPool() {
    const dbUrl = process.env.DATABASE_URL || process.env.DB_URL;
    let config = {};
    if (dbUrl) {
        console.log('🔗 استخدام رابط قاعدة البيانات من البيئة');
        const parsed = parseDatabaseUrl(dbUrl);
        if (parsed) config = parsed;
        else {
            console.error('❌ رابط قاعدة البيانات غير صالح، استخدام الإعدادات اليدوية');
            config = getManualConfig();
        }
    } else {
        console.log('📝 استخدام إعدادات قاعدة البيانات اليدوية');
        config = getManualConfig();
    }
    return new Pool(config);
}

function getManualConfig() {
    const sslMode = process.env.DB_SSL_MODE || 'prefer';
    let sslConfig = false;
    if (sslMode === 'require' || sslMode === 'true') sslConfig = { rejectUnauthorized: false };
    else if (sslMode === 'prefer') sslConfig = { rejectUnauthorized: false };
    return {
        host: process.env.DB_HOST || 'localhost',
        port: parseInt(process.env.DB_PORT) || 5432,
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'postgres',
        database: process.env.DB_NAME || 'user_system',
        ssl: sslConfig,
        connectionTimeoutMillis: 10000,
        idleTimeoutMillis: 30000,
        max: 20
    };
}

const pool = createPool();

// ===== دوال قاعدة البيانات =====
const db = {
    findUser: async (username) => {
        try {
            const result = await pool.query('SELECT * FROM users WHERE username = $1', [username.toLowerCase().trim()]);
            return result.rows[0] || null;
        } catch (error) {
            console.error('خطأ في البحث عن المستخدم:', error.message);
            throw error;
        }
    },
    createUser: async (username, hashedPassword) => {
        try {
            const result = await pool.query(
                `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, balance, created_at`,
                [username.toLowerCase().trim(), hashedPassword]
            );
            return result.rows[0];
        } catch (error) {
            console.error('خطأ في إنشاء المستخدم:', error.message);
            throw error;
        }
    },
    updateLastLogin: async (username) => {
        try {
            await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = $1', [username.toLowerCase().trim()]);
        } catch (error) {
            console.error('خطأ في تحديث آخر تسجيل دخول:', error.message);
            throw error;
        }
    },
    getUserData: async (username) => {
        try {
            const result = await pool.query('SELECT username, balance FROM users WHERE username = $1', [username.toLowerCase().trim()]);
            return result.rows[0] || null;
        } catch (error) {
            console.error('خطأ في جلب بيانات المستخدم:', error.message);
            throw error;
        }
    }
};

// ===== تهيئة قاعدة البيانات =====
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        console.log('🔄 جاري التحقق من قاعدة البيانات...');
        await client.query('SELECT NOW()');
        const tableCheck = await client.query(`
            SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users');
        `);
        if (!tableCheck.rows[0].exists) {
            console.log('📦 تهيئة قاعدة البيانات للمرة الأولى...');
            await client.query(`
                CREATE TABLE users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    balance DECIMAL(15,2) DEFAULT 1000.00,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                );
                CREATE INDEX idx_username ON users(username);
            `);
            console.log('✅ تم إنشاء الجداول بنجاح');
            if (process.env.NODE_ENV !== 'production') {
                const hashedPassword = await bcrypt.hash('admin123', 10);
                await client.query(
                    `INSERT INTO users (username, password_hash, balance) VALUES ($1, $2, $3)`,
                    ['admin', hashedPassword, 9999.99]
                );
                console.log('👤 تم إنشاء مستخدم تجريبي: admin / admin123');
            }
        } else {
            console.log('✅ قاعدة البيانات موجودة بالفعل');
        }
        return true;
    } catch (error) {
        console.error('❌ خطأ في تهيئة قاعدة البيانات:', error.message);
        return false;
    } finally {
        client.release();
    }
}

// ===== إعداد Express =====
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ===== API Routes =====

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// التحقق من صحة الخادم
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// إنشاء حساب
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        if (username.length < 3) {
            return res.status(400).json({ error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
        }
        
        const existingUser = await db.findUser(username);
        if (existingUser) {
            return res.status(409).json({ error: 'اسم المستخدم موجود مسبقاً' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = await db.createUser(username, hashedPassword);
        
        res.status(201).json({ 
            message: 'تم إنشاء الحساب بنجاح',
            user: { username: newUser.username, balance: parseFloat(newUser.balance) }
        });
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم، يرجى المحاولة مرة أخرى' });
    }
});

// تسجيل الدخول
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

        await db.updateLastLogin(username);

        const token = jwt.sign(
            { username: user.username, balance: parseFloat(user.balance), id: user.id },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: { username: user.username, balance: parseFloat(user.balance) }
        });
    } catch (error) {
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم، يرجى المحاولة مرة أخرى' });
    }
});

// التحقق من التوكن
app.post('/api/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.getUserData(decoded.username);
        
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        res.json({ username: user.username, balance: parseFloat(user.balance) });
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'توكن غير صالح' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'انتهت صلاحية التوكن' });
        }
        console.error('❌ خطأ في التحقق:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// معالجة الأخطاء
app.use((req, res) => {
    res.status(404).json({ error: 'المسار غير موجود' });
});

app.use((err, req, res, next) => {
    console.error('❌ خطأ غير متوقع:', err);
    res.status(500).json({ error: 'حدث خطأ داخلي في الخادم' });
});

// ===== تشغيل الخادم =====
async function startServer() {
    try {
        await initializeDatabase();
        app.listen(PORT, () => {
            console.log(`\n🚀 الخادم يعمل على http://localhost:${PORT}`);
            console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}\n`);
        });
    } catch (error) {
        console.error('❌ فشل تشغيل الخادم:', error.message);
        process.exit(1);
    }
}

startServer();
