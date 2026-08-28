require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { Pool } = require('pg');

// ===== إعدادات =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123456';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const isProduction = process.env.NODE_ENV === 'production';

// ===== قاعدة البيانات =====
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProduction ? { rejectUnauthorized: false } : false,
    max: 50,
    min: 5,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

// ===== Middleware =====
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"]
        }
    }
}));
app.use(compression());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ===== حماية من هجمات القوة العمياء =====
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'تم تجاوز حد الطلبات، حاول مرة أخرى لاحقاً' }
});
app.use('/api/', limiter);

// =============================================
// ===== تهيئة قاعدة البيانات =====
// =============================================
async function initDatabase() {
    const client = await pool.connect();
    try {
        console.log('🔄 جاري تهيئة قاعدة البيانات...');

        // مسح الجداول القديمة
        console.log('🗑️ جاري مسح الجداول القديمة...');
        await client.query('DROP TABLE IF EXISTS sessions CASCADE;');
        await client.query('DROP TABLE IF EXISTS activity_logs CASCADE;');
        await client.query('DROP TABLE IF EXISTS site_settings CASCADE;');
        await client.query('DROP TABLE IF EXISTS users CASCADE;');
        console.log('✅ تم مسح الجداول القديمة');

        // إنشاء الجداول الجديدة
        console.log('📦 جاري إنشاء الجداول الجديدة...');

        await client.query(`
            CREATE TABLE users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP,
                last_ip VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX idx_username ON users(username);');
        await client.query('CREATE INDEX idx_role ON users(role);');

        await client.query(`
            CREATE TABLE activity_logs (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
                username VARCHAR(50),
                action VARCHAR(50) NOT NULL,
                details TEXT,
                ip VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX idx_logs_user ON activity_logs(user_id);');
        await client.query('CREATE INDEX idx_logs_created ON activity_logs(created_at DESC);');

        await client.query(`
            CREATE TABLE site_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
            CREATE TABLE sessions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(500) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX idx_sessions_token ON sessions(token);');
        await client.query('CREATE INDEX idx_sessions_expires ON sessions(expires_at);');

        console.log('✅ تم إنشاء الجداول الجديدة');

        // إنشاء حساب الأدمن
        const adminUsername = 'noor2613857noor';
        const adminPassword = 'admin123';
        const hash = await bcrypt.hash(adminPassword, 10);
        await client.query(
            `INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)`,
            [adminUsername, hash, 'admin']
        );
        console.log(`👑 تم إنشاء حساب الأدمن: ${adminUsername} / ${adminPassword}`);

        // ===== الإعدادات الافتراضية (الألوان) =====
        const defaultSettings = [
            ['site_name', 'Game Wars'],
            ['primary_color', '#6366f1'],
            ['secondary_color', '#0891b2'],
            ['accent_color', '#8b5cf6'],
            ['bg_color', '#0a0a1a'],
            ['text_color', '#ffffff'],
            ['card_bg', 'rgba(255,255,255,0.03)'],
            ['border_color', 'rgba(255,255,255,0.05)'],
            ['glow_color', 'rgba(99,102,241,0.15)'],
            ['maintenance_mode', 'false'],
            ['registration_enabled', 'true']
        ];

        for (const [key, value] of defaultSettings) {
            await client.query(
                `INSERT INTO site_settings (key, value) VALUES ($1, $2)`,
                [key, value]
            );
        }
        console.log('✅ تم إضافة الإعدادات الافتراضية');
        console.log('✅ تهيئة قاعدة البيانات مكتملة');

    } catch (error) {
        console.error('❌ خطأ في تهيئة قاعدة البيانات:', error.message);
        throw error;
    } finally {
        client.release();
    }
}

// ===== دوال قاعدة البيانات =====
const db = {
    findUser: async (username) => {
        const res = await pool.query(
            'SELECT id, username, password_hash, role, is_active FROM users WHERE username = $1',
            [username.toLowerCase().trim()]
        );
        return res.rows[0] || null;
    },
    
    createUser: async (username, hash, ip = null, userAgent = null) => {
        const res = await pool.query(
            `INSERT INTO users (username, password_hash, last_ip) 
             VALUES ($1, $2, $3) RETURNING id, username, role`,
            [username.toLowerCase().trim(), hash, ip]
        );
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, ip, user_agent) 
             VALUES ($1, $2, $3, $4, $5)`,
            [res.rows[0].id, username, 'register', ip, userAgent]
        );
        return res.rows[0];
    },
    
    login: async (username, ip = null, userAgent = null) => {
        const res = await pool.query(
            `UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = $1 
             WHERE username = $2 RETURNING id, username, role`,
            [ip, username.toLowerCase().trim()]
        );
        if (res.rows.length > 0) {
            await pool.query(
                `INSERT INTO activity_logs (user_id, username, action, ip, user_agent) 
                 VALUES ($1, $2, $3, $4, $5)`,
                [res.rows[0].id, username, 'login', ip, userAgent]
            );
        }
        return res.rows[0] || null;
    },
    
    saveSession: async (userId, token, expiresAt) => {
        await pool.query(
            `INSERT INTO sessions (user_id, token, expires_at) VALUES ($1, $2, $3)`,
            [userId, token, expiresAt]
        );
    },
    
    getSettings: async () => {
        const res = await pool.query('SELECT key, value FROM site_settings');
        const settings = {};
        res.rows.forEach(row => { settings[row.key] = row.value; });
        return settings;
    },
    
    updateSetting: async (key, value) => {
        await pool.query(
            `UPDATE site_settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2`,
            [value, key]
        );
    },
    
    getUsers: async () => {
        const res = await pool.query(
            'SELECT id, username, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC'
        );
        return res.rows;
    },
    
    toggleUser: async (username, active) => {
        await pool.query(
            `UPDATE users SET is_active = $1, updated_at = CURRENT_TIMESTAMP WHERE username = $2`,
            [active, username.toLowerCase().trim()]
        );
    },
    
    deleteUser: async (username) => {
        await pool.query('DELETE FROM users WHERE username = $1', [username.toLowerCase().trim()]);
    },
    
    getLogs: async (limit = 100) => {
        const res = await pool.query(
            `SELECT username, action, details, ip, created_at 
             FROM activity_logs ORDER BY created_at DESC LIMIT $1`,
            [limit]
        );
        return res.rows;
    },
    
    getStats: async () => {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
        const todayRegs = await pool.query(
            "SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE"
        );
        const todayLogins = await pool.query(
            "SELECT COUNT(*) FROM activity_logs WHERE action = 'login' AND DATE(created_at) = CURRENT_DATE"
        );
        return {
            totalUsers: parseInt(totalUsers.rows[0].count),
            todayRegistrations: parseInt(todayRegs.rows[0].count),
            todayLogins: parseInt(todayLogins.rows[0].count)
        };
    }
};

// =============================================
// ===== API Routes =====
// =============================================

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== جلب إعدادات الموقع (بما فيها الألوان) =====
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        if (username.length < 3) {
            return res.status(400).json({ error: 'اسم المستخدم 3 أحرف على الأقل' });
        }
        if (password.length < 8) {
            return res.status(400).json({ error: 'كلمة المرور 8 أحرف على الأقل' });
        }

        const existing = await db.findUser(username);
        if (existing) {
            return res.status(409).json({ error: 'اسم المستخدم موجود مسبقاً' });
        }

        const hash = await bcrypt.hash(password, 10);
        const user = await db.createUser(username, hash, ip, userAgent);

        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            user: { username: user.username }
        });
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const userAgent = req.headers['user-agent'];

        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }

        const user = await db.findUser(username);
        if (!user) {
            return res.status(401).json({ error: 'بيانات غير صحيحة' });
        }
        if (!user.is_active) {
            return res.status(403).json({ error: 'الحساب معطل' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'بيانات غير صحيحة' });
        }

        const updatedUser = await db.login(username, ip, userAgent);
        if (!updatedUser) {
            return res.status(500).json({ error: 'حدث خطأ' });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await db.saveSession(user.id, token, expiresAt);

        // جلب الإعدادات مع التوكن
        const settings = await db.getSettings();

        res.json({
            token,
            user: { id: user.id, username: user.username, role: user.role },
            settings: settings
        });
    } catch (error) {
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

app.post('/api/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'غير مصرح' });

        const decoded = jwt.verify(token, JWT_SECRET);
        const sessionCheck = await pool.query(
            'SELECT * FROM sessions WHERE token = $1 AND expires_at > NOW()',
            [token]
        );
        if (sessionCheck.rows.length === 0) {
            return res.status(401).json({ error: 'جلسة غير صالحة' });
        }

        const settings = await db.getSettings();

        res.json({
            id: decoded.id,
            username: decoded.username,
            role: decoded.role,
            settings: settings
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'انتهت صلاحية التوكن' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'توكن غير صالح' });
        }
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// =============================================
// ===== ADMIN API =====
// =============================================

const verifyAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'غير مصرح' });

        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: 'صلاحيات أدمن مطلوبة' });
        }

        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'توكن غير صالح' });
    }
};

app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const stats = await db.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await db.getUsers();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.post('/api/admin/toggle-user', verifyAdmin, async (req, res) => {
    try {
        const { username, active } = req.body;
        await db.toggleUser(username, active);
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'user_toggle',
             `${active ? 'تفعيل' : 'تعطيل'} المستخدم ${username}`]
        );
        res.json({ message: `تم ${active ? 'تفعيل' : 'تعطيل'} المستخدم` });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.delete('/api/admin/delete-user', verifyAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        if (username === 'noor2613857noor') {
            return res.status(403).json({ error: 'لا يمكن حذف الأدمن الرئيسي' });
        }
        await db.deleteUser(username);
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'delete_user', `حذف المستخدم ${username}`]
        );
        res.json({ message: 'تم حذف المستخدم' });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.get('/api/admin/logs', verifyAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const logs = await db.getLogs(limit);
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.get('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const { key, value } = req.body;
        await db.updateSetting(key, value);
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'settings_update', `تحديث: ${key} = ${value}`]
        );
        // إرجاع الإعدادات المحدثة
        const settings = await db.getSettings();
        res.json({ message: 'تم تحديث الإعداد', settings: settings });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

// =============================================
// ===== الصفحات =====
// =============================================

app.use(express.static('public'));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================
// ===== تشغيل الخادم =====
// =============================================

async function startServer() {
    try {
        await initDatabase();
        app.listen(PORT, () => {
            console.log(`\n🚀 Game Wars يعمل على http://localhost:${PORT}`);
            console.log(`👑 الأدمن: noor2613857noor / admin123`);
            console.log(`📊 لوحة التحكم: http://localhost:${PORT}/admin\n`);
        });
    } catch (error) {
        console.error('❌ فشل تشغيل الخادم:', error.message);
        process.exit(1);
    }
}

process.on('SIGTERM', async () => { await pool.end(); process.exit(0); });
process.on('SIGINT', async () => { await pool.end(); process.exit(0); });

startServer();
