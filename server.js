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
        database: process.env.DB_NAME || 'game_wars',
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
        
        // جدول المستخدمين
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                balance DECIMAL(15,2) DEFAULT 1000.00,
                role VARCHAR(20) DEFAULT 'user',
                is_active BOOLEAN DEFAULT true,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_ip VARCHAR(45)
            );
            CREATE INDEX IF NOT EXISTS idx_username ON users(username);
        `);

        // جدول سجل النشاطات
        await client.query(`
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                username VARCHAR(50),
                action VARCHAR(100),
                details TEXT,
                ip VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_logs_user ON activity_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_logs_created ON activity_logs(created_at DESC);
        `);

        // جدول إعدادات الموقع
        await client.query(`
            CREATE TABLE IF NOT EXISTS site_settings (
                id SERIAL PRIMARY KEY,
                key VARCHAR(50) UNIQUE NOT NULL,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log('✅ قاعدة البيانات جاهزة');

        // ===== إنشاء حساب الأدمن =====
        const adminUsername = 'noor2613857noor';
        const adminCheck = await client.query('SELECT * FROM users WHERE username = $1', [adminUsername]);
        
        if (adminCheck.rows.length === 0) {
            const hash = await bcrypt.hash('admin123', 10);
            await client.query(
                'INSERT INTO users (username, password_hash, balance, role) VALUES ($1, $2, $3, $4)',
                [adminUsername, hash, 99999.99, 'admin']
            );
            console.log('👑 تم إنشاء حساب الأدمن:', adminUsername);
            
            // تسجيل النشاط
            await client.query(
                'INSERT INTO activity_logs (username, action, details) VALUES ($1, $2, $3)',
                ['system', 'admin_created', 'تم إنشاء حساب الأدمن']
            );
        } else {
            console.log('✅ حساب الأدمن موجود بالفعل');
        }

        // ===== الإعدادات الافتراضية للموقع =====
        const defaultSettings = [
            ['site_name', 'Game Wars'],
            ['site_theme', 'dark'],
            ['primary_color', '#4f46e5'],
            ['secondary_color', '#0891b2'],
            ['accent_color', '#7c3aed'],
            ['background_color', '#0b0b1e'],
            ['text_color', '#ffffff'],
            ['header_style', 'glass'],
            ['animation_speed', '1'],
            ['admin_notifications', 'true']
        ];

        for (const [key, value] of defaultSettings) {
            const check = await client.query('SELECT * FROM site_settings WHERE key = $1', [key]);
            if (check.rows.length === 0) {
                await client.query('INSERT INTO site_settings (key, value) VALUES ($1, $2)', [key, value]);
            }
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
    createUser: async (username, passwordHash, role = 'user') => {
        const res = await pool.query(
            'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id, username, balance, role',
            [username.toLowerCase().trim(), passwordHash, role]
        );
        return res.rows[0];
    },
    updateLogin: async (username, ip) => {
        await pool.query(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = $1 WHERE username = $2',
            [ip, username.toLowerCase().trim()]
        );
    },
    getUser: async (username) => {
        const res = await pool.query('SELECT id, username, balance, role, is_active FROM users WHERE username = $1', [username.toLowerCase().trim()]);
        return res.rows[0] || null;
    },
    getAllUsers: async () => {
        const res = await pool.query('SELECT id, username, balance, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC');
        return res.rows;
    },
    logActivity: async (userId, username, action, details, ip = null) => {
        await pool.query(
            'INSERT INTO activity_logs (user_id, username, action, details, ip) VALUES ($1, $2, $3, $4, $5)',
            [userId, username, action, details, ip]
        );
    },
    getActivityLogs: async (limit = 50) => {
        const res = await pool.query(
            'SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT $1',
            [limit]
        );
        return res.rows;
    },
    getSettings: async () => {
        const res = await pool.query('SELECT key, value FROM site_settings');
        const settings = {};
        res.rows.forEach(row => { settings[row.key] = row.value; });
        return settings;
    },
    updateSetting: async (key, value) => {
        await pool.query(
            'UPDATE site_settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2',
            [value, key]
        );
    },
    updateBalance: async (username, newBalance) => {
        const res = await pool.query(
            'UPDATE users SET balance = $1 WHERE username = $2 RETURNING balance',
            [newBalance, username.toLowerCase().trim()]
        );
        return res.rows[0]?.balance || null;
    }
};

// ===== إعداد Express =====
app.use(cors());
app.use(express.json());

// ===== Middleware للتحقق من الأدمن =====
const verifyAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.getUser(decoded.username);
        
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ error: 'غير مصرح - صلاحيات أدمن مطلوبة' });
        }
        
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'توكن غير صالح' });
    }
};

// ===== API Routes =====

// === الصفحة الرئيسية ===
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// === Admin Panel ===
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// === إنشاء حساب (عام) ===
app.post('/api/register', async (req, res) => {
    const client = await pool.connect();
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
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
        const newUser = await db.createUser(username, hashedPassword, 'user');
        
        // تسجيل النشاط
        await db.logActivity(newUser.id, username, 'register', 'قام بإنشاء حساب جديد', ip);
        
        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            user: {
                username: newUser.username,
                balance: parseFloat(newUser.balance),
                role: newUser.role
            }
        });
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    } finally {
        client.release();
    }
});

// === تسجيل الدخول ===
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }
        
        const user = await db.findUser(username);
        if (!user) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
        if (!user.is_active) {
            return res.status(403).json({ error: 'الحساب معطل، يرجى التواصل مع الدعم' });
        }
        
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }
        
        await db.updateLogin(username, ip);
        
        // تسجيل النشاط
        await db.logActivity(user.id, username, 'login', 'تسجيل دخول ناجح', ip);
        
        const token = jwt.sign(
            { 
                username: user.username, 
                balance: parseFloat(user.balance), 
                id: user.id,
                role: user.role 
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            token,
            user: {
                username: user.username,
                balance: parseFloat(user.balance),
                role: user.role
            }
        });
    } catch (error) {
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// === التحقق من التوكن ===
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
            balance: parseFloat(user.balance),
            role: user.role
        });
    } catch (error) {
        res.status(401).json({ error: 'توكن غير صالح' });
    }
});

// ===== ADMIN API =====

// === جلب إعدادات الموقع ===
app.get('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

// === تحديث إعدادات الموقع ===
app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const { key, value } = req.body;
        await db.updateSetting(key, value);
        
        await db.logActivity(
            req.user.id, 
            req.user.username, 
            'settings_update', 
            `تحديث الإعداد: ${key} = ${value}`
        );
        
        res.json({ message: 'تم تحديث الإعداد بنجاح' });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في تحديث الإعدادات' });
    }
});

// === جلب جميع المستخدمين ===
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await db.getAllUsers();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في جلب المستخدمين' });
    }
});

// === تعديل رصيد المستخدم ===
app.post('/api/admin/update-balance', verifyAdmin, async (req, res) => {
    try {
        const { username, amount, action } = req.body;
        const user = await db.findUser(username);
        
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        
        let newBalance = parseFloat(user.balance);
        if (action === 'add') {
            newBalance += parseFloat(amount);
        } else if (action === 'subtract') {
            newBalance -= parseFloat(amount);
        } else if (action === 'set') {
            newBalance = parseFloat(amount);
        }
        
        await db.updateBalance(username, newBalance);
        
        await db.logActivity(
            req.user.id,
            req.user.username,
            'balance_update',
            `${action} ${amount} إلى رصيد ${username} (الرصيد الجديد: ${newBalance})`
        );
        
        res.json({ message: 'تم تحديث الرصيد بنجاح', balance: newBalance });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في تحديث الرصيد' });
    }
});

// === تعطيل/تفعيل المستخدم ===
app.post('/api/admin/toggle-user', verifyAdmin, async (req, res) => {
    try {
        const { username, active } = req.body;
        await pool.query('UPDATE users SET is_active = $1 WHERE username = $2', [active, username]);
        
        await db.logActivity(
            req.user.id,
            req.user.username,
            'user_toggle',
            `${active ? 'تفعيل' : 'تعطيل'} المستخدم ${username}`
        );
        
        res.json({ message: `تم ${active ? 'تفعيل' : 'تعطيل'} المستخدم بنجاح` });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في تحديث حالة المستخدم' });
    }
});

// === جلب سجل النشاطات ===
app.get('/api/admin/logs', verifyAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const logs = await db.getActivityLogs(limit);
        res.json(logs);
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في جلب السجلات' });
    }
});

// === حذف مستخدم ===
app.delete('/api/admin/delete-user', verifyAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (username === 'noor2613857noor') {
            return res.status(403).json({ error: 'لا يمكن حذف حساب الأدمن الرئيسي' });
        }
        
        await pool.query('DELETE FROM users WHERE username = $1', [username]);
        
        await db.logActivity(
            req.user.id,
            req.user.username,
            'delete_user',
            `حذف المستخدم ${username}`
        );
        
        res.json({ message: 'تم حذف المستخدم بنجاح' });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في حذف المستخدم' });
    }
});

// === جلب إحصائيات الموقع ===
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
        const totalBalance = await pool.query('SELECT SUM(balance) FROM users');
        const todayRegs = await pool.query(
            "SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE"
        );
        const todayLogins = await pool.query(
            "SELECT COUNT(*) FROM activity_logs WHERE action = 'login' AND DATE(created_at) = CURRENT_DATE"
        );
        
        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalBalance: parseFloat(totalBalance.rows[0].sum || 0),
            todayRegistrations: parseInt(todayRegs.rows[0].count),
            todayLogins: parseInt(todayLogins.rows[0].count)
        });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ في جلب الإحصائيات' });
    }
});

// ===== ملفات ثابتة =====
app.use(express.static('public'));

// ===== تشغيل الخادم =====
async function start() {
    await initDB();
    app.listen(PORT, () => {
        console.log(`\n🚀 Game Wars يعمل على http://localhost:${PORT}`);
        console.log(`👑 أدمن: noor2613857noor / admin123`);
        console.log(`📊 لوحة التحكم: http://localhost:${PORT}/admin\n`);
    });
}

start();
