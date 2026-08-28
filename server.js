require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

// ===== إعدادات البيئة =====
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key_change_this_in_production_123456';
const NODE_ENV = process.env.NODE_ENV || 'development';

// ===== دالة تحليل رابط قاعدة البيانات =====
function parseDatabaseUrl(url) {
    if (!url) return null;
    
    try {
        const parsed = new URL(url);
        const sslMode = parsed.searchParams.get('ssl') || 
                        parsed.searchParams.get('sslmode') || 
                        'prefer';
        
        // تحديد إعدادات SSL
        let sslConfig = false;
        if (sslMode === 'require' || sslMode === 'true' || sslMode === 'verify-full') {
            sslConfig = {
                rejectUnauthorized: false // ضروري لـ Render و Supabase
            };
        } else if (sslMode === 'prefer') {
            sslConfig = {
                rejectUnauthorized: false
            };
        }
        
        return {
            host: parsed.hostname,
            port: parseInt(parsed.port) || 5432,
            user: parsed.username,
            password: parsed.password,
            database: parsed.pathname.slice(1),
            ssl: sslConfig,
            // إعدادات إضافية للتحمل
            connectionTimeoutMillis: 10000,
            idleTimeoutMillis: 30000,
            max: 20
        };
    } catch (error) {
        console.error('❌ خطأ في تحليل رابط قاعدة البيانات:', error.message);
        return null;
    }
}

// ===== إنشاء تجمع اتصالات PostgreSQL =====
function createPool() {
    let config = {};
    
    // الأولوية: DATABASE_URL (متغير Render)
    const dbUrl = process.env.DATABASE_URL || process.env.DB_URL;
    
    if (dbUrl) {
        console.log('🔗 استخدام رابط قاعدة البيانات من البيئة');
        const parsed = parseDatabaseUrl(dbUrl);
        if (parsed) {
            config = parsed;
            // إخفاء كلمة المرور في السجلات
            const maskedUrl = dbUrl.replace(/:[^:@]*@/, ':***@');
            console.log(`📊 قاعدة البيانات: ${maskedUrl}`);
        } else {
            console.error('❌ رابط قاعدة البيانات غير صالح، استخدام الإعدادات اليدوية');
            config = getManualConfig();
        }
    } else {
        console.log('📝 استخدام إعدادات قاعدة البيانات اليدوية');
        config = getManualConfig();
    }
    
    return new Pool(config);
}

// ===== إعدادات يدوية احتياطية =====
function getManualConfig() {
    const sslMode = process.env.DB_SSL_MODE || 'prefer';
    let sslConfig = false;
    
    if (sslMode === 'require' || sslMode === 'true') {
        sslConfig = { rejectUnauthorized: false };
    } else if (sslMode === 'prefer') {
        sslConfig = { rejectUnauthorized: false };
    }
    
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

// ===== تهيئة قاعدة البيانات =====
async function initializeDatabase(pool) {
    const client = await pool.connect();
    try {
        console.log('🔄 جاري التحقق من قاعدة البيانات...');
        
        // اختبار الاتصال
        const testResult = await client.query('SELECT NOW()');
        console.log(`✅ اتصال قاعدة البيانات ناجح: ${testResult.rows[0].now}`);
        
        // التحقق من وجود جدول المستخدمين
        const tableCheck = await client.query(`
            SELECT EXISTS (
                SELECT 1 
                FROM information_schema.tables 
                WHERE table_name = 'users'
            );
        `);
        
        const tableExists = tableCheck.rows[0].exists;
        
        if (!tableExists) {
            console.log('📦 تهيئة قاعدة البيانات للمرة الأولى...');
            
            // إنشاء جدول المستخدمين
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
                CREATE INDEX IF NOT EXISTS idx_created_at ON users(created_at);
            `);
            
            console.log('✅ تم إنشاء الجداول بنجاح');
            
            // إضافة مستخدم تجريبي (فقط في بيئة التطوير)
            if (NODE_ENV !== 'production') {
                const userCheck = await client.query(
                    'SELECT * FROM users WHERE username = $1',
                    ['admin']
                );
                
                if (userCheck.rows.length === 0) {
                    const hashedPassword = await bcrypt.hash('admin123', 10);
                    await client.query(
                        `INSERT INTO users (username, password_hash, balance) 
                         VALUES ($1, $2, $3)`,
                        ['admin', hashedPassword, 9999.99]
                    );
                    console.log('👤 تم إنشاء مستخدم تجريبي: admin / admin123');
                }
            }
        } else {
            console.log('✅ قاعدة البيانات موجودة بالفعل');
            
            // التحقق من وجود المستخدم التجريبي (فقط في التطوير)
            if (NODE_ENV !== 'production') {
                const userCheck = await client.query(
                    'SELECT * FROM users WHERE username = $1',
                    ['admin']
                );
                
                if (userCheck.rows.length === 0) {
                    const hashedPassword = await bcrypt.hash('admin123', 10);
                    await client.query(
                        `INSERT INTO users (username, password_hash, balance) 
                         VALUES ($1, $2, $3)`,
                        ['admin', hashedPassword, 9999.99]
                    );
                    console.log('👤 تم إنشاء مستخدم تجريبي: admin / admin123');
                }
            }
        }
        
        console.log('✅ تهيئة قاعدة البيانات مكتملة');
        return true;
        
    } catch (error) {
        console.error('❌ خطأ في تهيئة قاعدة البيانات:', error.message);
        console.error('تفاصيل:', error.stack);
        return false;
    } finally {
        client.release();
    }
}

// ===== إنشاء تجمع الاتصالات =====
const pool = createPool();

// ===== دوال قاعدة البيانات =====
const db = {
    findUser: async (username) => {
        try {
            const result = await pool.query(
                'SELECT * FROM users WHERE username = $1',
                [username.toLowerCase().trim()]
            );
            return result.rows[0] || null;
        } catch (error) {
            console.error('خطأ في البحث عن المستخدم:', error.message);
            throw error;
        }
    },
    
    createUser: async (username, hashedPassword) => {
        try {
            const result = await pool.query(
                `INSERT INTO users (username, password_hash) 
                 VALUES ($1, $2) 
                 RETURNING id, username, balance, created_at`,
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
            await pool.query(
                'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE username = $1',
                [username.toLowerCase().trim()]
            );
        } catch (error) {
            console.error('خطأ في تحديث آخر تسجيل دخول:', error.message);
            throw error;
        }
    },
    
    getUserData: async (username) => {
        try {
            const result = await pool.query(
                'SELECT username, balance FROM users WHERE username = $1',
                [username.toLowerCase().trim()]
            );
            return result.rows[0] || null;
        } catch (error) {
            console.error('خطأ في جلب بيانات المستخدم:', error.message);
            throw error;
        }
    },
    
    updateBalance: async (username, newBalance) => {
        try {
            const result = await pool.query(
                'UPDATE users SET balance = $1 WHERE username = $2 RETURNING balance',
                [newBalance, username.toLowerCase().trim()]
            );
            return result.rows[0]?.balance || null;
        } catch (error) {
            console.error('خطأ في تحديث الرصيد:', error.message);
            throw error;
        }
    }
};

// ===== إعداد Express =====
app.use(cors({
    origin: NODE_ENV === 'production' ? process.env.CLIENT_URL || '*' : '*',
    credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ===== ملفات ثابتة =====
app.use(express.static(path.join(__dirname, 'public')));

// ===== نقاط النهاية (API Routes) =====

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// التحقق من حالة الخادم
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: NODE_ENV,
        database: pool.options.database || 'unknown'
    });
});

// التحقق من حالة قاعدة البيانات
app.get('/api/db-status', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW() as time, version() as version');
        res.json({
            status: 'connected',
            time: result.rows[0].time,
            version: result.rows[0].version,
            database: pool.options.database,
            host: pool.options.host,
            ssl: !!pool.options.ssl
        });
    } catch (error) {
        res.status(500).json({
            status: 'disconnected',
            error: error.message
        });
    }
});

// إنشاء حساب جديد
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // التحقق من صحة الإدخال
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'يرجى ملء جميع الحقول',
                field: !username ? 'username' : 'password'
            });
        }
        
        if (username.length < 3) {
            return res.status(400).json({ 
                error: 'اسم المستخدم يجب أن يكون 3 أحرف على الأقل' 
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' 
            });
        }
        
        // التحقق من وجود المستخدم
        const existingUser = await db.findUser(username);
        if (existingUser) {
            return res.status(409).json({ 
                error: 'اسم المستخدم موجود مسبقاً' 
            });
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
        res.status(500).json({ 
            error: 'حدث خطأ في الخادم، يرجى المحاولة مرة أخرى' 
        });
    }
});

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                error: 'يرجى ملء جميع الحقول' 
            });
        }

        // البحث عن المستخدم
        const user = await db.findUser(username);
        if (!user) {
            return res.status(401).json({ 
                error: 'اسم المستخدم أو كلمة المرور غير صحيحة' 
            });
        }

        // التحقق من كلمة المرور
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ 
                error: 'اسم المستخدم أو كلمة المرور غير صحيحة' 
            });
        }

        // تحديث آخر تسجيل دخول
        await db.updateLastLogin(username);

        // إنشاء توكن
        const token = jwt.sign(
            { 
                username: user.username, 
                balance: parseFloat(user.balance),
                id: user.id
            },
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
        res.status(500).json({ 
            error: 'حدث خطأ في الخادم، يرجى المحاولة مرة أخرى' 
        });
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

        res.json({
            username: user.username,
            balance: parseFloat(user.balance)
        });
        
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

// ===== معالجة الأخطاء =====
app.use((req, res) => {
    res.status(404).json({ error: 'المسار غير موجود' });
});

app.use((err, req, res, next) => {
    console.error('❌ خطأ غير متوقع:', err);
    res.status(500).json({ 
        error: 'حدث خطأ داخلي في الخادم' 
    });
});

// ===== تشغيل الخادم =====
async function startServer() {
    try {
        // تهيئة قاعدة البيانات
        const dbInitialized = await initializeDatabase(pool);
        
        if (!dbInitialized && NODE_ENV === 'production') {
            console.warn('⚠️ تحذير: قاعدة البيانات غير متصلة بشكل كامل');
        }
        
        // تشغيل الخادم
        const server = app.listen(PORT, () => {
            console.log(`\n${'='.repeat(50)}`);
            console.log(`🚀 الخادم يعمل على http://localhost:${PORT}`);
            console.log(`📊 قاعدة البيانات: ${pool.options.database || 'غير متصلة'}`);
            console.log(`🔗 المضيف: ${pool.options.host || 'localhost'}`);
            console.log(`🔒 SSL: ${pool.options.ssl ? 'مفعل ✅' : 'غير مفعل ❌'}`);
            console.log(`🌍 البيئة: ${NODE_ENV}`);
            console.log(`${'='.repeat(50)}\n`);
            
            if (NODE_ENV !== 'production') {
                console.log('👤 مستخدم تجريبي: admin / admin123');
                console.log(`📡 تحقق من حالة الخادم: http://localhost:${PORT}/api/health`);
                console.log(`📡 تحقق من حالة قاعدة البيانات: http://localhost:${PORT}/api/db-status\n`);
            }
        });
        
        // إغلاق نظيف
        process.on('SIGTERM', async () => {
            console.log('\n🛑 استلام إشارة SIGTERM، جاري الإيقاف...');
            server.close(async () => {
                await pool.end();
                console.log('✅ تم إغلاق الاتصالات');
                process.exit(0);
            });
        });
        
        process.on('SIGINT', async () => {
            console.log('\n🛑 استلام إشارة SIGINT، جاري الإيقاف...');
            server.close(async () => {
                await pool.end();
                console.log('✅ تم إغلاق الاتصالات');
                process.exit(0);
            });
        });
        
    } catch (error) {
        console.error('❌ فشل تشغيل الخادم:', error.message);
        console.error('تفاصيل:', error.stack);
        process.exit(1);
    }
}

// ===== بدء التطبيق =====
startServer();
