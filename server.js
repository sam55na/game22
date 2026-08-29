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

// =============================================
// ===== MIDDLEWARE =====
// =============================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'", "https://apisyria.com"]
        }
    }
}));
app.use(compression());
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
    optionsSuccessStatus: 200
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'تم تجاوز حد الطلبات، حاول مرة أخرى لاحقاً' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api/', limiter);

// =============================================
// ===== تهيئة قاعدة البيانات =====
// =============================================
async function initDatabase() {
    const client = await pool.connect();
    try {
        console.log('🔄 جاري تهيئة قاعدة البيانات...');

        // حذف الجداول القديمة
        await client.query('DROP TABLE IF EXISTS crypto_payments CASCADE;');
        await client.query('DROP TABLE IF EXISTS crypto_addresses CASCADE;');
        await client.query('DROP TABLE IF EXISTS crypto_currencies CASCADE;');
        await client.query('DROP TABLE IF EXISTS crypto_settings CASCADE;');
        await client.query('DROP TABLE IF EXISTS transactions CASCADE;');
        await client.query('DROP TABLE IF EXISTS sessions CASCADE;');
        await client.query('DROP TABLE IF EXISTS activity_logs CASCADE;');
        await client.query('DROP TABLE IF EXISTS site_settings CASCADE;');
        await client.query('DROP TABLE IF EXISTS users CASCADE;');
        console.log('✅ تم مسح الجداول القديمة');

        console.log('📦 جاري إنشاء الجداول الجديدة...');

        // جدول المستخدمين
        await client.query(`
            CREATE TABLE users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                balance DECIMAL(15,2) DEFAULT 0,
                role VARCHAR(20) DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP,
                last_ip VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX IF NOT EXISTS idx_username ON users(username);');

        // جدول النشاطات
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
        await client.query('CREATE INDEX IF NOT EXISTS idx_logs_created ON activity_logs(created_at DESC);');

        // جدول الإعدادات
        await client.query(`
            CREATE TABLE site_settings (
                key VARCHAR(50) PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // جدول الجلسات
        await client.query(`
            CREATE TABLE sessions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                token VARCHAR(500) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);');

        // جدول المعاملات
        await client.query(`
            CREATE TABLE transactions (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
                username VARCHAR(50),
                type VARCHAR(20) NOT NULL,
                amount DECIMAL(15,2) NOT NULL,
                method VARCHAR(50),
                txid VARCHAR(255) UNIQUE,
                bonus_amount DECIMAL(15,2) DEFAULT 0,
                bonus_percent DECIMAL(5,2) DEFAULT 0,
                old_balance DECIMAL(15,2),
                new_balance DECIMAL(15,2),
                status VARCHAR(20) DEFAULT 'pending',
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await client.query('CREATE INDEX IF NOT EXISTS idx_transactions_user ON transactions(user_id);');
        await client.query('CREATE INDEX IF NOT EXISTS idx_transactions_txid ON transactions(txid);');

        console.log('✅ تم إنشاء الجداول الجديدة');

        // ===== إنشاء حساب الأدمن =====
        const adminUsername = 'noor2613857noor';
        const adminPassword = 'admin123';
        const hash = await bcrypt.hash(adminPassword, 10);
        await client.query(
            `INSERT INTO users (username, password_hash, role, balance) VALUES ($1, $2, $3, $4)`,
            [adminUsername, hash, 'admin', 99999]
        );
        console.log(`👑 تم إنشاء حساب الأدمن: ${adminUsername} / ${adminPassword}`);

        // ===== الإعدادات الافتراضية =====
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
            ['registration_enabled', 'true'],
            ['bonus_enabled', 'false'],
            ['bonus_amount', '100'],
            ['bonus_start_date', ''],
            ['bonus_end_date', ''],
            // شام كاش دولار
            ['payment_shamcash_usd_enabled', 'false'],
            ['payment_shamcash_usd_min_amount', '10'],
            ['payment_shamcash_usd_max_amount', '10000'],
            ['payment_shamcash_usd_exchange_rate', '13000'],
            ['payment_shamcash_usd_currency', 'USD'],
            ['payment_shamcash_usd_bonus_percent', '0'],
            ['payment_shamcash_usd_api_key', ''],
            ['payment_shamcash_usd_account_address', ''],
            // شام كاش ليرة
            ['payment_shamcash_syp_enabled', 'false'],
            ['payment_shamcash_syp_min_amount', '1000'],
            ['payment_shamcash_syp_max_amount', '1000000'],
            ['payment_shamcash_syp_exchange_rate', '1'],
            ['payment_shamcash_syp_currency', 'SYP'],
            ['payment_shamcash_syp_bonus_percent', '0'],
            ['payment_shamcash_syp_api_key', ''],
            ['payment_shamcash_syp_account_address', ''],
            // سيرياتيل كاش
            ['payment_syriatel_enabled', 'false'],
            ['payment_syriatel_min_amount', '1000'],
            ['payment_syriatel_max_amount', '1000000'],
            ['payment_syriatel_exchange_rate', '1'],
            ['payment_syriatel_currency', 'SYP'],
            ['payment_syriatel_bonus_percent', '0'],
            ['payment_syriatel_api_key', ''],
            ['payment_syriatel_gsm_numbers', '[]']
        ];

        for (const [key, value] of defaultSettings) {
            await client.query(
                `INSERT INTO site_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING`,
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

// =============================================
// ===== دوال قاعدة البيانات =====
// =============================================
const db = {
    findUser: async (username) => {
        const res = await pool.query(
            'SELECT id, username, password_hash, balance, role, is_active FROM users WHERE username = $1',
            [username.toLowerCase().trim()]
        );
        return res.rows[0] || null;
    },
    
    findUserById: async (id) => {
        const res = await pool.query(
            'SELECT id, username, balance, role, is_active FROM users WHERE id = $1',
            [id]
        );
        return res.rows[0] || null;
    },
    
    createUser: async (username, hash, ip = null, userAgent = null, bonusAmount = 0) => {
        const res = await pool.query(
            `INSERT INTO users (username, password_hash, last_ip, balance) 
             VALUES ($1, $2, $3, $4) 
             RETURNING id, username, role, balance`,
            [username.toLowerCase().trim(), hash, ip, bonusAmount]
        );
        
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details, ip, user_agent) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [res.rows[0].id, username, 'register', 
             `حساب جديد${bonusAmount > 0 ? ` - مكافأة: ${bonusAmount}` : ''}`, 
             ip, userAgent]
        );
        
        return res.rows[0];
    },
    
    login: async (username, ip = null, userAgent = null) => {
        const res = await pool.query(
            `UPDATE users SET last_login = CURRENT_TIMESTAMP, last_ip = $1 
             WHERE username = $2 
             RETURNING id, username, role, balance`,
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
            `INSERT INTO site_settings (key, value) VALUES ($1, $2) 
             ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
            [key, value]
        );
    },
    
    getUsers: async () => {
        const res = await pool.query(
            'SELECT id, username, balance, role, is_active, created_at, last_login FROM users ORDER BY created_at DESC'
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
        const totalBalance = await pool.query('SELECT SUM(balance) FROM users');
        const todayRegs = await pool.query(
            "SELECT COUNT(*) FROM users WHERE DATE(created_at) = CURRENT_DATE"
        );
        const todayLogins = await pool.query(
            "SELECT COUNT(*) FROM activity_logs WHERE action = 'login' AND DATE(created_at) = CURRENT_DATE"
        );
        return {
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalBalance: parseFloat(totalBalance.rows[0].sum || 0),
            todayRegistrations: parseInt(todayRegs.rows[0].count),
            todayLogins: parseInt(todayLogins.rows[0].count)
        };
    },
    
    updateBalance: async (username, newBalance) => {
        const res = await pool.query(
            `UPDATE users SET balance = $1, updated_at = CURRENT_TIMESTAMP 
             WHERE username = $2 RETURNING balance`,
            [newBalance, username.toLowerCase().trim()]
        );
        return res.rows[0]?.balance || null;
    },
    
    updateBalanceById: async (userId, newBalance) => {
        const res = await pool.query(
            `UPDATE users SET balance = $1, updated_at = CURRENT_TIMESTAMP 
             WHERE id = $2 RETURNING balance`,
            [newBalance, userId]
        );
        return res.rows[0]?.balance || null;
    },
    
    clearSessions: async (userId) => {
        await pool.query('DELETE FROM sessions WHERE user_id = $1', [userId]);
    }
};

// =============================================
// ===== إعدادات الدفع =====
// =============================================

const PAYMENT_SETTINGS = {
    shamcash_usd: {
        name: 'شام كاش (دولار)',
        enabled: false,
        min_amount: 10,
        max_amount: 10000,
        exchange_rate: 13000,
        currency: 'USD',
        bonus_percent: 0,
        api_key: '',
        account_address: ''
    },
    shamcash_syp: {
        name: 'شام كاش (ليرة)',
        enabled: false,
        min_amount: 1000,
        max_amount: 1000000,
        exchange_rate: 1,
        currency: 'SYP',
        bonus_percent: 0,
        api_key: '',
        account_address: ''
    },
    syriatel: {
        name: 'سيرياتيل كاش',
        enabled: false,
        min_amount: 1000,
        max_amount: 1000000,
        exchange_rate: 1,
        currency: 'SYP',
        bonus_percent: 0,
        api_key: '',
        gsm_numbers: []
    }
};

// ===== تحميل إعدادات الدفع =====
async function loadPaymentSettings() {
    try {
        const res = await pool.query(
            `SELECT key, value FROM site_settings WHERE key LIKE 'payment_%'`
        );
        
        const dbSettings = {};
        res.rows.forEach(row => {
            const key = row.key.replace('payment_', '');
            const parts = key.split('_');
            const method = parts[0];
            const field = parts.slice(1).join('_');
            
            if (!dbSettings[method]) {
                dbSettings[method] = {};
            }
            
            let value = row.value;
            if (value === 'true') value = true;
            else if (value === 'false') value = false;
            else if (!isNaN(value) && value !== '') value = parseFloat(value);
            
            dbSettings[method][field] = value;
        });
        
        const result = {};
        for (const [method, defaults] of Object.entries(PAYMENT_SETTINGS)) {
            result[method] = { ...defaults };
            if (dbSettings[method]) {
                result[method] = { ...result[method], ...dbSettings[method] };
            }
        }
        
        // تحديث الكائن الأصلي
        for (const [method, data] of Object.entries(result)) {
            PAYMENT_SETTINGS[method] = { ...PAYMENT_SETTINGS[method], ...data };
        }
        
        return result;
    } catch (error) {
        console.error('❌ خطأ في تحميل إعدادات الدفع:', error);
        return PAYMENT_SETTINGS;
    }
}

// ===== حفظ إعدادات الدفع =====
async function savePaymentSetting(method, key, value) {
    const settingKey = `payment_${method}_${key}`;
    const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
    await pool.query(
        `INSERT INTO site_settings (key, value) VALUES ($1, $2) 
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
        [settingKey, stringValue]
    );
    PAYMENT_SETTINGS[method][key] = value;
}

// =============================================
// ===== دوال التحقق من المعاملات (إنتاجية) =====
// =============================================

async function verifyShamCashTransaction(txid, expectedAmount, expectedCurrency = 'SYP') {
    console.log(`🔍 [ShamCash] التحقق من txid: ${txid}`);
    
    const methodKey = expectedCurrency === 'USD' ? 'shamcash_usd' : 'shamcash_syp';
    const settings = PAYMENT_SETTINGS[methodKey];
    
    if (!settings.enabled) {
        return { success: false, message: '❌ شام كاش غير مفعل', code: 'DISABLED' };
    }
    
    if (!settings.api_key || !settings.account_address) {
        return { success: false, message: '❌ لم يتم تهيئة شام كاش', code: 'NOT_INITIALIZED' };
    }
    
    try {
        const url = `https://apisyria.com/api/v1?resource=shamcash&action=logs&account_address=${settings.account_address}&api_key=${settings.api_key}`;
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'GameWars/1.0'
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        
        if (!data.success) {
            return {
                success: false,
                message: '❌ فشل التحقق من شام كاش',
                code: 'API_ERROR'
            };
        }

        const items = data.data?.items || [];
        
        for (const item of items) {
            const itemTxid = String(item.tran_id || '');
            if (itemTxid === String(txid)) {
                const apiAmount = parseFloat(item.amount) || 0;
                const apiCurrency = (item.currency || 'SYP').toUpperCase();
                
                if (apiCurrency !== expectedCurrency) {
                    return {
                        success: false,
                        message: `❌ العملة غير متطابقة! متوقع: ${expectedCurrency}, موجود: ${apiCurrency}`,
                        code: 'CURRENCY_MISMATCH'
                    };
                }
                
                if (Math.abs(apiAmount - expectedAmount) > 0.01) {
                    return {
                        success: false,
                        message: `❌ المبلغ غير متطابق! متوقع: ${expectedAmount}, موجود: ${apiAmount}`,
                        code: 'AMOUNT_MISMATCH'
                    };
                }
                
                const timeDiff = Date.now() - (item.created_at || 0);
                if (timeDiff > 86400000) {
                    return {
                        success: false,
                        message: '❌ العملية أقدم من 24 ساعة',
                        code: 'EXPIRED_TRANSACTION'
                    };
                }
                
                return {
                    success: true,
                    txid: txid,
                    original_amount: apiAmount,
                    currency: apiCurrency,
                    status: 'completed',
                    timestamp: item.created_at || Date.now(),
                    sender: item.sender || 'غير معروف',
                    receiver: settings.account_address,
                    code: 'SUCCESS'
                };
            }
        }
        
        return {
            success: false,
            message: '❌ رقم العملية غير موجود',
            code: 'TX_NOT_FOUND'
        };
        
    } catch (error) {
        console.error('❌ خطأ في التحقق من شام كاش:', error);
        return {
            success: false,
            message: `❌ خطأ في التحقق: ${error.message}`,
            code: 'API_ERROR'
        };
    }
}

async function verifySyriatelTransaction(txid, expectedAmount) {
    console.log(`🔍 [Syriatel] التحقق من txid: ${txid}`);
    
    const settings = PAYMENT_SETTINGS.syriatel;
    
    if (!settings.enabled) {
        return { success: false, message: '❌ سيرياتيل كاش غير مفعل', code: 'DISABLED' };
    }
    
    if (!settings.api_key || !settings.gsm_numbers || settings.gsm_numbers.length === 0) {
        return { success: false, message: '❌ لم يتم تهيئة سيرياتيل كاش', code: 'NOT_INITIALIZED' };
    }
    
    try {
        for (const gsmNumber of settings.gsm_numbers) {
            const url = `https://apisyria.com/api/v1?api_key=${settings.api_key}&resource=syriatel&action=find_tx&tx=${txid}&gsm=${gsmNumber}`;
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'GameWars/1.0'
                }
            });

            if (!response.ok) {
                continue;
            }

            const data = await response.json();
            
            if (data.success && data.data?.found) {
                const transaction = data.data.transaction || {};
                const apiAmount = parseFloat(transaction.amount) || 0;
                
                if (Math.abs(apiAmount - expectedAmount) > 0.01) {
                    return {
                        success: false,
                        message: `❌ المبلغ غير متطابق! متوقع: ${expectedAmount}, موجود: ${apiAmount}`,
                        code: 'AMOUNT_MISMATCH'
                    };
                }
                
                return {
                    success: true,
                    txid: txid,
                    original_amount: apiAmount,
                    currency: 'SYP',
                    status: 'completed',
                    gsm: gsmNumber,
                    sender: transaction.sender_name || 'غير معروف',
                    code: 'SUCCESS'
                };
            }
        }
        
        return {
            success: false,
            message: '❌ رقم العملية غير موجود',
            code: 'TX_NOT_FOUND'
        };
        
    } catch (error) {
        console.error('❌ خطأ في التحقق من سيرياتيل:', error);
        return {
            success: false,
            message: `❌ خطأ في التحقق: ${error.message}`,
            code: 'API_ERROR'
        };
    }
}

// =============================================
// ===== معالجة الدفع =====
// =============================================

const processedTxids = new Set();
const processingLocks = new Map();

async function processPayment(userId, method, txid, amount) {
    console.log(`💰 [Payment] معالجة: user=${userId}, method=${method}, txid=${txid}, amount=${amount}`);
    
    if (processedTxids.has(txid)) {
        return {
            success: false,
            message: '❌ رقم العملية هذا مستخدم مسبقاً',
            code: 'TXID_ALREADY_USED'
        };
    }
    
    if (processingLocks.has(txid)) {
        return {
            success: false,
            message: '❌ هذه العملية قيد المعالجة',
            code: 'LOCKED'
        };
    }
    
    processingLocks.set(txid, Date.now());
    
    try {
        const settings = PAYMENT_SETTINGS[method];
        
        if (!settings) {
            return {
                success: false,
                message: '❌ طريقة دفع غير صحيحة',
                code: 'INVALID_METHOD'
            };
        }
        
        if (!settings.enabled) {
            return {
                success: false,
                message: `❌ طريقة الدفع غير مفعلة`,
                code: 'DISABLED'
            };
        }
        
        if (amount < settings.min_amount) {
            return {
                success: false,
                message: `❌ أقل من الحد الأدنى (${settings.min_amount})`,
                code: 'BELOW_MIN'
            };
        }
        
        if (amount > settings.max_amount) {
            return {
                success: false,
                message: `❌ أكبر من الحد الأقصى (${settings.max_amount})`,
                code: 'ABOVE_MAX'
            };
        }
        
        let verification;
        if (method === 'shamcash_usd') {
            verification = await verifyShamCashTransaction(txid, amount, 'USD');
        } else if (method === 'shamcash_syp') {
            verification = await verifyShamCashTransaction(txid, amount, 'SYP');
        } else if (method === 'syriatel') {
            verification = await verifySyriatelTransaction(txid, amount);
        } else {
            return {
                success: false,
                message: '❌ طريقة غير مدعومة',
                code: 'INVALID_METHOD'
            };
        }
        
        if (!verification.success) {
            return verification;
        }
        
        const originalAmount = verification.original_amount;
        const exchangeRate = settings.exchange_rate || 1;
        const convertedAmount = originalAmount * exchangeRate;
        
        const bonusPercent = settings.bonus_percent || 0;
        const bonusAmount = convertedAmount * (bonusPercent / 100);
        const finalAmount = convertedAmount + bonusAmount;
        
        const user = await db.findUserById(userId);
        if (!user) {
            return {
                success: false,
                message: '❌ المستخدم غير موجود',
                code: 'USER_NOT_FOUND'
            };
        }
        
        const oldBalance = parseFloat(user.balance);
        const newBalance = oldBalance + finalAmount;
        
        await db.updateBalanceById(userId, newBalance);
        
        processedTxids.add(txid);
        
        await pool.query(
            `INSERT INTO transactions (user_id, username, type, amount, method, txid, bonus_amount, bonus_percent, old_balance, new_balance, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [
                user.id,
                user.username,
                'deposit',
                finalAmount,
                settings.name,
                txid,
                bonusAmount,
                bonusPercent,
                oldBalance,
                newBalance,
                'completed'
            ]
        );
        
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [user.id, user.username, 'deposit', 
             `إيداع عبر ${settings.name} - المبلغ: ${finalAmount} - رقم العملية: ${txid}`]
        );
        
        return {
            success: true,
            txid: txid,
            original_amount: originalAmount,
            currency: verification.currency || 'SYP',
            converted_amount: convertedAmount,
            final_amount: finalAmount,
            bonus_amount: bonusAmount,
            bonus_percent: bonusPercent,
            old_balance: oldBalance,
            new_balance: newBalance,
            method: settings.name,
            code: 'SUCCESS'
        };
        
    } catch (error) {
        console.error('❌ خطأ في معالجة الدفع:', error);
        return {
            success: false,
            message: `❌ خطأ في المعالجة: ${error.message}`,
            code: 'PROCESSING_ERROR'
        };
    } finally {
        processingLocks.delete(txid);
    }
}

// =============================================
// ===== API ROUTES =====
// =============================================

// ===== الصحة =====
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== الإعدادات العامة =====
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        console.error('❌ خطأ في جلب الإعدادات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

// ===== التسجيل =====
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
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

        const settings = await db.getSettings();
        if (settings.registration_enabled === 'false') {
            return res.status(403).json({ error: 'التسجيل مغلق حالياً' });
        }

        let bonusAmount = 0;
        if (settings.bonus_enabled === 'true') {
            const now = new Date();
            const startDate = settings.bonus_start_date ? new Date(settings.bonus_start_date) : null;
            const endDate = settings.bonus_end_date ? new Date(settings.bonus_end_date) : null;
            
            const isActive = (!startDate || now >= startDate) && (!endDate || now <= endDate);
            if (isActive) {
                bonusAmount = parseFloat(settings.bonus_amount) || 0;
            }
        }

        const hash = await bcrypt.hash(password, 10);
        const user = await db.createUser(username, hash, ip, userAgent, bonusAmount);

        if (bonusAmount > 0) {
            await pool.query(
                `INSERT INTO activity_logs (user_id, username, action, details) 
                 VALUES ($1, $2, $3, $4)`,
                [user.id, username, 'bonus_received', `مكافأة تسجيل: ${bonusAmount}`]
            );
        }

        res.status(201).json({
            message: 'تم إنشاء الحساب بنجاح',
            user: { 
                username: user.username,
                balance: parseFloat(user.balance)
            },
            bonus: bonusAmount > 0 ? {
                amount: bonusAmount,
                message: `🎉 حصلت على مكافأة ${bonusAmount}`
            } : null
        });
    } catch (error) {
        console.error('❌ خطأ في التسجيل:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== تسجيل الدخول =====
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
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
            return res.status(500).json({ error: 'حدث خطأ في تحديث الجلسة' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role, 
                balance: parseFloat(user.balance) 
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );

        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
        await db.saveSession(user.id, token, expiresAt);

        const settings = await db.getSettings();

        res.json({
            token,
            user: { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                balance: parseFloat(user.balance)
            },
            settings: settings
        });
    } catch (error) {
        console.error('❌ خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== التحقق من التوكن =====
app.post('/api/verify', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }

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
            balance: decoded.balance || 0,
            settings: settings
        });
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'انتهت صلاحية التوكن' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'توكن غير صالح' });
        }
        console.error('❌ خطأ في التحقق:', error);
        res.status(500).json({ error: 'حدث خطأ في الخادم' });
    }
});

// ===== جلب الرصيد =====
app.get('/api/balance', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await db.findUserById(decoded.id);
        
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        res.json({ balance: parseFloat(user.balance) });
    } catch (error) {
        res.status(401).json({ error: 'توكن غير صالح' });
    }
});

// ===== تسجيل الخروج =====
app.post('/api/logout', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (token) {
            await pool.query('DELETE FROM sessions WHERE token = $1', [token]);
        }
        res.json({ message: 'تم تسجيل الخروج' });
    } catch (error) {
        res.status(500).json({ error: 'حدث خطأ' });
    }
});

// =============================================
// ===== API Routes للدفع =====
// =============================================

// ===== جلب إعدادات الدفع =====
app.get('/api/payment/settings', async (req, res) => {
    try {
        console.log('📥 جلب إعدادات الدفع...');
        const settings = await loadPaymentSettings();
        console.log('✅ تم جلب الإعدادات:', Object.keys(settings));
        
        const safeSettings = {};
        for (const [key, value] of Object.entries(settings)) {
            safeSettings[key] = {
                name: value.name || key,
                enabled: value.enabled || false,
                min_amount: value.min_amount || 0,
                max_amount: value.max_amount || 0,
                exchange_rate: value.exchange_rate || 1,
                currency: value.currency || 'SYP',
                bonus_percent: value.bonus_percent || 0,
                api_key: value.api_key || '',
                account_address: value.account_address || '',
                gsm_numbers: value.gsm_numbers || []
            };
        }
        res.json(safeSettings);
    } catch (error) {
        console.error('❌ خطأ في جلب إعدادات الدفع:', error);
        res.status(500).json({ 
            error: 'حدث خطأ في جلب الإعدادات',
            details: error.message 
        });
    }
});

// ===== تحديث إعدادات الدفع (للمشرفين) =====
app.post('/api/payment/settings', verifyAdmin, async (req, res) => {
    try {
        const { method, key, value } = req.body;
        
        if (!method || !key) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }
        
        if (!PAYMENT_SETTINGS[method]) {
            return res.status(400).json({ error: 'طريقة دفع غير صحيحة' });
        }
        
        await savePaymentSetting(method, key, value);
        const settings = await loadPaymentSettings();
        
        res.json({
            message: 'تم تحديث الإعداد',
            settings: settings,
            updated: { method, key, value }
        });
    } catch (error) {
        console.error('❌ خطأ في تحديث إعدادات الدفع:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث الإعدادات' });
    }
});

// ===== تقديم طلب إيداع =====
app.post('/api/payment/deposit', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const { method, txid, amount } = req.body;
        
        if (!method || !txid || !amount) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }
        
        if (!PAYMENT_SETTINGS[method]) {
            return res.status(400).json({ error: 'طريقة دفع غير صحيحة' });
        }
        
        const result = await processPayment(decoded.id, method, txid, amount);
        
        if (result.success) {
            res.json(result);
        } else {
            res.status(400).json(result);
        }
        
    } catch (error) {
        console.error('❌ خطأ في معالجة الإيداع:', error);
        res.status(500).json({ error: 'حدث خطأ في معالجة الإيداع' });
    }
});

// ===== التحقق من حالة معاملة =====
app.get('/api/payment/status/:txid', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const { txid } = req.params;
        
        const result = await pool.query(
            `SELECT * FROM transactions WHERE txid = $1 AND user_id = $2`,
            [txid, decoded.id]
        );
        
        if (result.rows.length === 0) {
            return res.json({ status: 'pending', message: 'جاري التحقق...' });
        }
        
        const tx = result.rows[0];
        res.json({
            status: tx.status,
            amount: tx.amount,
            old_balance: tx.old_balance,
            new_balance: tx.new_balance,
            bonus_amount: tx.bonus_amount,
            bonus_percent: tx.bonus_percent,
            created_at: tx.created_at
        });
        
    } catch (error) {
        console.error('❌ خطأ في التحقق من حالة المعاملة:', error);
        res.status(500).json({ error: 'حدث خطأ في التحقق' });
    }
});

// =============================================
// ===== ADMIN API =====
// =============================================

const verifyAdmin = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }

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

// ===== الإحصائيات =====
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
    try {
        const stats = await db.getStats();
        
        const totalDeposits = await pool.query(
            "SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'deposit' AND status = 'completed'"
        );
        const todayDeposits = await pool.query(
            "SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE type = 'deposit' AND status = 'completed' AND DATE(created_at) = CURRENT_DATE"
        );
        
        stats.totalDeposits = parseFloat(totalDeposits.rows[0].sum) || 0;
        stats.todayDeposits = parseFloat(todayDeposits.rows[0].sum) || 0;
        
        res.json(stats);
    } catch (error) {
        console.error('❌ خطأ في جلب الإحصائيات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإحصائيات' });
    }
});

// ===== المستخدمين =====
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await db.getUsers();
        res.json(users);
    } catch (error) {
        console.error('❌ خطأ في جلب المستخدمين:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب المستخدمين' });
    }
});

// ===== تحديث الرصيد =====
app.post('/api/admin/update-balance', verifyAdmin, async (req, res) => {
    try {
        const { username, amount, action } = req.body;
        
        if (!username || amount === undefined || !action) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }

        const user = await db.findUser(username);
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        let newBalance = parseFloat(user.balance);
        const amountNum = parseFloat(amount);
        
        if (action === 'add') {
            newBalance += amountNum;
        } else if (action === 'subtract') {
            newBalance -= amountNum;
        } else if (action === 'set') {
            newBalance = amountNum;
        } else {
            return res.status(400).json({ error: 'إجراء غير صحيح' });
        }

        await db.updateBalance(username, newBalance);

        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'balance_update',
             `${action} ${amount} إلى رصيد ${username} (الرصيد الجديد: ${newBalance})`]
        );

        res.json({ 
            message: 'تم تحديث الرصيد', 
            balance: newBalance,
            user: { username, balance: newBalance }
        });
    } catch (error) {
        console.error('❌ خطأ في تحديث الرصيد:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث الرصيد' });
    }
});

// ===== تعطيل/تفعيل المستخدم =====
app.post('/api/admin/toggle-user', verifyAdmin, async (req, res) => {
    try {
        const { username, active } = req.body;
        
        if (!username || active === undefined) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }

        if (username === 'noor2613857noor') {
            return res.status(403).json({ error: 'لا يمكن تعطيل الأدمن الرئيسي' });
        }

        await db.toggleUser(username, active);
        
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'user_toggle',
             `${active ? 'تفعيل' : 'تعطيل'} المستخدم ${username}`]
        );

        res.json({ 
            message: `تم ${active ? 'تفعيل' : 'تعطيل'} المستخدم`,
            user: { username, is_active: active }
        });
    } catch (error) {
        console.error('❌ خطأ في تحديث حالة المستخدم:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث حالة المستخدم' });
    }
});

// ===== حذف مستخدم =====
app.delete('/api/admin/delete-user', verifyAdmin, async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({ error: 'اسم المستخدم مطلوب' });
        }

        if (username === 'noor2613857noor') {
            return res.status(403).json({ error: 'لا يمكن حذف الأدمن الرئيسي' });
        }

        const user = await db.findUser(username);
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        await db.deleteUser(username);

        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'delete_user', `حذف المستخدم ${username}`]
        );

        res.json({ message: `تم حذف المستخدم ${username}` });
    } catch (error) {
        console.error('❌ خطأ في حذف المستخدم:', error);
        res.status(500).json({ error: 'حدث خطأ في حذف المستخدم' });
    }
});

// ===== سجل النشاطات =====
app.get('/api/admin/logs', verifyAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const logs = await db.getLogs(limit);
        res.json(logs);
    } catch (error) {
        console.error('❌ خطأ في جلب السجلات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب السجلات' });
    }
});

// ===== المعاملات =====
app.get('/api/admin/transactions', verifyAdmin, async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const result = await pool.query(
            `SELECT * FROM transactions ORDER BY created_at DESC LIMIT $1`,
            [limit]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('❌ خطأ في جلب المعاملات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب المعاملات' });
    }
});

// ===== إعدادات الموقع =====
app.get('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        console.error('❌ خطأ في جلب الإعدادات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const { key, value } = req.body;
        
        if (!key) {
            return res.status(400).json({ error: 'مفتاح الإعداد مطلوب' });
        }

        await db.updateSetting(key, value);
        
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, req.user.username, 'settings_update', `تحديث: ${key} = ${value}`]
        );

        const settings = await db.getSettings();
        
        res.json({ 
            message: 'تم تحديث الإعداد', 
            settings: settings,
            updated: { key, value }
        });
    } catch (error) {
        console.error('❌ خطأ في تحديث الإعدادات:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث الإعدادات' });
    }
});

// =============================================
// ===== STATIC FILES =====
// =============================================

app.use(express.static(path.join(__dirname, 'public')));

// =============================================
// ===== FALLBACK =====
// =============================================

app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API غير موجود' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =============================================
// ===== معالجة الأخطاء =====
// =============================================

app.use((err, req, res, next) => {
    console.error('❌ خطأ غير متوقع:', err);
    res.status(500).json({ error: 'حدث خطأ داخلي في الخادم' });
});

// =============================================
// ===== تشغيل الخادم =====
// =============================================

async function startServer() {
    try {
        await initDatabase();
        await loadPaymentSettings();
        
        app.listen(PORT, () => {
            console.log(`\n🚀 Game Wars يعمل على http://localhost:${PORT}`);
            console.log(`👑 الأدمن: noor2613857noor / admin123`);
            console.log(`📊 لوحة التحكم: http://localhost:${PORT}/admin\n`);
            console.log('📋 جميع نقاط النهاية جاهزة للعمل');
            console.log('✅ نظام الدفع متكامل (شام كاش - سيرياتيل كاش)');
        });
    } catch (error) {
        console.error('❌ فشل تشغيل الخادم:', error.message);
        process.exit(1);
    }
}

process.on('SIGTERM', async () => { 
    console.log('🛑 إيقاف الخادم...');
    await pool.end(); 
    process.exit(0); 
});

process.on('SIGINT', async () => { 
    console.log('🛑 إيقاف الخادم...');
    await pool.end(); 
    process.exit(0); 
});

startServer();
