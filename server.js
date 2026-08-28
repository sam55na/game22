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

// 1. الأمان والضغط
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

// 2. CORS
app.use(cors({
    origin: process.env.CORS_ORIGIN || '*',
    credentials: true,
    optionsSuccessStatus: 200
}));

// 3. JSON Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 4. Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'تم تجاوز حد الطلبات، حاول مرة أخرى لاحقاً' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false },
    keyGenerator: (req) => req.ip || req.connection.remoteAddress || 'unknown'
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

        // إنشاء الجداول الجديدة
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
        await client.query('CREATE INDEX IF NOT EXISTS idx_role ON users(role);');

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
        await client.query('CREATE INDEX IF NOT EXISTS idx_logs_user ON activity_logs(user_id);');

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
        await client.query('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);');

        // ===== جداول نظام الدفع =====

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
        await client.query('CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);');

        // جدول العملات الرقمية
        await client.query(`
            CREATE TABLE crypto_currencies (
                currency_key TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                symbol TEXT NOT NULL,
                network TEXT NOT NULL,
                min_amount REAL DEFAULT 1,
                max_amount REAL DEFAULT 100000,
                is_enabled INTEGER DEFAULT 1,
                priority INTEGER DEFAULT 0,
                decimals INTEGER DEFAULT 8,
                is_internal INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // جدول عناوين العملات الرقمية
        await client.query(`
            CREATE TABLE crypto_addresses (
                currency_key TEXT PRIMARY KEY,
                symbol TEXT NOT NULL,
                network TEXT NOT NULL,
                address TEXT NOT NULL,
                memo TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // جدول طلبات الدفع بالعملات الرقمية
        await client.query(`
            CREATE TABLE crypto_payments (
                request_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                currency_key TEXT NOT NULL,
                currency_name TEXT NOT NULL,
                amount_usd REAL NOT NULL,
                crypto_amount REAL NOT NULL,
                amount_syp REAL NOT NULL,
                bonus_amount REAL DEFAULT 0,
                final_amount REAL DEFAULT 0,
                address TEXT NOT NULL,
                memo TEXT,
                tx_id TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            );
        `);

        // جدول إعدادات العملات الرقمية
        await client.query(`
            CREATE TABLE crypto_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                is_enabled INTEGER DEFAULT 0,
                api_key TEXT DEFAULT '',
                api_secret TEXT DEFAULT '',
                internal_address TEXT DEFAULT '',
                bonus_enabled INTEGER DEFAULT 0,
                bonus_percent REAL DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

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
            ['bonus_start_date', null],
            ['bonus_end_date', null],
            // إعدادات شام كاش دولار
            ['payment_shamcash_usd_enabled', 'false'],
            ['payment_shamcash_usd_min_amount', '10'],
            ['payment_shamcash_usd_max_amount', '10000'],
            ['payment_shamcash_usd_exchange_rate', '13000'],
            ['payment_shamcash_usd_currency', 'USD'],
            ['payment_shamcash_usd_bonus_percent', '0'],
            ['payment_shamcash_usd_api_key', ''],
            ['payment_shamcash_usd_account_address', ''],
            // إعدادات شام كاش ليرة
            ['payment_shamcash_syp_enabled', 'false'],
            ['payment_shamcash_syp_min_amount', '1000'],
            ['payment_shamcash_syp_max_amount', '1000000'],
            ['payment_shamcash_syp_exchange_rate', '1'],
            ['payment_shamcash_syp_currency', 'SYP'],
            ['payment_shamcash_syp_bonus_percent', '0'],
            ['payment_shamcash_syp_api_key', ''],
            ['payment_shamcash_syp_account_address', ''],
            // إعدادات سيرياتيل كاش
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
                `INSERT INTO site_settings (key, value) VALUES ($1, $2)`,
                [key, value]
            );
        }

        // ===== إعدادات العملات الرقمية الافتراضية =====
        await client.query(`
            INSERT INTO crypto_settings (id, is_enabled) VALUES (1, 0)
        `);

        // ===== العملات الرقمية المدعومة =====
        const supportedCurrencies = [
            ['USDT', 'Tether USD', 'USDT', 'BSC', 1, 100000, 1, 8, 0],
            ['BTC', 'Bitcoin', 'BTC', 'BTC', 10, 100000, 2, 8, 0],
            ['ETH', 'Ethereum', 'ETH', 'ERC20', 10, 100000, 3, 8, 0],
            ['BNB', 'BNB', 'BNB', 'BSC', 10, 100000, 4, 8, 1]
        ];

        for (const curr of supportedCurrencies) {
            await client.query(`
                INSERT INTO crypto_currencies 
                (currency_key, name, symbol, network, min_amount, max_amount, is_enabled, priority, decimals, is_internal)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            `, curr);
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
            `UPDATE site_settings SET value = $1, updated_at = CURRENT_TIMESTAMP WHERE key = $2`,
            [value, key]
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
// ===== نظام الدفع =====
// =============================================

// ===== إعدادات الدفع =====
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
        
        const settings = {};
        res.rows.forEach(row => {
            const key = row.key.replace('payment_', '');
            const parts = key.split('_');
            const method = parts[0];
            const field = parts.slice(1).join('_');
            
            if (!settings[method]) {
                settings[method] = {};
            }
            
            let value = row.value;
            if (value === 'true') value = true;
            else if (value === 'false') value = false;
            else if (!isNaN(value) && value !== '') value = parseFloat(value);
            
            settings[method][field] = value;
        });
        
        for (const [method, defaults] of Object.entries(PAYMENT_SETTINGS)) {
            if (settings[method]) {
                PAYMENT_SETTINGS[method] = { ...defaults, ...settings[method] };
            }
        }
        
        return PAYMENT_SETTINGS;
    } catch (error) {
        console.error('❌ خطأ في تحميل إعدادات الدفع:', error);
        return PAYMENT_SETTINGS;
    }
}

// ===== حفظ إعدادات الدفع =====
async function savePaymentSetting(method, key, value) {
    const settingKey = `payment_${method}_${key}`;
    await pool.query(
        `INSERT INTO site_settings (key, value) VALUES ($1, $2) 
         ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = CURRENT_TIMESTAMP`,
        [settingKey, String(value)]
    );
    PAYMENT_SETTINGS[method][key] = value;
}

// ===== المعاملات المؤقتة =====
const pendingVerifications = new Map();
const processedTxids = new Set();
const processingLocks = new Map();

// ===== العملات الرقمية المدعومة =====
const SUPPORTED_CURRENCIES = {
    USDT: { name: 'Tether USD', symbol: 'USDT', network: 'BSC', min_usd: 1, max_usd: 100000, priority: 1, decimals: 8, is_internal: false },
    BTC: { name: 'Bitcoin', symbol: 'BTC', network: 'BTC', min_usd: 10, max_usd: 100000, priority: 2, decimals: 8, is_internal: false },
    ETH: { name: 'Ethereum', symbol: 'ETH', network: 'ERC20', min_usd: 10, max_usd: 100000, priority: 3, decimals: 8, is_internal: false },
    BNB: { name: 'BNB', symbol: 'BNB', network: 'BSC', min_usd: 10, max_usd: 100000, priority: 4, decimals: 8, is_internal: true }
};

// =============================================
// ===== دوال التحقق من المعاملات =====
// =============================================

// ===== التحقق من ShamCash API =====
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
        const result = await mockShamCashAPI(txid, settings.account_address, settings.api_key);
        
        if (!result.success) {
            return result;
        }
        
        const apiAmount = result.amount;
        const apiCurrency = result.currency;
        
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
        
        return {
            success: true,
            txid: txid,
            original_amount: apiAmount,
            currency: apiCurrency,
            status: 'completed',
            timestamp: result.timestamp || Date.now(),
            sender: result.sender || 'غير معروف',
            receiver: settings.account_address,
            code: 'SUCCESS'
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

// ===== محاكاة ShamCash API =====
async function mockShamCashAPI(txid, accountAddress, apiKey) {
    return new Promise((resolve) => {
        setTimeout(() => {
            if (txid.startsWith('SHAM_')) {
                const parts = txid.split('_');
                const amount = parseFloat(parts[1]) || 100;
                const currency = parts[2] || 'SYP';
                resolve({
                    success: true,
                    amount: amount,
                    currency: currency === 'USD' ? 'USD' : 'SYP',
                    sender: 'محول',
                    timestamp: Date.now()
                });
            } else {
                resolve({
                    success: false,
                    message: '❌ رقم العملية غير موجود',
                    code: 'TX_NOT_FOUND'
                });
            }
        }, 2000);
    });
}

// ===== التحقق من Syriatel Cash API =====
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
        const result = await mockSyriatelAPI(txid, settings.api_key, settings.gsm_numbers);
        
        if (!result.success) {
            return result;
        }
        
        const apiAmount = result.amount;
        
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
            gsm: result.gsm,
            sender: result.sender || 'غير معروف',
            code: 'SUCCESS'
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

// ===== محاكاة Syriatel API =====
async function mockSyriatelAPI(txid, apiKey, gsmNumbers) {
    return new Promise((resolve) => {
        setTimeout(() => {
            if (txid.startsWith('SYR_')) {
                const amount = parseFloat(txid.split('_')[1]) || 100;
                resolve({
                    success: true,
                    amount: amount,
                    gsm: gsmNumbers[0] || '0999999999',
                    sender: 'مرسل',
                    timestamp: Date.now()
                });
            } else {
                resolve({
                    success: false,
                    message: '❌ رقم العملية غير موجود',
                    code: 'TX_NOT_FOUND'
                });
            }
        }, 2000);
    });
}

// =============================================
// ===== دوال العملات الرقمية =====
// =============================================

// ===== جلب عنوان الإيداع =====
async function getCryptoAddress(currencyKey) {
    try {
        const res = await pool.query(
            'SELECT address, memo FROM crypto_addresses WHERE currency_key = $1',
            [currencyKey]
        );
        return res.rows[0] || null;
    } catch (error) {
        console.error('❌ خطأ في جلب عنوان العملة:', error);
        return null;
    }
}

// ===== حفظ عنوان الإيداع =====
async function saveCryptoAddress(currencyKey, symbol, network, address, memo = '') {
    try {
        await pool.query(`
            INSERT INTO crypto_addresses (currency_key, symbol, network, address, memo, updated_at)
            VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
            ON CONFLICT (currency_key) DO UPDATE SET 
                symbol = $2, network = $3, address = $4, memo = $5, updated_at = CURRENT_TIMESTAMP
        `, [currencyKey, symbol, network, address, memo]);
        return true;
    } catch (error) {
        console.error('❌ خطأ في حفظ عنوان العملة:', error);
        return false;
    }
}

// ===== جلب سعر العملة =====
async function getCryptoPrice(currency) {
    if (currency === 'USDT') return 1.0;
    
    try {
        const res = await pool.query(
            'SELECT value FROM site_settings WHERE key = $1',
            [`crypto_price_${currency}`]
        );
        if (res.rows.length > 0) {
            return parseFloat(res.rows[0].value) || 0;
        }
        return 0;
    } catch (error) {
        console.error('❌ خطأ في جلب سعر العملة:', error);
        return 0;
    }
}

// ===== حساب كمية العملة =====
function getCryptoAmount(amountUsd, currency) {
    if (currency === 'USDT') return amountUsd;
    const price = SUPPORTED_CURRENCIES[currency]?.price || 0;
    if (price <= 0) return 0;
    return amountUsd / price;
}

// ===== حساب البونص =====
async function calculateBonus(userId, amount, method) {
    const settings = PAYMENT_SETTINGS[method];
    const bonusPercent = settings.bonus_percent || 0;
    
    if (bonusPercent <= 0) {
        return { bonusAmount: 0, bonusPercent: 0, bonusType: null };
    }
    
    const bonusAmount = amount * (bonusPercent / 100);
    
    return {
        bonusAmount: bonusAmount,
        bonusPercent: bonusPercent,
        bonusType: `auto_${method}`
    };
}

// =============================================
// ===== معالجة الدفع =====
// =============================================

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
        const exchangeRate = settings.exchange_rate;
        const convertedAmount = originalAmount * exchangeRate;
        
        const bonus = await calculateBonus(userId, convertedAmount, method);
        const finalAmount = convertedAmount + bonus.bonusAmount;
        
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
                bonus.bonusAmount || 0,
                bonus.bonusPercent || 0,
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
            bonus_amount: bonus.bonusAmount || 0,
            bonus_percent: bonus.bonusPercent || 0,
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
// ===== معالجة الدفع بالعملات الرقمية =====
// =============================================

async function processCryptoPayment(userId, currencyKey, amountUsd, txid) {
    console.log(`💰 [Crypto] معالجة: user=${userId}, currency=${currencyKey}, amount=${amountUsd}, txid=${txid}`);
    
    const currency = SUPPORTED_CURRENCIES[currencyKey];
    if (!currency) {
        return { success: false, message: '❌ عملة غير مدعومة', code: 'UNSUPPORTED_CURRENCY' };
    }
    
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
        const settings = await pool.query(
            'SELECT is_enabled, bonus_percent FROM crypto_settings WHERE id = 1'
        );
        const cryptoSettings = settings.rows[0] || { is_enabled: 0, bonus_percent: 0 };
        
        if (!cryptoSettings.is_enabled) {
            return { success: false, message: '❌ نظام العملات الرقمية معطل', code: 'DISABLED' };
        }
        
        if (amountUsd < currency.min_usd) {
            return {
                success: false,
                message: `❌ أقل من الحد الأدنى ($${currency.min_usd})`,
                code: 'BELOW_MIN'
            };
        }
        
        if (amountUsd > currency.max_usd) {
            return {
                success: false,
                message: `❌ أكبر من الحد الأقصى ($${currency.max_usd})`,
                code: 'ABOVE_MAX'
            };
        }
        
        const exchangeRate = 13000; // سعر الصرف الافتراضي
        const amountSyp = amountUsd * exchangeRate;
        
        const bonusPercent = cryptoSettings.bonus_percent || 0;
        const bonusAmount = amountSyp * (bonusPercent / 100);
        const finalAmount = amountSyp + bonusAmount;
        
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
        
        const cryptoAmount = getCryptoAmount(amountUsd, currencyKey);
        
        await pool.query(
            `INSERT INTO transactions (user_id, username, type, amount, method, txid, bonus_amount, bonus_percent, old_balance, new_balance, status, details)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
            [
                user.id,
                user.username,
                'deposit',
                finalAmount,
                `عملة رقمية ${currency.name}`,
                txid,
                bonusAmount,
                bonusPercent,
                oldBalance,
                newBalance,
                'completed',
                `إيداع عبر ${currency.name} - المبلغ: ${cryptoAmount} ${currency.symbol}`
            ]
        );
        
        await pool.query(
            `INSERT INTO activity_logs (user_id, username, action, details) 
             VALUES ($1, $2, $3, $4)`,
            [user.id, user.username, 'crypto_deposit', 
             `إيداع عبر ${currency.name} - المبلغ: ${finalAmount} - رقم العملية: ${txid}`]
        );
        
        return {
            success: true,
            txid: txid,
            original_amount: amountUsd,
            currency: 'USD',
            crypto_amount: cryptoAmount,
            crypto_symbol: currency.symbol,
            converted_amount: amountSyp,
            final_amount: finalAmount,
            bonus_amount: bonusAmount,
            bonus_percent: bonusPercent,
            old_balance: oldBalance,
            new_balance: newBalance,
            method: `عملة رقمية ${currency.name}`,
            code: 'SUCCESS'
        };
        
    } catch (error) {
        console.error('❌ خطأ في معالجة الدفع بالعملات الرقمية:', error);
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

// ===== التحقق من صحة الخادم =====
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ===== جلب إعدادات الموقع (عام) =====
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        console.error('❌ خطأ في جلب الإعدادات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

// ===== تسجيل مستخدم جديد =====
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip;
        const userAgent = req.headers['user-agent'];

        console.log('📝 محاولة تسجيل:', { username, ip });

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

        console.log('✅ تم إنشاء الحساب:', username);

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

        console.log('📝 محاولة دخول:', { username, ip });

        if (!username || !password) {
            return res.status(400).json({ error: 'يرجى ملء جميع الحقول' });
        }

        const user = await db.findUser(username);
        if (!user) {
            console.log('❌ مستخدم غير موجود:', username);
            return res.status(401).json({ error: 'بيانات غير صحيحة' });
        }
        if (!user.is_active) {
            console.log('❌ حساب معطل:', username);
            return res.status(403).json({ error: 'الحساب معطل' });
        }

        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            console.log('❌ كلمة مرور خاطئة:', username);
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

        console.log('✅ تم تسجيل الدخول:', username);

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

// ===== جلب رصيد المستخدم =====
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
        const settings = await loadPaymentSettings();
        const safeSettings = {};
        for (const [key, value] of Object.entries(settings)) {
            safeSettings[key] = {
                name: value.name,
                enabled: value.enabled,
                min_amount: value.min_amount,
                max_amount: value.max_amount,
                exchange_rate: value.exchange_rate,
                currency: value.currency,
                bonus_percent: value.bonus_percent
            };
        }
        res.json(safeSettings);
    } catch (error) {
        console.error('❌ خطأ في جلب إعدادات الدفع:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
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
        
        res.json({
            message: 'تم تحديث الإعداد',
            method: method,
            key: key,
            value: value
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
// ===== API Routes للعملات الرقمية =====
// =============================================

// ===== جلب العملات المتاحة =====
app.get('/api/crypto/currencies', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM crypto_currencies WHERE is_enabled = 1 ORDER BY priority ASC'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('❌ خطأ في جلب العملات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب العملات' });
    }
});

// ===== جلب عنوان الإيداع =====
app.get('/api/crypto/address/:currency', async (req, res) => {
    try {
        const { currency } = req.params;
        const address = await getCryptoAddress(currency);
        
        if (!address) {
            return res.status(404).json({ error: 'عنوان غير متوفر' });
        }
        
        res.json(address);
    } catch (error) {
        console.error('❌ خطأ في جلب العنوان:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب العنوان' });
    }
});

// ===== تحديث عنوان الإيداع (للمشرفين) =====
app.post('/api/crypto/address', verifyAdmin, async (req, res) => {
    try {
        const { currency, address, memo } = req.body;
        
        if (!currency || !address) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }
        
        const currencyInfo = SUPPORTED_CURRENCIES[currency];
        if (!currencyInfo) {
            return res.status(400).json({ error: 'عملة غير مدعومة' });
        }
        
        await saveCryptoAddress(currency, currencyInfo.symbol, currencyInfo.network, address, memo || '');
        
        res.json({ message: 'تم تحديث العنوان بنجاح' });
    } catch (error) {
        console.error('❌ خطأ في تحديث العنوان:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث العنوان' });
    }
});

// ===== تقديم طلب إيداع بالعملات الرقمية =====
app.post('/api/crypto/deposit', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'غير مصرح' });
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        const { currency, amount, txid } = req.body;
        
        if (!currency || !amount || !txid) {
            return res.status(400).json({ error: 'بيانات غير مكتملة' });
        }
        
        if (!SUPPORTED_CURRENCIES[currency]) {
            return res.status(400).json({ error: 'عملة غير مدعومة' });
        }
        
        const result = await processCryptoPayment(decoded.id, currency, amount, txid);
        
        if (result.success) {
            res.json(result);
        } else {
            res.status(400).json(result);
        }
        
    } catch (error) {
        console.error('❌ خطأ في معالجة الإيداع بالعملات الرقمية:', error);
        res.status(500).json({ error: 'حدث خطأ في معالجة الإيداع' });
    }
});

// ===== جلب إعدادات العملات الرقمية (للمشرفين) =====
app.get('/api/crypto/settings', verifyAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM crypto_settings WHERE id = 1');
        res.json(result.rows[0] || {});
    } catch (error) {
        console.error('❌ خطأ في جلب إعدادات العملات الرقمية:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

// ===== تحديث إعدادات العملات الرقمية (للمشرفين) =====
app.post('/api/crypto/settings', verifyAdmin, async (req, res) => {
    try {
        const { is_enabled, api_key, api_secret, internal_address, bonus_enabled, bonus_percent } = req.body;
        
        await pool.query(`
            UPDATE crypto_settings SET 
                is_enabled = $1,
                api_key = $2,
                api_secret = $3,
                internal_address = $4,
                bonus_enabled = $5,
                bonus_percent = $6,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
        `, [is_enabled || 0, api_key || '', api_secret || '', internal_address || '', bonus_enabled || 0, bonus_percent || 0]);
        
        res.json({ message: 'تم تحديث الإعدادات بنجاح' });
    } catch (error) {
        console.error('❌ خطأ في تحديث إعدادات العملات الرقمية:', error);
        res.status(500).json({ error: 'حدث خطأ في تحديث الإعدادات' });
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

// ===== جلب الإحصائيات =====
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

// ===== جلب المستخدمين =====
app.get('/api/admin/users', verifyAdmin, async (req, res) => {
    try {
        const users = await db.getUsers();
        res.json(users);
    } catch (error) {
        console.error('❌ خطأ في جلب المستخدمين:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب المستخدمين' });
    }
});

// ===== تحديث رصيد المستخدم =====
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

// ===== جلب سجل النشاطات =====
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

// ===== جلب المعاملات (للمشرفين) =====
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

// ===== جلب إعدادات الموقع (للأدمن) =====
app.get('/api/admin/settings', verifyAdmin, async (req, res) => {
    try {
        const settings = await db.getSettings();
        res.json(settings);
    } catch (error) {
        console.error('❌ خطأ في جلب الإعدادات:', error);
        res.status(500).json({ error: 'حدث خطأ في جلب الإعدادات' });
    }
});

// ===== تحديث إعدادات الموقع =====
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
            console.log('📋 جميع نقاط النهاية:');
            console.log('   POST /api/register - تسجيل مستخدم جديد');
            console.log('   POST /api/login - تسجيل الدخول');
            console.log('   POST /api/verify - التحقق من التوكن');
            console.log('   GET  /api/balance - جلب الرصيد');
            console.log('   POST /api/logout - تسجيل الخروج');
            console.log('   GET  /api/settings - جلب الإعدادات');
            console.log('   --- الدفع ---');
            console.log('   GET  /api/payment/settings - جلب إعدادات الدفع');
            console.log('   POST /api/payment/deposit - تقديم طلب إيداع');
            console.log('   GET  /api/payment/status/:txid - التحقق من حالة المعاملة');
            console.log('   --- العملات الرقمية ---');
            console.log('   GET  /api/crypto/currencies - جلب العملات المتاحة');
            console.log('   GET  /api/crypto/address/:currency - جلب عنوان الإيداع');
            console.log('   POST /api/crypto/deposit - تقديم طلب إيداع بالعملات الرقمية');
            console.log('   --- ADMIN ---');
            console.log('   GET  /api/admin/stats - الإحصائيات');
            console.log('   GET  /api/admin/users - قائمة المستخدمين');
            console.log('   POST /api/admin/update-balance - تحديث الرصيد');
            console.log('   POST /api/admin/toggle-user - تعطيل/تفعيل');
            console.log('   DELETE /api/admin/delete-user - حذف مستخدم');
            console.log('   GET  /api/admin/logs - سجل النشاطات');
            console.log('   GET  /api/admin/transactions - المعاملات');
            console.log('   GET  /api/admin/settings - جلب الإعدادات');
            console.log('   POST /api/admin/settings - تحديث الإعدادات');
            console.log('   POST /api/payment/settings - تحديث إعدادات الدفع');
            console.log('   GET  /api/crypto/settings - جلب إعدادات العملات الرقمية');
            console.log('   POST /api/crypto/settings - تحديث إعدادات العملات الرقمية');
            console.log('   POST /api/crypto/address - تحديث عنوان الإيداع\n');
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
