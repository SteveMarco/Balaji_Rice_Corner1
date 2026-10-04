const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rice_shop_secure_jwt_secret_key_2026';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database Setup
const db = new sqlite3.Database('./database.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

// Initialize Database Tables & Default Admin Account
db.serialize(() => {
    // Users Table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT CHECK(role IN ('admin', 'customer')) DEFAULT 'customer',
            status TEXT CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Brands / Inventory Table
    db.run(`
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            brand_name TEXT NOT NULL,
            description TEXT,
            bag_size TEXT NOT NULL,
            price REAL NOT NULL,
            stock_bags INTEGER NOT NULL,
            low_stock_threshold INTEGER DEFAULT 10,
            image_url TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Orders Table
    db.run(`
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            total_amount REAL NOT NULL,
            delivery_fee REAL DEFAULT 55.0,
            payment_method TEXT CHECK(payment_method IN ('cash', 'online')),
            order_status TEXT DEFAULT 'completed',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(customer_id) REFERENCES users(id)
        )
    `);

    // Auto-create Default Admin Account if missing
    db.get(`SELECT * FROM users WHERE role = 'admin'`, async (err, row) => {
        if (err) {
            console.error('Error checking admin user:', err);
            return;
        }
        if (!row) {
            const defaultPasswordHash = await bcrypt.hash('admin123', 10);
            db.run(
                `INSERT INTO users (name, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, 'admin', 'approved')`,
                ['Store Admin', 'admin@riceshop.com', '0000000000', defaultPasswordHash],
                (err) => {
                    if (err) console.error('Failed to create default admin:', err.message);
                    else console.log('--> Default Admin Created: admin@riceshop.com / admin123');
                }
            );
        }
    });
});

// Auth Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token.' });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin authorization required.' });
    }
    next();
}

// -------------------------------------------------------------
// USER AUTHENTICATION & APPROVAL ROUTES
// -------------------------------------------------------------

// Customer Registration
app.post('/api/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) {
        return res.status(400).json({ error: 'All fields are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO users (name, email, phone, password_hash, role, status) VALUES (?, ?, ?, ?, 'customer', 'pending')`;
        
        db.run(query, [name, email, phone, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Email address already registered.' });
                }
                return res.status(500).json({ error: 'Failed to create user.' });
            }
            res.json({ message: 'Account created! Please wait for Admin approval before logging in.' });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// User / Admin Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required.' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        if (user.role === 'customer' && user.status !== 'approved') {
            return res.status(403).json({ 
                error: `Account is currently ${user.status}. Please await admin approval.` 
            });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role, name: user.name, email: user.email }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        res.json({ 
            token, 
            role: user.role, 
            name: user.name,
            message: 'Login successful'
        });
    });
});

// Admin: Get Pending User Approvals
app.get('/api/admin/pending-users', authenticateToken, requireAdmin, (req, res) => {
    db.all(`SELECT id, name, email, phone, status, created_at FROM users WHERE status = 'pending'`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to fetch pending users.' });
        res.json(rows || []);
    });
});

// Admin: Approve or Reject User Account
app.post('/api/admin/approve-user', authenticateToken, requireAdmin, (req, res) => {
    const { userId, status } = req.body;
    if (!userId || !['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid user ID or status choice.' });
    }

    db.run(`UPDATE users SET status = ? WHERE id = ?`, [status, userId], function(err) {
        if (err) return res.status(500).json({ error: 'Database update failed.' });
        res.json({ message: `User status successfully updated to ${status}.` });
    });
});

// Admin: Update Credentials
app.post('/api/admin/update-credentials', authenticateToken, requireAdmin, async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) {
        return res.status(400).json({ error: 'New email and new password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(
            `UPDATE users SET email = ?, password_hash = ? WHERE id = ? AND role = 'admin'`, 
            [email, hashedPassword, req.user.id], 
            function(err) {
                if (err) return res.status(500).json({ error: 'Failed to update credentials.' });
                res.json({ message: 'Admin credentials updated successfully. Please log in again.' });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Failed to hash password.' });
    }
});

// -------------------------------------------------------------
// RICE BRANDS & INVENTORY MANAGEMENT
// -------------------------------------------------------------

// Fetch All Rice Brands (Authenticated Users Only)
app.get('/api/brands', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM brands ORDER BY id DESC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Failed to retrieve rice brands.' });
        res.json(rows || []);
    });
});

// Admin: Add New Rice Brand
app.post('/api/admin/brands', authenticateToken, requireAdmin, (req, res) => {
    const { brand_name, description, bag_size, price, stock_bags, low_stock_threshold, image_url } = req.body;

    if (!brand_name || !bag_size || price === undefined || stock_bags === undefined) {
        return res.status(400).json({ error: 'Missing required brand fields.' });
    }

    const query = `
        INSERT INTO brands (brand_name, description, bag_size, price, stock_bags, low_stock_threshold, image_url)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;

    db.run(
        query, 
        [brand_name, description, bag_size, price, stock_bags, low_stock_threshold || 10, image_url], 
        function(err) {
            if (err) return res.status(500).json({ error: 'Failed to insert brand.' });
            res.json({ message: 'New rice brand published to stock catalog!', brandId: this.lastID });
        }
    );
});

// -------------------------------------------------------------
// ANALYTICS & LOW STOCK REPORTS
// -------------------------------------------------------------

// Admin: Analytics & Low Stock Summary
app.get('/api/admin/analytics', authenticateToken, requireAdmin, (req, res) => {
    const report = {
        totalSales: 0,
        totalOrders: 0,
        lowStockItems: []
    };

    db.get(`SELECT SUM(total_amount) as total_sales, COUNT(*) as order_count FROM orders`, [], (err, row) => {
        if (!err && row) {
            report.totalSales = row.total_sales || 0;
            report.totalOrders = row.order_count || 0;
        }

        db.all(`SELECT * FROM brands WHERE stock_bags <= low_stock_threshold`, [], (err, lowStockRows) => {
            if (!err) {
                report.lowStockItems = lowStockRows || [];
            }
            res.json(report);
        });
    });
});

// Start Express Server
app.listen(PORT, () => {
    console.log(`===========================================`);
    console.log(`Rice Shop Web Application live on port ${PORT}`);
    console.log(`Access Landing Page: http://localhost:${PORT}`);
    console.log(`===========================================`);
});
