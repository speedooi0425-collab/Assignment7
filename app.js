const express = require('express');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2/promise'); // Using mysql2 for parameterized queries
const app = express();

app.use(express.json());

// 1. INPUT VALIDATION & SQL INJECTION PREVENTION
app.post('/api/vault/login', 
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;
        
        try {
            // SECURE: Parameterized Query (prevents SQL Injection)
            const [rows] = await db.execute(
                'SELECT * FROM users WHERE email = ? AND password = ?', 
                [email, password]
            );
            
            if (rows.length > 0) {
                res.status(200).json({ message: "Access Granted" });
            } else {
                res.status(401).json({ message: "Invalid Credentials" });
            }
        } catch (err) {
            res.status(500).send("Server Error");
        }
});

// 2. AUTHENTICATION & ROLE-BASED ACCESS CONTROL (RBAC)
const checkRole = (role) => {
    return (req, res, next) => {
        // Mocking a user role from a JWT or Session
        const userRole = req.headers['x-user-role']; 
        if (userRole !== role) {
            return res.status(403).json({ message: "Forbidden: Higher clearance required" });
        }
        next();
    };
};

app.get('/api/vault/admin-data', checkRole('admin'), (req, res) => {
    res.json({ secretData: "This is only visible to Admin users." });
});

app.listen(3000, () => console.log('SafeVault Secure Server running on 3000'));
