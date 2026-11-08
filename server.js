const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.static(path.join(__dirname, 'public')));;
const upload = multer({ storage: multer.memoryStorage() });

// PostgreSQL connection pool
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'iss-ds',
    password: '081806',
    port: 5432,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use('/repository', express.static(path.join(__dirname, 'repository')));
app.use(session({
    secret: 'iss_ds_super_secret_key',
    resave: false,
    saveUninitialized: false
}));

// Middleware to protect routes (FR-011)
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        next();
    } else {
        res.redirect('/login');
    }
}

app.get('/documents', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'documents.html'));
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/', (req, res) => {
    res.redirect('/login');
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Protect the UI Pages
app.get('/upload', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'upload.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

app.get('/activity-log', requireAuth, (req, res) => {
    if (req.session.role !== 'Administrator' && req.session.role !== 'President') {
        // Redirects to dashboard with an error flag instead of a raw alert
        return res.redirect('/dashboard?error=activity_denied');
    }
    res.sendFile(path.join(__dirname, 'activity-log.html'));
});

app.get('/admin', requireAuth, (req, res) => {
    if (req.session.role !== 'Administrator') {
        // Redirects to dashboard with an error flag instead of a raw alert
        return res.redirect('/dashboard?error=admin_denied');
    }
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// API: Documents Search & Filter
app.get('/api/documents', requireAuth, async (req, res) => {
    const { keyword, category } = req.query;
    const userRole = req.session.role;
    
    let queryText = `
        SELECT d.id, d.title, d.category, d.document_date, 
               d.approval_status, d.approver, d.approval_date,
               dv.version_number, dv.standardized_file_name
        FROM Document d
        JOIN DocumentVersion dv ON d.id = dv.document_id
        WHERE dv.version_number = (
            SELECT MAX(version_number) FROM DocumentVersion WHERE document_id = d.id
        )
    `;
    const params = [];
    let paramIndex = 1;

    if (userRole === 'Officer') {
        queryText += ` AND d.category != 'Finance'`;
    }

    if (keyword) {
        queryText += ` AND (d.title ILIKE $${paramIndex} OR d.category ILIKE $${paramIndex})`;
        params.push(`%${keyword}%`);
        paramIndex++;
    }
    
    if (category) {
        queryText += ` AND d.category = $${paramIndex}`;
        params.push(category);
        paramIndex++;
    }

    queryText += ` ORDER BY d.document_date DESC`;

    try {
        const client = await pool.connect();
        const result = await client.query(queryText, params);
        client.release();
        
        res.json({ userRole: req.session.role, documents: result.rows });
    } catch (error) {
        console.error('Search Error:', error);
        res.status(500).send('Server error during search.');
    }
});

// API: Upload Document
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
    const { title, category, date } = req.body;
    const file = req.file;
    const userId = req.session.userId;
    const userRole = req.session.role;

    if (!file || !title || !category || !date) {
        return res.status(400).send('Missing required fields.');
    }

    if (category === 'Finance' && userRole === 'Officer') {
    return res.status(403).send('Access Denied: Only Treasurer, President, or Admin can upload Finance documents.');
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN'); 

        let docQuery = await client.query(`SELECT id FROM Document WHERE title = $1 AND category = $2`, [title, category]);
        let documentId;
        let newVersion = 1;

        if (docQuery.rows.length > 0) {
            documentId = docQuery.rows[0].id;
            const versionQuery = await client.query(`SELECT MAX(version_number) as max_v FROM DocumentVersion WHERE document_id = $1`, [documentId]);
            newVersion = (versionQuery.rows[0].max_v || 0) + 1;
        } else {
            const newDoc = await client.query(`INSERT INTO Document (title, category, document_date) VALUES ($1, $2, $3) RETURNING id`, [title, category, date]);
            documentId = newDoc.rows[0].id;
        }

        const extension = path.extname(file.originalname);
        const safeTitle = title.replace(/[^a-zA-Z0-9]/g, '_'); 
        const standardizedFileName = `${category}_${safeTitle}_${date}_v${newVersion}${extension}`;
        
        const repositoryPath = path.join(__dirname, 'repository', category);
        if (!fs.existsSync(repositoryPath)){
            fs.mkdirSync(repositoryPath, { recursive: true });
        }
        
        const finalFilePath = path.join(repositoryPath, standardizedFileName);
        fs.writeFileSync(finalFilePath, file.buffer); 

        await client.query(`INSERT INTO DocumentVersion (document_id, version_number, standardized_file_name, file_path, uploaded_by) VALUES ($1, $2, $3, $4, $5)`, [documentId, newVersion, standardizedFileName, finalFilePath, userId]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Upload Document', documentId, `Version ${newVersion} uploaded`]);

        await client.query('COMMIT');
        res.status(200).send(`Successfully uploaded version ${newVersion}: ${standardizedFileName}. <br><br><a href="/dashboard">Return to Dashboard</a>`);

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Upload Error:', error);
        res.status(500).send('Server error during upload.');
    } finally {
        client.release();
    }
});

// API: Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT * FROM UserAccount WHERE username = $1', [username]);
        
        if (result.rows.length > 0) {
            const user = result.rows[0];
            let isValid = false;

            if (user.password_hash === 'password123' && password === 'password123') {
                isValid = true;
                const hashed = await bcrypt.hash(password, 10);
                await client.query('UPDATE UserAccount SET password_hash = $1 WHERE id = $2', [hashed, user.id]);
            } else {
                isValid = await bcrypt.compare(password, user.password_hash);
            }

            if (isValid) {
                req.session.userId = user.id;
                req.session.role = user.access_level;
                await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, result) VALUES ($1, $2, $3)`, [user.id, 'Login', 'Success']);
                client.release();
                return res.redirect('/dashboard');
            }
        }
        client.release();
        res.redirect('/login?error=1');
        
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).send('Server error during login.');
    }
});

// API: Activity Log
app.get('/api/activity', requireAuth, async (req, res) => {
    const role = req.session.role;
    if (role !== 'Administrator' && role !== 'President') return res.status(403).send('Access Denied');

    const queryText = `
        SELECT a.id, a.action_date, u.username, a.action_type, a.document_id, a.result
        FROM ActivityLogEntry a
        JOIN UserAccount u ON a.user_id = u.id
        ORDER BY a.action_date DESC
        LIMIT 100
    `;

    try {
        const client = await pool.connect();
        const result = await client.query(queryText);
        client.release();
        res.json(result.rows);
    } catch (error) {
        console.error('Activity Log Error:', error);
        res.status(500).send('Server error fetching activity log.');
    }
});

// API: Users Management
app.get('/api/users', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).send('Access Denied');
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT id, full_name, username, access_level, status, date_created FROM UserAccount ORDER BY date_created DESC');
        client.release();
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Server error');
    }
});

app.post('/api/users', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).send('Access Denied');
    
    const { full_name, username, password, access_level } = req.body;
    if (!full_name || !username || !password || !access_level) return res.status(400).send('Missing required fields.');

    try {
        const client = await pool.connect();
        const checkUser = await client.query('SELECT id FROM UserAccount WHERE username = $1', [username]);
        
        if (checkUser.rows.length > 0) {
            client.release();
            return res.status(400).send('Username already exists.');
        }

        const hashed = await bcrypt.hash(password, 10);
        await client.query('BEGIN');
        const newUser = await client.query(`INSERT INTO UserAccount (full_name, username, password_hash, access_level) VALUES ($1, $2, $3, $4) RETURNING id`, [full_name, username, hashed, access_level]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, result) VALUES ($1, $2, $3)`, [req.session.userId, 'Create Account', `Created ${access_level} account: ${username}`]);
        await client.query('COMMIT');
        client.release();
        
        res.redirect('/admin');
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).send('Server error');
    }
});

// API: Approve Document
app.post('/api/approve/:id', requireAuth, async (req, res) => {
    if (req.session.role !== 'President') return res.status(403).send('Access Denied: Only the President can approve documents.');
    const docId = req.params.id;
    const userId = req.session.userId;

    try {
        const client = await pool.connect();
        const userRes = await client.query('SELECT username FROM UserAccount WHERE id = $1', [userId]);
        const approverName = userRes.rows[0].username;

        await client.query(`UPDATE Document SET approval_status = 'Approved', approver = $1, approval_date = CURRENT_TIMESTAMP WHERE id = $2`, [approverName, docId]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Approve Document', docId, 'Document marked as Approved']);

        client.release();
        res.status(200).send('Document approved.');
    } catch (error) {
        console.error('Approval Error:', error);
        res.status(500).send('Server error during approval.');
    }
});

// API: Update User Access Level
app.put('/api/users/:id/role', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).json({ success: false, error: 'Access Denied' });
    const userId = req.params.id;
    const { newRole } = req.body;
    
    try {
        await pool.query('UPDATE UserAccount SET access_level = $1 WHERE id = $2', [newRole, userId]);
        res.json({ success: true, message: 'Role updated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Database error' });
    }
});

// API: Deactivate User
app.put('/api/users/:id/deactivate', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).json({ success: false, error: 'Access Denied' });
    const userId = req.params.id;
    
    try {
        await pool.query("UPDATE UserAccount SET status = 'inactive' WHERE id = $1", [userId]);
        res.json({ success: true, message: 'User deactivated successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Database error' });
    }
});

// API: Reset Password
app.put('/api/users/:id/reset-password', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).json({ success: false, error: 'Access Denied' });
    const userId = req.params.id;
    const { newPassword } = req.body;
    
    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE UserAccount SET password_hash = $1 WHERE id = $2', [hashedPassword, userId]);
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, error: 'Database error' });
    }
});

app.get('/api/current-user', (req, res) => {
    // Correctly checks the session variable you set during login
    if (req.session && req.session.role) {
        res.json({ role: req.session.role });
    } else {
        res.json({ role: 'User' }); // Fallback
    }
});

app.listen(3000, () => console.log('ISS-DS Backend running on port 3000'));