const cron = require('node-cron');
const archiver = require('archiver');
const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

// PostgreSQL connection pool
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'iss-ds',
    password: '081806',
    port: 5432,
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
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

// Helper: Database Export JSON structure for backups
async function getDatabaseExport() {
    const client = await pool.connect();
    try {
        const users = await client.query('SELECT id, full_name, username, access_level, status, date_created FROM UserAccount');
        const docs = await client.query('SELECT * FROM Document');
        const docVersions = await client.query('SELECT * FROM DocumentVersion');
        const activity = await client.query('SELECT * FROM ActivityLogEntry');

        return {
            export_date: new Date().toISOString(),
            UserAccount: users.rows,
            Document: docs.rows,
            DocumentVersion: docVersions.rows,
            ActivityLogEntry: activity.rows
        };
    } finally {
        client.release();
    }
}

/* ==========================================================================
   VIEW ROUTES (HTML PAGES)
   ========================================================================== */

app.get('/', (req, res) => res.redirect('/login'));

app.get('/login', (req, res) => {
    const loginPath = fs.existsSync(path.join(__dirname, 'public', 'login.html'))
        ? path.join(__dirname, 'public', 'login.html')
        : path.join(__dirname, 'login.html');
    res.sendFile(loginPath);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/dashboard', requireAuth, (req, res) => {
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'dashboard.html'))
        ? path.join(__dirname, 'public', 'dashboard.html')
        : path.join(__dirname, 'dashboard.html');
    res.sendFile(pagePath);
});

app.get('/upload', requireAuth, (req, res) => {
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'upload.html'))
        ? path.join(__dirname, 'public', 'upload.html')
        : path.join(__dirname, 'upload.html');
    res.sendFile(pagePath);
});

app.get('/documents', requireAuth, (req, res) => {
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'documents.html'))
        ? path.join(__dirname, 'public', 'documents.html')
        : path.join(__dirname, 'documents.html');
    res.sendFile(pagePath);
});

app.get('/activity-log', requireAuth, (req, res) => {
    if (req.session.role !== 'Administrator' && req.session.role !== 'President') {
        return res.redirect('/dashboard?error=activity_denied');
    }
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'activity-log.html'))
        ? path.join(__dirname, 'public', 'activity-log.html')
        : path.join(__dirname, 'activity-log.html');
    res.sendFile(pagePath);
});

app.get('/recycle-bin', requireAuth, (req, res) => {
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'recycle-bin.html'))
        ? path.join(__dirname, 'public', 'recycle-bin.html')
        : path.join(__dirname, 'recycle-bin.html');
    res.sendFile(pagePath);
});

app.get('/admin', requireAuth, (req, res) => {
    if (req.session.role !== 'Administrator') {
        return res.redirect('/dashboard?error=admin_denied');
    }
    const pagePath = fs.existsSync(path.join(__dirname, 'public', 'admin.html'))
        ? path.join(__dirname, 'public', 'admin.html')
        : path.join(__dirname, 'admin.html');
    res.sendFile(pagePath);
});

/* ==========================================================================
   AUTHENTICATION & USER APIs
   ========================================================================== */

// API: Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    let client;
    try {
        client = await pool.connect();
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
                return res.redirect('/dashboard');
            }
        }
        res.redirect('/login?error=1');
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).send('Server error during login.');
    } finally {
        if (client) client.release();
    }
});

app.get('/api/current-user', (req, res) => {
    if (req.session && req.session.role) {
        res.json({ role: req.session.role, userId: req.session.userId });
    } else {
        res.json({ role: 'User', userId: null });
    }
});

// API: User Management (Admin Only)
app.get('/api/users', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') return res.status(403).send('Access Denied');
    try {
        const result = await pool.query('SELECT id, full_name, username, access_level, status, date_created FROM UserAccount ORDER BY date_created DESC');
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

    let client;
    try {
        client = await pool.connect();
        const checkUser = await client.query('SELECT id FROM UserAccount WHERE username = $1', [username]);
        
        if (checkUser.rows.length > 0) {
            return res.status(400).send('Username already exists.');
        }

        const hashed = await bcrypt.hash(password, 10);
        await client.query('BEGIN');
        const newUser = await client.query(`INSERT INTO UserAccount (full_name, username, password_hash, access_level) VALUES ($1, $2, $3, $4) RETURNING id`, [full_name, username, hashed, access_level]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, result) VALUES ($1, $2, $3)`, [req.session.userId, 'Create Account', `Created ${access_level} account: ${username}`]);
        await client.query('COMMIT');
        
        res.redirect('/admin');
    } catch (error) {
        if (client) await client.query('ROLLBACK');
        console.error('Error creating user:', error);
        res.status(500).send('Server error');
    } finally {
        if (client) client.release();
    }
});

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

/* ==========================================================================
   DOCUMENT MANAGEMENT APIs
   ========================================================================== */

// API: Documents Search & Filter
app.get('/api/documents', requireAuth, async (req, res) => {
    const { keyword, category } = req.query;
    const userRole = req.session.role;
    
    let queryText = `
        SELECT d.id, d.title, d.category, d.subfolder, d.document_date, 
               d.approval_status, d.approver, d.approval_date,
               dv.version_number, dv.standardized_file_name
        FROM Document d
        JOIN DocumentVersion dv ON d.id = dv.document_id
        WHERE d.is_deleted = FALSE AND dv.version_number = (
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
        const result = await pool.query(queryText, params);
        res.json({ userRole: req.session.role, documents: result.rows });
    } catch (error) {
        console.error('Search Error:', error);
        res.status(500).send('Server error during search.');
    }
});

// API: Get Frequently Accessed Documents (FR-008)
app.get('/api/documents/frequent', requireAuth, async (req, res) => {
    const userRole = req.session.role;
    
    let queryText = `
        SELECT d.id, d.title, d.category, d.document_date, d.view_count,
               dv.version_number, dv.standardized_file_name
        FROM Document d
        JOIN DocumentVersion dv ON d.id = dv.document_id
        WHERE d.is_deleted = FALSE AND dv.version_number = (
            SELECT MAX(version_number) FROM DocumentVersion WHERE document_id = d.id
        )
    `;
    
    if (userRole === 'Officer') {
        queryText += ` AND d.category != 'Finance'`;
    }
    
    queryText += ` ORDER BY COALESCE(d.view_count, 0) DESC LIMIT 4`;
    
    try {
        const result = await pool.query(queryText);
        res.json({ documents: result.rows });
    } catch (error) {
        console.error('Frequent Docs Error:', error);
        res.status(500).send('Server error fetching frequent documents.');
    }
});

// API: Upload Document
app.post('/api/upload', requireAuth, upload.single('file'), async (req, res) => {
    const { title, category, date, subfolder } = req.body;
    const targetSubfolder = subfolder || 'General';
    const file = req.file;
    const userId = req.session.userId;
    const userRole = req.session.role;

    if (!file || !title || !category || !date) {
        return res.status(400).send('Missing required fields.');
    }

    if (category === 'Finance' && userRole === 'Officer') {
        return res.status(403).send('Access Denied: Only Treasurer, President, or Admin can upload Finance documents.');
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); 

        let docQuery = await client.query(`SELECT id FROM Document WHERE title = $1 AND category = $2 AND subfolder = $3`, [title, category, targetSubfolder]);
        let documentId;
        let newVersion = 1;

        if (docQuery.rows.length > 0) {
            documentId = docQuery.rows[0].id;
            const versionQuery = await client.query(`SELECT MAX(version_number) as max_v FROM DocumentVersion WHERE document_id = $1`, [documentId]);
            newVersion = (versionQuery.rows[0].max_v || 0) + 1;
        } else {
            const newDoc = await client.query(`INSERT INTO Document (title, category, subfolder, document_date) VALUES ($1, $2, $3, $4) RETURNING id`, [title, category, targetSubfolder, date]);
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
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Upload Document', documentId, `Version ${newVersion} uploaded to ${targetSubfolder}`]);

        await client.query('COMMIT');
        res.status(200).send('Uploaded successfully');
    } catch (error) {
        if (client) await client.query('ROLLBACK');
        console.error('Upload Error:', error);
        res.status(500).send('Server error during upload.');
    } finally {
        if (client) client.release();
    }
});

// API: Edit Document Metadata (FR-003)
app.put('/api/documents/:id', requireAuth, async (req, res) => {
    const docId = req.params.id;
    const { title, category, date } = req.body;
    const userRole = req.session.role;
    const userId = req.session.userId;

    if (!title || !category || !date) {
        return res.status(400).send('Missing required fields.');
    }

    if (category === 'Finance' && userRole === 'Officer') {
        return res.status(403).send('Access Denied: You do not have permission to use the Finance category.');
    }

    let client;
    try {
        client = await pool.connect();
        await client.query(`UPDATE Document SET title = $1, category = $2, document_date = $3 WHERE id = $4`, [title, category, date, docId]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Edit Document', docId, `Updated metadata to Category: ${category}`]);

        res.json({ success: true, message: 'Document updated successfully' });
    } catch (error) {
        console.error('Edit Error:', error);
        res.status(500).send('Server error during document update.');
    } finally {
        if (client) client.release();
    }
});

// API: Approve Document (President / Administrator)
const handleApproveDocument = async (req, res) => {
    if (req.session.role !== 'President' && req.session.role !== 'Administrator') {
        return res.status(403).send('Access Denied: Only President or Administrator can approve documents.');
    }
    const docId = req.params.id;
    const userId = req.session.userId;

    let client;
    try {
        client = await pool.connect();
        const userRes = await client.query('SELECT username FROM UserAccount WHERE id = $1', [userId]);
        const approverName = userRes.rows.length > 0 ? userRes.rows[0].username : req.session.role;

        await client.query(`UPDATE Document SET approval_status = 'Approved', approver = $1, approval_date = CURRENT_TIMESTAMP WHERE id = $2`, [approverName, docId]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Approve Document', docId, 'Document marked as Approved']);

        res.status(200).send('Document approved successfully.');
    } catch (error) {
        console.error('Approval Error:', error);
        res.status(500).send('Server error during approval.');
    } finally {
        if (client) client.release();
    }
};

app.post('/api/documents/approve/:id', requireAuth, handleApproveDocument);
app.post('/api/approve/:id', requireAuth, handleApproveDocument); // Backward-compatible alias

/* ==========================================================================
   RECYCLE BIN & DELETION APIs
   ========================================================================== */

// Soft Delete (Move to Recycle Bin)
app.post('/api/documents/soft-delete/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    const userId = req.session.userId;

    if (req.session.role === 'Officer') {
        return res.status(403).send('Access Denied: Officers cannot delete documents.');
    }

    let client;
    try {
        client = await pool.connect();
        await client.query('UPDATE Document SET is_deleted = TRUE WHERE id = $1', [id]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Move to Recycle Bin', id, 'Document moved to recycle bin']);

        res.status(200).json({ success: true, message: 'Moved to recycle bin' });
    } catch (error) {
        console.error("Soft delete error:", error);
        res.status(500).json({ success: false, error: 'Server error' });
    } finally {
        if (client) client.release();
    }
});

// Get Deleted Documents for Recycle Bin
app.get('/api/documents/deleted', requireAuth, async (req, res) => {
    try {
        const queryText = `
            SELECT d.id, d.title, d.category, d.document_date,
                   dv.version_number, dv.standardized_file_name
            FROM Document d
            JOIN DocumentVersion dv ON d.id = dv.document_id
            WHERE d.is_deleted = TRUE AND dv.version_number = (
                SELECT MAX(version_number) FROM DocumentVersion WHERE document_id = d.id
            )
            ORDER BY d.id DESC
        `;
        const result = await pool.query(queryText);
        res.json({ documents: result.rows });
    } catch (error) {
        console.error("Fetch deleted error:", error);
        res.status(500).send('Server error');
    }
});

// Restore Document from Recycle Bin
app.post('/api/documents/restore/:id', requireAuth, async (req, res) => {
    const { id } = req.params;
    const userId = req.session.userId;
    let client;
    try {
        client = await pool.connect();
        await client.query('UPDATE Document SET is_deleted = FALSE WHERE id = $1', [id]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'Restore Document', id, 'Document restored from recycle bin']);

        res.status(200).send('Restored successfully');
    } catch (error) {
        console.error("Restore error:", error);
        res.status(500).send('Server error');
    } finally {
        if (client) client.release();
    }
});

// Permanent Delete
app.delete('/api/documents/permanent-delete/:id', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') {
        return res.status(403).send('Access Denied: Only Administrators can permanently delete documents.');
    }
    const { id } = req.params;
    const userId = req.session.userId;
    let client;
    try {
        client = await pool.connect();
        await client.query('DELETE FROM Document WHERE id = $1', [id]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, result) VALUES ($1, $2, $3)`, [userId, 'Permanent Delete', `Permanently deleted document ID: ${id}`]);

        res.status(200).send('Permanently deleted');
    } catch (error) {
        console.error("Permanent delete error:", error);
        res.status(500).send('Server error');
    } finally {
        if (client) client.release();
    }
});

/* ==========================================================================
   ACTIVITY LOGGING & BACKUP APIs
   ========================================================================== */

// API: Fetch Activity Trail
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
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (error) {
        console.error('Activity Log Error:', error);
        res.status(500).send('Server error fetching activity log.');
    }
});

// API: Custom Action Logging
app.post('/api/activity/log', requireAuth, async (req, res) => {
    const { action_type, result, document_id } = req.body;
    try {
        await pool.query(
            `INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`,
            [req.session.userId, action_type, document_id || null, result]
        );
        res.status(200).send('Logged successfully');
    } catch (error) {
        console.error('Activity Logging Error:', error);
        res.status(500).send('Server error logging activity.');
    }
});

// API: Log Document View (FR-008)
app.post('/api/activity/log-view/:id', requireAuth, async (req, res) => {
    const docId = req.params.id;
    const userId = req.session.userId;
    let client;
    try {
        client = await pool.connect();
        await client.query('UPDATE Document SET view_count = COALESCE(view_count, 0) + 1 WHERE id = $1', [docId]);
        await client.query(`INSERT INTO ActivityLogEntry (user_id, action_type, document_id, result) VALUES ($1, $2, $3, $4)`, [userId, 'View Document', docId, 'Document previewed or accessed']);

        res.status(200).send('View logged');
    } catch (error) {
        console.error('Log View Error:', error);
        res.status(500).send('Server error');
    } finally {
        if (client) client.release();
    }
});

// Manual Administrator Backup Route (FR-018)
app.get('/api/backup', requireAuth, async (req, res) => {
    if (req.session.role !== 'Administrator') {
        return res.status(403).send('Access Denied: Only Administrators can perform system backups.');
    }
    
    try {
        const dbBackup = await getDatabaseExport();
        const dateStr = new Date().toISOString().split('T')[0];
        
        res.attachment(`ISS_DS_Backup_${dateStr}.zip`);
        const archive = archiver('zip', { zlib: { level: 9 } });
        
        archive.on('error', (err) => { throw err; });
        archive.pipe(res);

        archive.append(JSON.stringify(dbBackup, null, 2), { name: 'database_export.json' });
        
        const repoPath = path.join(__dirname, 'repository');
        if (fs.existsSync(repoPath)) {
            archive.directory(repoPath, 'repository_files');
        }

        await archive.finalize();

        await pool.query(
            `INSERT INTO ActivityLogEntry (user_id, action_type, result) VALUES ($1, $2, $3)`,
            [req.session.userId, 'System Backup', `Generated manual system backup ZIP`]
        );
    } catch (error) {
        console.error('Backup Error:', error);
        res.status(500).send('Server error during backup generation.');
    }
});

/* ==========================================================================
   CRON JOBS
   ========================================================================== */

// Automated Weekly Backup (NFR-005) - Runs every Sunday at Midnight
cron.schedule('0 0 * * 0', async () => {
    console.log('Running scheduled weekly system backup...');
    try {
        const dbBackup = await getDatabaseExport();
        const backupDir = path.join(__dirname, 'backups');
        
        if (!fs.existsSync(backupDir)){
            fs.mkdirSync(backupDir, { recursive: true });
        }

        const dateStr = new Date().toISOString().split('T')[0];
        const output = fs.createWriteStream(path.join(backupDir, `Weekly_Backup_${dateStr}.zip`));
        const archive = archiver('zip', { zlib: { level: 9 } });

        archive.pipe(output);
        archive.append(JSON.stringify(dbBackup, null, 2), { name: 'database_export.json' });
        
        const repoPath = path.join(__dirname, 'repository');
        if (fs.existsSync(repoPath)) {
            archive.directory(repoPath, 'repository_files');
        }

        await archive.finalize();
        console.log('Weekly backup saved to /backups folder.');
    } catch (error) {
        console.error('Automated Backup Error:', error);
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`ISS-DS Backend running on port ${PORT}`));