require('dotenv').config();
const express = require('express'), mysql = require('mysql2/promise'), crypto = require('crypto'), path = require('path');
const Layers = require('../shared/layers'), led = require('./ledger');
const E = process.env, SECRET = E.ELECTION_SECRET || 'dev-secret', BLOCK = +E.BLOCK_SIZE || 3;
const PARAMS = { shift: +E.ELECTION_SHIFT || 7, rails: +E.ELECTION_RAILS || 4 };
const pool = mysql.createPool({ host: E.DB_HOST || 'localhost', user: E.DB_USER || 'root', password: E.DB_PASS || '', database: E.DB_NAME || 'evoting', connectionLimit: 10, timezone: 'Z' });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const NIK_SALT = E.NIK_SALT || 'dev-nik-salt', FK = Buffer.from(sha(E.FACE_KEY || 'dev-face-key'), 'hex');
const pinHash = (pin, salt) => crypto.pbkdf2Sync(pin, salt, 100000, 32, 'sha256').toString('hex');
// Descriptor wajah disimpan terenkripsi AES-256-GCM: iv(12) | tag(16) | ciphertext
const sealFace = d => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', FK, iv); const ct = Buffer.concat([c.update(JSON.stringify(d)), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64'); };
const openFace = s => { const b = Buffer.from(s, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', FK, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()])); };
const faceMatch = (a, b) => Array.isArray(a) && a.length === 128 && Math.sqrt(a.reduce((s, x, i) => s + (x - b[i]) ** 2, 0)) <= 0.5;

const app = express(), sessions = new Map();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '../public')));
app.use('/shared', express.static(path.join(__dirname, '../shared')));
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Kesalahan server.' }); });
const auth = (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', ''), s = sessions.get(t);
  if (!s || s.exp < Date.now()) return res.status(401).json({ error: 'Sesi tidak valid.' });
  req.voterId = s.id; req.sessionToken = t; next();
};
const admin = (req, res, next) => req.headers['x-admin-key'] === (E.ADMIN_KEY || 'dev-admin') ? next() : res.status(403).json({ error: 'Khusus panitia.' });

app.get('/api/candidates', wrap(async (_, res) => res.json((await pool.query('SELECT id, name, vision FROM candidates'))[0])));
app.get('/api/election', (_, res) => res.json(PARAMS)); // pass AES = token sesi pemilih

app.post('/api/register', wrap(async (req, res) => {
  const { nik, pin, descriptor } = req.body;
  if (!/^\d{16}$/.test(nik) || !/^\d{4}$/.test(pin) || !Array.isArray(descriptor) || descriptor.length !== 128) return res.status(400).json({ error: 'Data tidak valid.' });
  const salt = crypto.randomBytes(16).toString('hex'), token = crypto.randomBytes(32).toString('hex'), code = 'V' + crypto.randomInt(100000, 999999);
  try {
    await pool.query('INSERT INTO voters (voter_code, nik_hash, pin_salt, pin_hash, token_hash, face_enc) VALUES (?,?,?,?,?,?)',
      [code, sha(NIK_SALT + nik), salt, pinHash(pin, salt), sha(token), sealFace(descriptor)]);
  } catch (e) { if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'NIK sudah terdaftar.' }); throw e; }
  res.json({ voterCode: code, token }); // token ditanam ke kartu pemilih (DCT) di sisi klien
}));

app.post('/api/login', wrap(async (req, res) => {
  const { voterCode, pin, token, descriptor, sim } = req.body;
  const [[v]] = await pool.query('SELECT * FROM voters WHERE voter_code = ?', [String(voterCode)]);
  const fail = () => res.status(401).json({ error: 'Autentikasi gagal.' });
  if (!v || v.failed_attempts >= 5) return fail();
  const faceOk = (sim === true && E.ALLOW_FACE_SIM === 'true') || faceMatch(descriptor, openFace(v.face_enc));
  if (!(pinHash(String(pin), v.pin_salt) === v.pin_hash && sha(String(token)) === v.token_hash && faceOk)) {
    await pool.query('UPDATE voters SET failed_attempts = failed_attempts + 1 WHERE id = ?', [v.id]); return fail();
  }
  await pool.query('UPDATE voters SET failed_attempts = 0 WHERE id = ?', [v.id]);
  const s = crypto.randomBytes(24).toString('hex'); sessions.set(s, { id: v.id, exp: Date.now() + 15 * 60e3 });
  res.json({ session: s, hasVoted: !!v.has_voted });
}));

app.post('/api/vote', auth, wrap(async (req, res) => {
  let cid;
  try { cid = Number(JSON.parse(await Layers.superDecrypt(req.body.ballot, { ...PARAMS, pass: req.sessionToken })).candidateId); }
  catch { return res.status(400).json({ error: 'Ballot tidak valid.' }); }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[c]] = await conn.query('SELECT id FROM candidates WHERE id = ?', [cid]);
    if (!c) { await conn.rollback(); return res.status(400).json({ error: 'Kandidat tidak ada.' }); }
    const [[v]] = await conn.query('SELECT has_voted FROM voters WHERE id = ? FOR UPDATE', [req.voterId]);
    if (v.has_voted) { await conn.rollback(); return res.status(409).json({ error: 'Anda sudah memilih.' }); }
    await conn.query('UPDATE voters SET has_voted = 1 WHERE id = ?', [req.voterId]);
    await conn.query('INSERT INTO pending_votes (choice_hash) VALUES (?)', [led.choiceHash(cid, SECRET)]);
    await led.ensureGenesis(conn); const block = await led.sealIfReady(conn, BLOCK);
    await conn.commit(); sessions.delete(req.sessionToken);
    res.json({ ok: true, sealedBlock: block });
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
}));

// Panitia: dashboard dihitung dari blok yang sudah tersegel
app.get('/api/admin/results', admin, wrap(async (_, res) => {
  const conn = await pool.getConnection();
  try {
    await led.ensureGenesis(conn);
    const [cands] = await conn.query('SELECT id, name FROM candidates'), [[p]] = await conn.query('SELECT COUNT(*) n FROM pending_votes');
    res.json({ tally: await led.tally(conn, cands, SECRET), pending: p.n, chain: await led.verifyChain(conn) });
  } finally { conn.release(); }
}));
app.post('/api/admin/seal', admin, wrap(async (_, res) => { const c = await pool.getConnection(); try { await led.ensureGenesis(c); res.json({ sealedBlock: await led.sealIfReady(c, 1) }); } finally { c.release(); } }));
app.post('/api/admin/tamper', admin, wrap(async (req, res) => { // demo Tamper Detection
  await pool.query("UPDATE ledger_blocks SET tx_json = JSON_ARRAY('forged') WHERE idx = ?", [+req.body.idx || 1]); res.json({ ok: true });
}));

// Brankas dokumen: server hanya menyimpan blob .secure (enkripsi terjadi di browser)
app.use('/api/docs', express.raw({ type: 'application/octet-stream', limit: '12mb' }));
app.post('/api/docs', admin, wrap(async (req, res) => {
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'Berkas kosong.' });
  const name = decodeURIComponent(req.headers['x-file-name'] || 'dokumen.secure').slice(0, 255);
  const [r] = await pool.query('INSERT INTO campaign_docs (name, size, data) VALUES (?,?,?)', [name, req.body.length, req.body]);
  res.json({ id: r.insertId });
}));
app.get('/api/docs', admin, wrap(async (_, res) => res.json((await pool.query('SELECT id, name, size, created_at FROM campaign_docs ORDER BY id DESC'))[0])));
app.get('/api/docs/:id', admin, wrap(async (req, res) => {
  const [[d]] = await pool.query('SELECT data FROM campaign_docs WHERE id = ?', [+req.params.id]);
  if (!d) return res.status(404).json({ error: 'Tidak ditemukan.' });
  res.type('application/octet-stream').send(d.data);
}));
app.get('/api/admin/blocks', admin, wrap(async (_, res) => {
  const [b] = await pool.query('SELECT idx, ts, merkle_root, prev_hash, hash, JSON_LENGTH(tx_json) AS tx FROM ledger_blocks ORDER BY idx'); res.json(b);
}));

app.listen(E.PORT || 3000, () => console.log('E-Voting server di http://localhost:' + (E.PORT || 3000)));
