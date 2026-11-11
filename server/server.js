require("dotenv").config();
const express = require("express"),
  mysql = require("mysql2/promise"),
  crypto = require("crypto"),
  path = require("path"),
  fs = require("fs"),
  { execFile } = require("child_process"),
  { promisify } = require("util");
const execFileAsync = promisify(execFile);
const Layers = require("../shared/layers"),
  led = require("./ledger");
const E = process.env;
if (
  E.NODE_ENV === "production" &&
  ["ADMIN_KEY", "ELECTION_SECRET", "NIK_SALT", "FACE_KEY"].some((k) => !E[k])
) {
  console.error("Isi ADMIN_KEY, ELECTION_SECRET, NIK_SALT, FACE_KEY di .env");
  process.exit(1);
}
const SECRET = E.ELECTION_SECRET || "dev-secret",
  BLOCK = +E.BLOCK_SIZE || 3,
  ADMIN_KEY = E.ADMIN_KEY || "dev-admin";
const PARAMS = { shift: +E.ELECTION_SHIFT || 7, rails: +E.ELECTION_RAILS || 4 };
const pool = mysql.createPool({
  host: E.DB_HOST || "localhost",
  user: E.DB_USER || "root",
  password: E.DB_PASS || "",
  database: E.DB_NAME || "evoting",
  connectionLimit: 10,
  timezone: "Z",
});
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const eq = (a, b) =>
  a.length === b.length &&
  crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const NIK_SALT = E.NIK_SALT || "dev-nik-salt",
  FK = Buffer.from(sha(E.FACE_KEY || "dev-face-key"), "hex");
const pinHash = (pin, salt) =>
  crypto.pbkdf2Sync(pin, salt, 100000, 32, "sha256").toString("hex");
// Descriptor wajah disimpan terenkripsi AES-256-GCM: iv(12) | tag(16) | ciphertext
const sealFace = (d) => {
  const iv = crypto.randomBytes(12),
    c = crypto.createCipheriv("aes-256-gcm", FK, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(d)), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]).toString("base64");
};
const openFace = (s) => {
  const b = Buffer.from(s, "base64"),
    d = crypto.createDecipheriv("aes-256-gcm", FK, b.subarray(0, 12));
  d.setAuthTag(b.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]));
};
const FACE_THRESHOLD = Number(E.FACE_THRESHOLD) || 0.5;
// Threshold untuk cek anti-sybil saat registrasi: lebih ketat (lebih kecil) agar
// hanya menolak wajah yang benar-benar sama. Jika dua orang berbeda kebetulan
// menghasilkan jarak ~0.45, threshold login (0.5) akan menganggap mereka sama padahal
// threshold registrasi yang lebih kecil (0.4) akan membedakan mereka.
const FACE_REGISTER_THRESHOLD = Number(E.FACE_REGISTER_THRESHOLD) || 0.4;
const validDesc = (d) =>
  Array.isArray(d) && d.length === 128 && d.every(Number.isFinite);

function faceDistance(a, b) {
  if (!validDesc(a) || !validDesc(b)) return Infinity;
  let normA = 0,
    normB = 0;
  for (let i = 0; i < 128; i++) {
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  normA = Math.sqrt(normA);
  normB = Math.sqrt(normB);
  if (normA === 0 || normB === 0) return Infinity;

  let sumSq = 0;
  for (let i = 0; i < 128; i++) {
    const diff = a[i] / normA - b[i] / normB;
    sumSq += diff * diff;
  }
  return Math.sqrt(sumSq);
}

const faceMatch = (a, b, threshold = FACE_THRESHOLD) => {
  const dist = faceDistance(a, b);
  return { ok: dist <= threshold, dist };
};

const app = express(),
  sessions = new Map(),
  adminFails = new Map();

// Dynamic per-voter USB dongle lock.
// Aplikasi tidak dikunci secara global; Gatekeeper selalu terbuka.
// Pemilih yang sedang login dicek terus apakah file .key-nya masih ada di USB.
const DONGLE_REQUIRED = E.DONGLE_REQUIRED !== "false";

// Memindai seluruh drive bertipe USB (Removable) yang terpasang dan siap di Windows.
async function getConnectedUsbDrives() {
  if (process.platform !== "win32") return [];
  const ps =
    "[System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType.ToString() -eq 'Removable' -and $_.IsReady } | ForEach-Object { [pscustomobject]@{ DriveLetter=$_.Name.Substring(0,2) } } | ConvertTo-Json -Compress";
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        ps,
      ],
      { windowsHide: true, timeout: 4000, maxBuffer: 1024 * 1024 },
    );
    if (!stdout.trim()) return [];
    const parsed = JSON.parse(stdout.trim());
    const drives = Array.isArray(parsed) ? parsed : [parsed];
    return drives
      .map((d) => String(d.DriveLetter || "").toUpperCase())
      .filter((d) => /^[A-Z]:$/.test(d));
  } catch (err) {
    console.error("Gagal mendeteksi USB drives:", err.message);
    return [];
  }
}

// Memindai berkas dongle-V*.key di semua drive USB yang terpasang.
async function findDonglesOnUsb() {
  if (!DONGLE_REQUIRED) return [];
  const usbDrives = await getConnectedUsbDrives();
  const detected = [];
  for (const drive of usbDrives) {
    try {
      const rootPath = drive + "\\";
      const files = await fs.promises.readdir(rootPath);
      for (const file of files) {
        if (/^dongle-V\d{6}\.key$/i.test(file)) {
          try {
            const raw = await fs.promises.readFile(
              path.join(rootPath, file),
              "utf8",
            );
            const parsed = JSON.parse(raw);
            if (
              parsed &&
              /^V\d{6}$/.test(parsed.voterCode) &&
              /^[0-9a-f]{64}$/.test(parsed.token)
            ) {
              detected.push({
                voterCode: parsed.voterCode,
                token: parsed.token,
                nikMask: parsed.nikMask || null,
                driveLetter: drive,
                fileName: file,
              });
            }
          } catch (_) {
            /* Lewati berkas rusak */
          }
        }
      }
    } catch (_) {
      /* Drive tidak dapat diakses */
    }
  }
  return detected;
}

// Background watcher: revoke sesi pemilih jika USB-nya dicabut.
if (DONGLE_REQUIRED) {
  setInterval(
    async () => {
      const voterSessions = Array.from(sessions.entries()).filter(
        ([_, s]) => !s.admin && s.voterCode,
      );
      if (voterSessions.length === 0) return;
      const dongles = await findDonglesOnUsb();
      for (const [tokenKey, s] of voterSessions) {
        const exists = dongles.some(
          (d) => d.voterCode === s.voterCode && d.token === s.token,
        );
        if (!exists) {
          sessions.delete(tokenKey);
          console.warn(
            `[SECURITY] USB dongle untuk voter ${s.voterCode} dicabut. Sesi dibatalkan.`,
          );
        }
      }
    },
    Math.max(1000, Number(E.DONGLE_POLL_MS) || 1500),
  ).unref();
}

const newSession = (data, ttl) => {
  const t = crypto.randomBytes(24).toString("hex");
  sessions.set(t, { ...data, exp: Date.now() + ttl });
  return t;
};
setInterval(
  () => sessions.forEach((s, k) => s.exp < Date.now() && sessions.delete(k)),
  60e3,
).unref();
let chain = Promise.resolve(); // registrasi diserialkan agar cek wajah ganda tidak bisa dibalap
const serial = (fn) => {
  const p = chain.then(fn);
  chain = p.catch(() => {});
  return p;
};

app.disable("x-powered-by");
app.use((_, res, next) => {
  res.set({
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
  });
  next();
});
// Tidak ada global lock — Gatekeeper selalu terbuka.
// Pemilih dikunci di level sesi (via /api/usb-status) bukan di level halaman.
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "../public")));
app.use("/shared", express.static(path.join(__dirname, "../shared")));
const wrap = (f) => (req, res) =>
  f(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: "Kesalahan server." });
  });
const sess = (req) =>
  sessions.get((req.headers.authorization || "").replace("Bearer ", ""));
const auth = (req, res, next) => {
  // khusus pemilih
  const t = (req.headers.authorization || "").replace("Bearer ", ""),
    s = sessions.get(t);
  if (!s || s.admin || s.exp < Date.now())
    return res.status(401).json({ error: "Sesi tidak valid." });
  req.voterId = s.id;
  req.sessionToken = t;
  next();
};
const admin = (req, res, next) => {
  const s = sess(req);
  return s && s.admin && s.exp > Date.now()
    ? next()
    : res.status(401).json({ error: "Khusus panitia. Login sebagai admin." });
};

app.get(
  "/api/usb-status",
  wrap(async (req, res) => {
    // Panitia: selalu OK
    const s = sess(req);
    if (!DONGLE_REQUIRED)
      return res.json({ ok: true, role: s?.admin ? "admin" : "guest" });
    if (s && s.admin && s.exp > Date.now())
      return res.json({ ok: true, role: "admin" });
    // Pemilih aktif: pastikan USB dengan token-nya masih tertancap
    if (s && s.voterCode && s.exp > Date.now()) {
      const dongles = await findDonglesOnUsb();
      const stillAttached = dongles.some(
        (d) => d.voterCode === s.voterCode && d.token === s.token,
      );
      if (!stillAttached) {
        sessions.delete(
          (req.headers.authorization || "").replace("Bearer ", ""),
        );
        return res.status(423).json({ error: "USB dongle pemilih dicabut." });
      }
      return res.json({ ok: true, role: "voter" });
    }
    // Tamu / belum login: tidak dikunci (Gatekeeper terbuka)
    res.json({ ok: true, role: "guest" });
  }),
);

// Deteksi otomatis dongle-V*.key di semua drive USB yang terpasang (Opsi B).
// Token dikirim ke client hanya untuk keperluan login — tidak disimpan di browser.
app.get(
  "/api/dongle/detect",
  wrap(async (_req, res) => {
    if (!DONGLE_REQUIRED) return res.json({ required: false, detected: [] });
    const dongles = await findDonglesOnUsb();
    res.json({ required: true, detected: dongles });
  }),
);

app.get(
  "/api/candidates",
  wrap(async (_, res) =>
    res.json((await pool.query("SELECT id, name, vision FROM candidates"))[0]),
  ),
);
app.get("/api/election", (_, res) => res.json(PARAMS)); // pass AES = token sesi pemilih

app.post(
  "/api/register",
  wrap((req, res) =>
    serial(async () => {
      const { nik, pin, descriptor } = req.body;
      if (
        typeof nik !== "string" ||
        typeof pin !== "string" ||
        !/^\d{16}$/.test(nik) ||
        !/^\d{4}$/.test(pin) ||
        !validDesc(descriptor)
      )
        return res.status(400).json({ error: "Data tidak valid." });
      // Anti-Sybil: satu wajah hanya boleh satu NIK.
      // Gunakan FACE_REGISTER_THRESHOLD (lebih kecil dari threshold login) agar
      // dua orang dengan wajah berbeda tidak saling terblokir satu sama lain.
      const [faces] = await pool.query("SELECT face_enc FROM voters");
      if (
        faces.some((r) => {
          try {
            return faceMatch(descriptor, openFace(r.face_enc), FACE_REGISTER_THRESHOLD).ok;
          } catch {
            return false;
          }
        })
      )
        return res.status(400).json({
          error: "Wajah ini sudah terdaftar pada NIK lain. Registrasi ditolak.",
        });
      const salt = crypto.randomBytes(16).toString("hex"),
        token = crypto.randomBytes(32).toString("hex"),
        code = "V" + crypto.randomInt(100000, 999999);
      try {
        await pool.query(
          "INSERT INTO voters (voter_code, nik_hash, pin_salt, pin_hash, token_hash, face_enc) VALUES (?,?,?,?,?,?)",
          [
            code,
            sha(NIK_SALT + nik),
            salt,
            pinHash(pin, salt),
            sha(token),
            sealFace(descriptor),
          ],
        );
      } catch (e) {
        if (e.code === "ER_DUP_ENTRY")
          return res.status(409).json({ error: "NIK sudah terdaftar." });
        throw e;
      }
      res.json({ voterCode: code, token });
    }),
  ),
);

app.post(
  "/api/login",
  wrap(async (req, res) => {
    const { voterCode, pin, token, descriptor } = req.body,
      fail = (msg = "Autentikasi gagal.") =>
        res.status(401).json({ error: msg });
    if (
      typeof voterCode !== "string" ||
      typeof pin !== "string" ||
      typeof token !== "string" ||
      !/^V\d{6}$/.test(voterCode) ||
      !/^\d{4}$/.test(pin) ||
      !/^[0-9a-f]{64}$/.test(token)
    )
      return fail();
    const [[v]] = await pool.query(
      "SELECT * FROM voters WHERE voter_code = ?",
      [voterCode],
    );
    if (!v || v.failed_attempts >= 5) return fail();

    let storedFace;
    try {
      storedFace = openFace(v.face_enc);
    } catch (err) {
      console.error("[AUTH] Gagal mendekripsi descriptor wajah:", err.message);
      return fail();
    }

    const { ok: faceMatched, dist } = faceMatch(descriptor, storedFace);
    const faceOk = faceMatched;

    console.log(
      `[AUTH] Login voter ${voterCode}: distance=${isFinite(dist) ? dist.toFixed(4) : dist}, threshold=${FACE_THRESHOLD} -> ${faceOk ? "PASS" : "FAIL"}`,
    );

    const pinOk = eq(pinHash(pin, v.pin_salt), v.pin_hash);
    const tokenOk = eq(sha(token), v.token_hash);

    if (!pinOk || !tokenOk || !faceOk) {
      await pool.query(
        "UPDATE voters SET failed_attempts = failed_attempts + 1 WHERE id = ?",
        [v.id],
      );
      if (pinOk && tokenOk && !faceOk) {
        console.warn(
          `[AUTH] Login ditolak untuk ${voterCode}: wajah tidak cocok (jarak: ${dist.toFixed(4)} > ${FACE_THRESHOLD}).`,
        );
        return fail("Wajah tidak cocok dengan data pemilih terdaftar.");
      }
      return fail();
    }
    await pool.query("UPDATE voters SET failed_attempts = 0 WHERE id = ?", [
      v.id,
    ]);
    res.json({
      session: newSession(
        { id: v.id, voterCode: v.voter_code, token },
        15 * 60e3,
      ),
      hasVoted: !!v.has_voted,
    });
  }),
);

app.post("/api/admin/login", (req, res) => {
  // login panitia: sesi 30 menit, 5 gagal = blok 5 menit per IP
  const a = adminFails.get(req.ip) || { n: 0, until: 0 };
  if (a.until > Date.now())
    return res
      .status(429)
      .json({ error: "Terlalu banyak percobaan. Coba lagi beberapa menit." });
  if (
    typeof req.body.key !== "string" ||
    !eq(sha(req.body.key), sha(ADMIN_KEY))
  ) {
    if (++a.n >= 5) {
      a.until = Date.now() + 300e3;
      a.n = 0;
    }
    adminFails.set(req.ip, a);
    return res.status(401).json({ error: "Kunci panitia salah." });
  }
  adminFails.delete(req.ip);
  res.json({ session: newSession({ admin: true }, 30 * 60e3) });
});

app.post(
  "/api/vote",
  auth,
  wrap(async (req, res) => {
    let cid;
    try {
      cid = Number(
        JSON.parse(
          await Layers.superDecrypt(String(req.body.ballot), {
            ...PARAMS,
            pass: req.sessionToken,
          }),
        ).candidateId,
      );
    } catch {
      return res.status(400).json({ error: "Ballot tidak valid." });
    }
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[c]] = await conn.query("SELECT id FROM candidates WHERE id = ?", [
        cid,
      ]);
      if (!c) {
        await conn.rollback();
        return res.status(400).json({ error: "Kandidat tidak ada." });
      }
      const [[v]] = await conn.query(
        "SELECT has_voted FROM voters WHERE id = ? FOR UPDATE",
        [req.voterId],
      );
      if (v.has_voted) {
        await conn.rollback();
        return res.status(409).json({ error: "Anda sudah memilih." });
      }
      await conn.query("UPDATE voters SET has_voted = 1 WHERE id = ?", [
        req.voterId,
      ]);
      await conn.query("INSERT INTO pending_votes (choice_hash) VALUES (?)", [
        led.choiceHash(cid, SECRET),
      ]);
      await led.ensureGenesis(conn);
      const block = await led.sealIfReady(conn, BLOCK);
      await conn.commit();
      sessions.delete(req.sessionToken);
      res.json({ ok: true, sealedBlock: block });
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
  }),
);

// ----- Panitia -----
app.get(
  "/api/admin/results",
  admin,
  wrap(async (_, res) => {
    const conn = await pool.getConnection();
    try {
      await led.ensureGenesis(conn);
      const [cands] = await conn.query("SELECT id, name FROM candidates"),
        [[p]] = await conn.query("SELECT COUNT(*) n FROM pending_votes");
      res.json({
        tally: await led.tally(conn, cands, SECRET),
        pending: p.n,
        chain: await led.verifyChain(conn),
      });
    } finally {
      conn.release();
    }
  }),
);
app.post(
  "/api/admin/seal",
  admin,
  wrap(async (_, res) => {
    const c = await pool.getConnection();
    try {
      await led.ensureGenesis(c);
      res.json({ sealedBlock: await led.sealIfReady(c, 1) });
    } finally {
      c.release();
    }
  }),
);
app.post(
  "/api/admin/tamper",
  admin,
  wrap(async (req, res) => {
    // demo Tamper Detection; matikan dengan ALLOW_TAMPER_DEMO=false
    if (E.ALLOW_TAMPER_DEMO === "false")
      return res.status(403).json({ error: "Demo tamper dimatikan." });
    await pool.query(
      "UPDATE ledger_blocks SET tx_json = JSON_ARRAY('forged') WHERE idx = ?",
      [Math.max(1, Math.trunc(+req.body.idx) || 1)],
    );
    res.json({ ok: true });
  }),
);
app.get(
  "/api/admin/blocks",
  admin,
  wrap(async (_, res) => {
    const [b] = await pool.query(
      "SELECT idx, ts, merkle_root, prev_hash, hash, JSON_LENGTH(tx_json) AS tx FROM ledger_blocks ORDER BY idx",
    );
    res.json(b);
  }),
);

// Brankas dokumen: server hanya menyimpan blob .secure (enkripsi di browser); format RC4S divalidasi
app.use(
  "/api/docs",
  express.raw({ type: "application/octet-stream", limit: "12mb" }),
);
app.post(
  "/api/docs",
  admin,
  wrap(async (req, res) => {
    const b = req.body;
    if (
      !Buffer.isBuffer(b) ||
      b.length < 53 ||
      b.subarray(0, 4).toString("latin1") !== "RC4S"
    )
      return res
        .status(400)
        .json({ error: "Bukan berkas .secure yang valid." });
    const name = decodeURIComponent(
      String(req.headers["x-file-name"] || "dokumen.secure"),
    )
      .replace(/[\\/]/g, "_")
      .slice(0, 255);
    const [r] = await pool.query(
      "INSERT INTO campaign_docs (name, size, data) VALUES (?,?,?)",
      [name, b.length, b],
    );
    res.json({ id: r.insertId });
  }),
);
app.get(
  "/api/docs",
  admin,
  wrap(async (_, res) =>
    res.json(
      (
        await pool.query(
          "SELECT id, name, size, created_at FROM campaign_docs ORDER BY id DESC",
        )
      )[0],
    ),
  ),
);
app.get(
  "/api/docs/:id",
  admin,
  wrap(async (req, res) => {
    const [[d]] = await pool.query(
      "SELECT data FROM campaign_docs WHERE id = ?",
      [+req.params.id || 0],
    );
    if (!d) return res.status(404).json({ error: "Tidak ditemukan." });
    res.type("application/octet-stream").send(d.data);
  }),
);
app.use((err, _req, res, _next) =>
  res.status(400).json({ error: "Permintaan tidak valid." }),
);

app.listen(E.PORT || 3000, () =>
  console.log("E-Voting server di http://localhost:" + (E.PORT || 3000)),
);
