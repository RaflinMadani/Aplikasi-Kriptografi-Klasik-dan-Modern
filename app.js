// app.js (bagian 1: Blockchain ledger suara). UI & state ditambahkan di batch berikutnya.
// Anonimitas: blok suara TIDAK memuat identitas pemilih, hanya ballot terenkripsi.
class Block {
  constructor(index, timestamp, type, data, previousHash = '') {
    Object.assign(this, { index, timestamp, type, data, previousHash, hash: '' });
  }
  calculateHash() {
    return sha256Hex([this.index, this.timestamp, this.type, JSON.stringify(this.data), this.previousHash].join('|'));
  }
}
class Blockchain {
  constructor() { this.chain = []; }
  async init() {
    const g = new Block(0, new Date().toISOString(), 'GENESIS', { note: 'E-Voting Ledger' }, '0');
    g.hash = await g.calculateHash(); this.chain = [g];
  }
  async addBlock(type, data) { // contoh: addBlock('VOTE_CAST', { ballot: pkg })
    const prev = this.chain.at(-1);
    const b = new Block(this.chain.length, new Date().toISOString(), type, data, prev.hash);
    b.hash = await b.calculateHash(); this.chain.push(b);
    return b;
  }
  async isValid() {
    for (let i = 0; i < this.chain.length; i++) {
      const c = this.chain[i];
      if (c.hash !== await c.calculateHash()) return { valid: false, at: i };
      if (i > 0 && c.previousHash !== this.chain[i - 1].hash) return { valid: false, at: i };
    }
    return { valid: true };
  }
  tamper(i = 1) { if (this.chain[i]) this.chain[i].data = { ballot: 'DIUBAH' }; } // simulasi
}

// ===== State & UI orchestrator =====
const $ = id => document.getElementById(id);
const S = { user: null, serial: null, secret: null, f1: null, f2: false, election: null, stop: null };
const ledger = new Blockchain();
const say = (id, t, ok = true) => { $(id).textContent = t; $(id).className = ok ? 'ok' : 'bad'; };
const download = (blob, name) => { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
const loadImg = f => new Promise((r, j) => { const i = new Image(); i.onload = () => r(i); i.onerror = () => j(new Error('Gambar tidak valid.')); i.src = URL.createObjectURL(f); });
const guard = (msgId, fn) => async () => { try { await fn(); } catch (e) { say(msgId, e.message || String(e), false); } };

async function log(type, data) { const b = await ledger.addBlock(type, data); await dbPut('ledger', b); renderChain(); }
function renderChain() {
  $('chain').innerHTML = ledger.chain.map(b => `<div class="blk"><b>#${b.index} ${b.type}</b> <span class="mut">${b.timestamp}</span><br>hash ${b.hash.slice(0, 20)}... prev ${b.previousHash.slice(0, 20)}...</div>`).join('');
}
function showTab(n) {
  if (n > 1 && !S.user) { say('msgLogin', 'Login 3 faktor dulu.', false); n = 1; }
  document.querySelectorAll('section').forEach(s => s.classList.toggle('on', s.id === 't' + n));
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.t == n));
  if (n === 5) showDb();
}
async function refreshLists() {
  const us = await dbGetAll('users'), cs = await dbGetAll('candidates');
  $('loginUser').innerHTML = us.map(u => `<option>${u.username}</option>`).join('');
  $('candList').innerHTML = cs.map(c => `<label><input type="radio" name="cand" value="${c.name}"> ${c.name}</label><br>`).join('');
  $('docCand').innerHTML = cs.map(c => `<option value="${c.id}">${c.name}</option>`).join('');
}
function lock(reason) {
  S.stop?.(); Object.assign(S, { user: null, serial: null, secret: null, f1: null, f2: false, stop: null });
  $('who').textContent = 'Belum login'; showTab(1); say('msgLogin', reason, false);
  log('AUTO_LOCK', { reason: 'USB dicabut' });
}

// --- Fitur 1 & 2: registrasi dan login 3 faktor ---
$('btnCam').onclick = guard('msgReg', () => startCamera($('cam')));
$('btnReg').onclick = guard('msgReg', async () => {
  const u = $('regUser').value.trim(), pin = $('regPin').value;
  if (!/^\w{3,20}$/.test(u) || pin.length < 6) throw new Error('Username 3-20 karakter, PIN minimal 6.');
  if (await dbGet('users', u)) throw new Error('Username sudah dipakai.');
  const desc = await captureFace($('cam')), token = await createToken(u);
  try { await writeDongleToUSB(token); } catch { download(new Blob([JSON.stringify(token)]), dongleName(u)); }
  // vektor wajah dienkripsi AES-256-GCM dengan secret dongle
  await dbPut('users', { username: u, pin: await hashPin(pin), dongleSerial: token.serial, faceEnc: await encryptField(desc, token.secret), createdAt: new Date().toISOString() });
  await log('USER_REGISTER', { note: 'pemilih baru terdaftar' });
  await refreshLists(); say('msgReg', 'Terdaftar. Simpan ' + dongleName(u) + ' di flashdisk.');
});
$('btnDongle').onclick = guard('msgLogin', async () => {
  S.f1 = null; S.f2 = false;
  const user = await dbGet('users', $('loginUser').value); if (!user) throw new Error('Pilih pengguna.');
  let r;
  if ($('modeUsb').checked) r = await readDongleFromUSB(user.username);
  else { const f = $('dongleFile').files[0]; if (!f) throw new Error('Pilih berkas .key.'); const raw = await f.text(); r = { handle: null, raw, token: JSON.parse(raw) }; }
  const v = await validateToken(r.token, user); if (!v.valid) throw new Error(v.reason);
  S.f1 = { user, ...r }; say('msgLogin', 'Faktor 1 (dongle) valid.');
});
$('btnFace').onclick = guard('msgLogin', async () => {
  if (!S.f1) throw new Error('Selesaikan faktor 1 dulu.');
  const stored = await decryptField(S.f1.user.faceEnc, S.f1.token.secret), r = await verifyFace($('cam'), stored);
  S.f2 = r.match; say('msgLogin', `Jarak Euclidean ${r.distance.toFixed(4)} (batas ${FACE_THRESHOLD}): ${r.match ? 'COCOK' : 'TIDAK COCOK'}`, r.match);
});
$('btnLogin').onclick = guard('msgLogin', async () => {
  if (!S.f1 || !S.f2) throw new Error('Faktor 1 dan 2 harus lolos.');
  if (!await verifyPin($('loginPin').value, S.f1.user.pin)) throw new Error('PIN salah.');
  const { user, token, handle, raw } = S.f1;
  Object.assign(S, { user: user.username, serial: token.serial, secret: token.secret });
  if (handle) S.stop = watchDongle(handle, user.username, raw, () => lock('USB dicabut, sesi dikunci otomatis.'));
  stopCamera($('cam')); $('loginPin').value = ''; $('who').textContent = 'Pemilih: ' + S.user; showTab(2);
});

// --- Fitur 3, 5, 7: suara (Rail Fence + AES-256-GCM), basis data terenkripsi, ledger ---
$('btnElect').onclick = guard('msgElect', async () => {
  const k = $('elKey').value, r = +$('elRails').value; if (k.length < 8) throw new Error('Kunci minimal 8 karakter.');
  S.election = { k, r }; $('elKey').value = ''; say('msgElect', 'Pemilihan aktif (kunci hanya di memori).');
});
$('btnVote').onclick = guard('msgVote', async () => {
  if (!S.election) throw new Error('Pemilihan belum diaktifkan panitia.');
  const c = document.querySelector('input[name=cand]:checked'); if (!c) throw new Error('Pilih calon.');
  const vh = await sha256Hex('voter|' + S.user);
  if (await dbGet('voted', vh)) throw new Error('Anda sudah memberikan suara.');
  const r = await superEncrypt(c.value, S.election.r, S.election.k);
  await dbPut('votes', { ballot: r.package });          // tanpa identitas
  await dbPut('voted', { voterHash: vh });              // hanya penanda sudah memilih
  await log('VOTE_CAST', { ballot: r.package });
  $('voteTrace').hidden = false; $('voteTrace').textContent = `Plaintext   : ${c.value}\nRail Fence  : ${r.intermediate}\nAES-GCM B64 : ${r.package}`;
  say('msgVote', 'Suara tercatat di blok #' + (ledger.chain.length - 1));
});
$('btnTally').onclick = guard('tallyOut', async () => {
  $('tallyOut').hidden = false;
  const votes = await dbGetAll('votes'), count = {};
  for (const v of votes) { const n = await superDecrypt(v.ballot, +$('tRails').value, $('tKey').value); count[n] = (count[n] || 0) + 1; }
  await dbPut('tally', { id: 1, data: await encryptField(count, $('tKey').value) }); // rekap tersimpan terenkripsi
  await log('TALLY_DONE', { total: votes.length });
  $('tallyOut').textContent = JSON.stringify(count, null, 2) + `\nTotal: ${votes.length}`;
});

// --- Fitur 4: dokumen calon (RC4) ---
$('btnDocEnc').onclick = guard('msgDoc', async () => {
  const f = $('docFile').files[0], k = $('docKey').value; if (!f || !k) throw new Error('Pilih berkas dan isi kunci.');
  const out = await encryptFile(f, k);
  await dbPut('candidate_docs', { candidateId: +$('docCand').value, name: f.name + '.enc', size: out.length, data: out, sha256: await sha256Hex(b64(out.slice(0, 4096))) });
  await log('DOC_ENCRYPT_RC4', { file: 'dokumen calon', bytes: out.length });
  download(new Blob([out]), f.name + '.enc'); say('msgDoc', 'Terenkripsi dan tersimpan.');
});
$('btnDocDec').onclick = guard('msgDec', async () => {
  const f = $('encFile').files[0]; if (!f) throw new Error('Pilih berkas .enc.');
  const r = await decryptFile(await f.arrayBuffer(), $('decKey').value); download(new Blob([r.data]), r.name); say('msgDec', 'Berhasil: ' + r.name);
});

// --- Fitur 6: kartu pemilih (LSB) ---
const cardToken = async () => `VC1|${S.user}|${await sha256Hex([S.user, S.serial, S.secret].join('|'))}`;
$('btnCard').onclick = guard('msgCard', async () => {
  const f = $('cardFile').files[0]; if (!f) throw new Error('Pilih gambar kartu.');
  const url = embedLSB(await loadImg(f), await cardToken());
  download(await (await fetch(url)).blob(), `kartu-${S.user}.png`); await log('VOTER_CARD_ISSUED', { note: 'kartu diterbitkan' }); say('msgCard', 'Kartu PNG diunduh.');
});
$('btnCheck').onclick = guard('msgCheck', async () => {
  const f = $('cardCheck').files[0]; if (!f) throw new Error('Pilih kartu PNG.');
  const p = extractLSB(await loadImg(f)), ok = p === await cardToken();
  say('msgCheck', ok ? 'Kartu sah: ' + p.slice(0, 24) + '...' : 'Token tidak cocok dengan pemilih ini.', ok);
});

// --- Tab 5: ledger dan DB inspector ---
$('btnValid').onclick = async () => { const r = await ledger.isValid(); say('msgChain', r.valid ? 'VALID' : 'TAMPERED pada blok #' + r.at, r.valid); };
$('btnTamper').onclick = async () => { ledger.tamper(1); renderChain(); $('btnValid').click(); };
$('btnReload').onclick = async () => { await loadLedger(); say('msgChain', 'Dimuat ulang dari database.'); };
const dump = (o, full) => JSON.stringify(o, (k, v) => v instanceof Uint8Array ? `<${v.length} bytes>` : (!full && typeof v === 'string' && v.length > 60 ? v.slice(0, 60) + '...' : v), 2);
async function showDb() { $('dbOut').textContent = dump(await dbGetAll($('dbStore').value)); }
$('dbStore').innerHTML = DB_STORES.map(s => `<option>${s}</option>`).join(''); $('dbStore').onchange = showDb;
$('btnExport').onclick = async () => download(new Blob([dump(await dbGetAll($('dbStore').value), true)]), $('dbStore').value + '.json');
$('btnReset').onclick = async () => { if (confirm('Hapus seluruh database?')) { await dbResetAll(); location.reload(); } };

async function loadLedger() {
  const recs = (await dbGetAll('ledger')).sort((a, b) => a.index - b.index);
  if (recs.length) ledger.chain = recs.map(r => Object.assign(new Block(), r));
  else { await ledger.init(); await dbPut('ledger', ledger.chain[0]); }
  renderChain();
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => showTab(+b.dataset.t));
(async () => {
  await loadLedger();
  if (!(await dbGetAll('candidates')).length) for (const name of ['Calon 1 - Andi Pratama', 'Calon 2 - Budi Santoso', 'Calon 3 - Citra Lestari']) await dbPut('candidates', { name });
  await refreshLists(); showTab(1);
})();
