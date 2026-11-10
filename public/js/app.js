// Orkestrator UI: tab, login 3FA, voting, super-enkripsi, file vault, DCT, dashboard.
const $ = id => document.getElementById(id);
const S = { session: null, voter: null, params: null, stopWatch: null, idle: null, card: '', dongle: null };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const vis = c => (c === ' ' ? '␣' : c);
const say = (id, t, ok = true) => { $(id).textContent = t; $(id).className = 'msg ' + (ok ? 'ok' : 'bad'); };
const table = (head, rows) => `<div class="tw"><table><thead><tr>${head.map(h => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const guard = (id, fn) => async () => { try { await fn(); } catch (e) { say(id, e.message || String(e), false); } };
const download = (blob, name) => { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
const scan = (id, n) => captureFace($('cam'), { canvas: $('camOverlay'), onStatus: t => say(id, t), samples: n });
const loadImg = f => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('Gambar tidak valid.')); i.src = URL.createObjectURL(f); });

async function api(path, { method = 'GET', body, admin, headers = {}, raw } = {}) {
  const h = { ...headers };
  if (S.session) h.Authorization = 'Bearer ' + S.session;
  if (admin) h['x-admin-key'] = $('adminKey').value;
  if (body && !raw) h['Content-Type'] = 'application/json';
  const r = await fetch(path, { method, headers: h, body: body && (raw ? body : JSON.stringify(body)) });
  if (r.status === 401 && S.session) lock('Sesi berakhir. Login ulang.');
  if (!(r.headers.get('content-type') || '').includes('json')) { if (!r.ok) throw new Error('Permintaan gagal.'); return r; }
  const j = await r.json(); if (!r.ok) throw new Error(j.error || 'Permintaan gagal.'); return j;
}

// ----- navigasi dan penguncian -----
function show(t) {
  if (t !== 'gate' && !S.session) { say('msgLogin', 'Login 3 faktor dulu.', false); t = 'gate'; }
  document.querySelectorAll('section').forEach(s => s.classList.toggle('on', s.id === t));
  document.querySelectorAll('nav button').forEach(b => b.classList.toggle('on', b.dataset.t === t));
  if (t === 'stego' && !$('stegoMsg').value) $('stegoMsg').value = S.card;
}
document.querySelectorAll('nav button').forEach(b => b.onclick = () => show(b.dataset.t));
function lock(reason, ok = false) {
  S.stopWatch?.(); clearTimeout(S.idle);
  Object.assign(S, { session: null, voter: null, stopWatch: null, card: '', dongle: null });
  $('who').textContent = 'Terkunci'; $('nav').classList.add('locked'); $('stegoMsg').value = '';
  show('gate'); say('msgLogin', reason, ok);
}
function armIdle() { clearTimeout(S.idle); S.idle = setTimeout(() => S.session && lock('Tidak ada aktivitas 5 menit. Sesi dikunci.'), 300000); }
['pointerdown', 'keydown'].forEach(e => document.addEventListener(e, () => S.session && armIdle()));

// ----- Gatekeeper: registrasi dan login 3 faktor -----
$('btnCam').onclick = guard('msgLogin', async () => { await startCamera($('cam'), t => say('msgLogin', t)); });
$('btnReg').onclick = guard('msgReg', async () => {
  const nik = $('regNik').value.trim(), pin = $('regPin').value;
  if (!/^\d{16}$/.test(nik) || !/^\d{4}$/.test(pin)) throw new Error('NIK harus 16 digit dan PIN 4 digit.');
  const descriptor = await scan('msgReg', 5);
  const r = await api('/api/register', { method: 'POST', body: { nik, pin, descriptor } });
  const where = await saveDongle({ voterCode: r.voterCode, token: r.token });
  say('msgReg', `Terdaftar. Kode pemilih ${r.voterCode}. Dongle ${where === 'usb' ? 'ditulis ke flashdisk' : 'diunduh: salin ke flashdisk'}.`);
});
const setDongle = d => { S.dongle = d; say('msgLogin', `Dongle terbaca (${d.rec.voterCode}${d.handle ? ', flashdisk dipantau' : ', mode unggah'}).`); };
$('btnUsb').onclick = guard('msgLogin', async () => setDongle(await readDongleUSB()));
$('keyFile').onchange = guard('msgLogin', async () => { const f = $('keyFile').files[0]; if (f) setDongle(await readDongleFile(f)); });
$('btnLogin').onclick = guard('msgLogin', async () => {
  const d = S.dongle; if (!d) throw new Error('Pilih dongle .key dulu.');
  const sim = $('faceSim').checked, descriptor = sim ? null : await scan('msgLogin', 3);
  const r = await api('/api/login', { method: 'POST', body: { voterCode: d.rec.voterCode, pin: $('loginPin').value, token: d.rec.token, descriptor, sim } });
  Object.assign(S, { session: r.session, voter: d.rec.voterCode, card: `${d.rec.voterCode}|${d.rec.token}` });
  S.params = await api('/api/election');
  if (d.handle) S.stopWatch = watchDongle(d.handle, d.name, d.raw, () => lock('Flashdisk dicabut. Sesi dikunci otomatis.'));
  $('loginPin').value = ''; stopCamera($('cam')); armIdle();
  $('who').textContent = 'Pemilih ' + S.voter; $('nav').classList.remove('locked');
  await loadCandidates(); show(r.hasVoted ? 'text' : 'vote');
});

// ----- tabel Step-by-Step untuk super-enkripsi -----
function renderLayers(el, plain, r, shift, rails) {
  const L = r.layers, rows = r.steps.slice(0, 80).map(s => [s.i, vis(s.plain), vis(s.caesar), vis(s.rail)]);
  el.innerHTML = '<h3>Hasil per lapis</h3>' + table(['Lapis', 'Keluaran'], [['Plaintext', plain], [`1. Caesar (geser ${shift})`, L.caesar], [`2. Rail Fence (${rails} rel)`, L.rail], ['3. AES-256-GCM (Base64)', L.aes]])
    + '<h3>Transformasi per karakter</h3>' + table(['#', 'Plaintext', 'Setelah Caesar', 'Setelah Rail Fence'], rows)
    + (r.steps.length > 80 ? '<p class="mut">80 karakter pertama ditampilkan.</p>' : '');
}
$('btnTxtEnc').onclick = guard('msgTxt', async () => {
  const t = $('txtIn').value, o = { shift: +$('txtShift').value, rails: +$('txtRails').value, pass: $('txtPass').value };
  if (!t || o.pass.length < 6) throw new Error('Isi teks dan kunci AES (min 6).');
  const r = await Layers.superEncrypt(t, o); renderLayers($('txtTrace'), t, r, o.shift, o.rails);
  $('txtPkg').value = r.package; say('msgTxt', 'Terenkripsi. Paket Base64 disalin ke kotak dekripsi.');
});
$('btnTxtDec').onclick = guard('msgTxtDec', async () => {
  const o = { shift: +$('txtShift').value, rails: +$('txtRails').value, pass: $('txtPass').value };
  say('msgTxtDec', 'Hasil: ' + await Layers.superDecrypt($('txtPkg').value.trim(), o));
});

// ----- Surat suara -----
async function loadCandidates() {
  const c = await api('/api/candidates'); $('btnVote').disabled = false; $('voteTrace').innerHTML = '';
  $('candList').innerHTML = c.map(x => `<label class="opt"><input type="radio" name="cand" value="${x.id}"><span><b>${esc(x.name)}</b><br><span class="mut">${esc(x.vision || '')}</span></span></label>`).join('');
}
$('btnVote').onclick = guard('msgVote', async () => {
  const c = document.querySelector('input[name=cand]:checked'); if (!c) throw new Error('Pilih kandidat.');
  const plain = JSON.stringify({ candidateId: +c.value }), r = await Layers.superEncrypt(plain, { ...S.params, pass: S.session });
  renderLayers($('voteTrace'), plain, r, S.params.shift, S.params.rails);
  const res = await api('/api/vote', { method: 'POST', body: { ballot: r.package } });
  $('btnVote').disabled = true;
  say('msgVote', res.sealedBlock != null ? `Suara tercatat, blok #${res.sealedBlock} tersegel. Sesi ditutup dalam 6 detik.` : 'Suara tercatat, menunggu disegel ke blok. Sesi ditutup dalam 6 detik.');
  setTimeout(() => lock('Suara Anda sudah tercatat. Sesi ditutup.', true), 6000);
});

// ----- File Vault (.secure) -----
function renderTrace(el, t, dec) {
  const H = dec ? ['Ciphertext', 'Keystream', 'Plaintext'] : ['Plaintext', 'Keystream', 'Ciphertext'], h2 = n => n.toString(16).padStart(2, '0');
  el.innerHTML = '<h3>Parameter proses</h3>' + table(['Langkah', 'Nilai'], [
    ['Berkas', `${t.file} (${t.size} byte), total .secure ${t.total} byte`], ['Header (RC4S, versi)', t.header], ['Salt PBKDF2 (16 B)', t.salt],
    ['Kunci RC4 (16 B)', t.rc4Key], ['Kunci HMAC (8 B pertama)', t.macKey], ['S-box awal [0..15]', t.sBefore], ['S-box setelah KSA [0..15]', t.sAfter],
    ['RC4-drop', SEC.DROP + ' byte keystream dibuang'], ['HMAC-SHA256', t.tag]])
    + '<h3>10 byte pertama (XOR)</h3>' + table(['#', H[0] + ' hex', 'biner', H[1] + ' hex', 'biner', H[2] + ' hex', 'biner'], t.rows.map(r => [r.n, h2(r.i), bin(r.i), h2(r.k), bin(r.k), h2(r.o), bin(r.o)]));
}
let lastSecure = null;
$('btnSecEnc').onclick = guard('msgFile', async () => {
  const f = $('fileIn').files[0], p = $('filePass').value; if (!f || p.length < 6) throw new Error('Pilih berkas dan isi kunci (min 6).');
  const r = await secureEncrypt(f, p); lastSecure = { bytes: r.bytes, name: f.name + '.secure' };
  download(new Blob([r.bytes]), lastSecure.name); renderTrace($('fileTrace'), r.trace, false); say('msgFile', 'Terenkripsi dan diunduh: ' + lastSecure.name);
});
$('btnSecSave').onclick = guard('msgFile', async () => {
  if (!lastSecure) throw new Error('Enkripsi berkas dulu.');
  const r = await api('/api/docs', { method: 'POST', admin: true, raw: true, body: lastSecure.bytes, headers: { 'Content-Type': 'application/octet-stream', 'x-file-name': encodeURIComponent(lastSecure.name) } });
  say('msgFile', 'Tersimpan di MySQL, id ' + r.id);
});
$('btnSecDec').onclick = guard('msgSecDec', async () => {
  const f = $('secIn').files[0]; if (!f) throw new Error('Pilih berkas .secure.');
  const r = await secureDecrypt(await f.arrayBuffer(), $('secPass').value);
  download(new Blob([r.data]), r.name); renderTrace($('decTrace'), r.trace, true); say('msgSecDec', 'HMAC valid. Berkas dipulihkan: ' + r.name);
});
$('btnDocs').onclick = guard('msgFile', async () => {
  const d = await api('/api/docs', { admin: true });
  $('docList').innerHTML = d.length ? `<div class="tw"><table><tr><th>ID</th><th>Nama</th><th>Ukuran</th><th></th></tr>${d.map(x => `<tr><td>${x.id}</td><td>${esc(x.name)}</td><td>${x.size}</td><td><button class="go alt" data-doc="${x.id}" data-name="${esc(x.name)}">Unduh</button></td></tr>`).join('')}</table></div>` : '<p class="mut">Belum ada dokumen.</p>';
});
$('docList').onclick = guard('msgFile', async e => { const b = e.target.closest('[data-doc]'); if (b) download(await (await api('/api/docs/' + b.dataset.doc, { admin: true })).blob(), b.dataset.name); });

// ----- Steganografi DCT -----
$('btnEmbed').onclick = guard('msgStego', async () => {
  const f = $('imgIn').files[0], m = $('stegoMsg').value; if (!f || !m) throw new Error('Pilih gambar dan isi pesan.');
  const url = embedDCT(await loadImg(f), m); download(await (await fetch(url)).blob(), 'kartu-pemilih.png'); say('msgStego', 'Pesan disisipkan ke domain DCT. PNG diunduh.');
});
$('btnExtract').onclick = guard('msgStego', async () => {
  const f = $('imgIn').files[0]; if (!f) throw new Error('Pilih gambar kartu.');
  $('stegoMsg').value = extractDCT(await loadImg(f)); say('msgStego', 'Pesan berhasil diekstrak.');
});

// ----- Command Dashboard: data dari blok ledger tersegel -----
let chart, dashTimer;
async function refreshDash() {
  const r = await api('/api/admin/results', { admin: true }), labels = Object.keys(r.tally), vals = Object.values(r.tally);
  if (!chart) { Chart.defaults.color = '#93a3bd'; chart = new Chart($('chart'), { type: 'bar', data: { labels, datasets: [{ label: 'Suara tersegel', data: vals, backgroundColor: '#e0a43a' }] }, options: { scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }, plugins: { legend: { display: false } } } }); }
  else { chart.data.labels = labels; chart.data.datasets[0].data = vals; chart.update(); }
  const ch = r.chain, total = vals.reduce((a, b) => a + b, 0);
  $('dashStat').innerHTML = [['Suara tersegel', total], ['Menunggu segel', r.pending], ['Rantai', ch.valid ? `VALID (${ch.blocks} blok)` : `TAMPERED blok #${ch.at}: ${ch.reason}`]].map(([k, v]) => `<div class="stat"><span class="mut">${k}</span><br><b class="${k === 'Rantai' && !ch.valid ? 'bad' : ''}">${esc(v)}</b></div>`).join('');
  const b = await api('/api/admin/blocks', { admin: true });
  $('blocks').innerHTML = table(['#', 'Waktu', 'Tx', 'Merkle root', 'Hash', 'Prev'], b.map(x => [x.idx, String(x.ts).replace('T', ' ').slice(0, 19), x.tx, x.merkle_root.slice(0, 14) + '...', x.hash.slice(0, 14) + '...', x.prev_hash.slice(0, 14) + '...']));
}
$('btnDash').onclick = guard('msgDash', async () => { await refreshDash(); say('msgDash', 'Diperbarui ' + new Date().toLocaleTimeString()); });
$('autoDash').onchange = () => { clearInterval(dashTimer); if ($('autoDash').checked) dashTimer = setInterval(() => refreshDash().catch(e => say('msgDash', e.message, false)), 5000); };
$('btnSeal').onclick = guard('msgDash', async () => { await api('/api/admin/seal', { method: 'POST', admin: true }); await refreshDash(); });
$('btnTamper').onclick = guard('msgDash', async () => { await api('/api/admin/tamper', { method: 'POST', admin: true, body: { idx: 1 } }); await refreshDash(); });
show('gate');