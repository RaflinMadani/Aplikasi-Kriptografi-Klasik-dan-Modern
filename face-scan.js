// face-scan.js - Dongle (File System Access API, auto-lock saat dicabut) + face-api.js (Euclidean <= 0.50)
const FACE_THRESHOLD = 0.5, FACE_MODELS = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.13/model/';
let _faceReady = false;
async function loadFaceModels() {
  if (_faceReady) return;
  await Promise.all([faceapi.nets.tinyFaceDetector, faceapi.nets.faceLandmark68Net, faceapi.nets.faceRecognitionNet].map(n => n.loadFromUri(FACE_MODELS)));
  _faceReady = true;
}
async function startCamera(v) { v.srcObject = await navigator.mediaDevices.getUserMedia({ video: true }); await v.play(); }
function stopCamera(v) { v.srcObject?.getTracks().forEach(t => t.stop()); v.srcObject = null; }
async function captureFace(v) {
  await loadFaceModels();
  const r = await faceapi.detectSingleFace(v, new faceapi.TinyFaceDetectorOptions()).withFaceLandmarks().withFaceDescriptor();
  if (!r) throw new Error('Wajah tidak terdeteksi. Nyalakan kamera dan hadap ke layar.');
  return Array.from(r.descriptor);
}
const euclid = (a, b) => Math.sqrt(a.reduce((s, x, i) => s + (x - b[i]) ** 2, 0));
async function verifyFace(v, stored) { const d = euclid(await captureFace(v), stored); return { distance: d, match: d <= FACE_THRESHOLD }; }

const dongleName = u => `dongle-${u}.key`;
const _sig = t => sha256Hex([t.serial, t.username, t.secret].join('|'));
async function createToken(username) {
  const t = { serial: 'SN-' + b64(crypto.getRandomValues(new Uint8Array(6))).replace(/\W/g, '').toUpperCase(), username, secret: b64(crypto.getRandomValues(new Uint8Array(32))) };
  t.signature = await _sig(t); return t;
}
async function validateToken(t, user) {
  try {
    if (t.username !== user.username) return { valid: false, reason: 'Token bukan milik pengguna ini.' };
    if (await _sig(t) !== t.signature) return { valid: false, reason: 'Signature SHA-256 tidak cocok.' };
    if (t.serial !== user.dongleSerial) return { valid: false, reason: 'Serial token tidak terdaftar.' };
    return { valid: true };
  } catch { return { valid: false, reason: 'Token rusak.' }; }
}
async function writeDongleToUSB(token) {
  const h = await showDirectoryPicker({ mode: 'readwrite' });
  const w = await (await h.getFileHandle(dongleName(token.username), { create: true })).createWritable();
  await w.write(JSON.stringify(token)); await w.close(); return h;
}
const _readRaw = async (h, u) => (await (await h.getFileHandle(dongleName(u))).getFile()).text();
async function readDongleFromUSB(u) { const h = await showDirectoryPicker({ mode: 'read' }); const raw = await _readRaw(h, u); return { handle: h, raw, token: JSON.parse(raw) }; }
function watchDongle(h, u, raw, onEject) { // heartbeat 2 detik
  const id = setInterval(async () => { try { if (await _readRaw(h, u) !== raw) throw 0; } catch { clearInterval(id); onEject(); } }, 2000);
  return () => clearInterval(id);
}
