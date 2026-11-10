// face.js - face-api.js: model berlapis (lokal lalu CDN), kamera 640x480, deteksi dengan retry,
// descriptor 128-d dirata-rata dari beberapa sampel. Pencocokan Euclidean (<= 0.50) dilakukan di server.
const FACE_MODEL_URLS = ['./models', 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.13/model/', 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/'];
let _faceReady = false, _faceStream = null;

async function loadFaceModels(onStatus = () => {}) {
  if (_faceReady) return;
  if (typeof faceapi === 'undefined') throw new Error('face-api.js gagal dimuat (cek internet atau blokir CDN).');
  let last;
  for (const url of FACE_MODEL_URLS) {
    try {
      onStatus('Memuat model AI dari ' + url + ' ...');
      await Promise.all([faceapi.nets.tinyFaceDetector, faceapi.nets.faceLandmark68Net, faceapi.nets.faceRecognitionNet].map(n => n.loadFromUri(url)));
      _faceReady = true; return;
    } catch (e) { last = e; }
  }
  throw new Error('Model AI gagal dimuat: ' + (last?.message || last));
}

async function startCamera(video, onStatus = () => {}) {
  if (!navigator.mediaDevices?.getUserMedia) throw new Error('Kamera butuh localhost atau HTTPS.');
  await loadFaceModels(onStatus);
  _faceStream?.getTracks().forEach(t => t.stop());
  _faceStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480, facingMode: 'user' }, audio: false });
  video.srcObject = _faceStream; await video.play();
  if (!(video.readyState >= 2 && video.videoWidth)) await new Promise(r => { video.onloadeddata = r; });
  await new Promise(r => setTimeout(r, 800)); // beri waktu auto-exposure agar frame pertama tidak gelap
  onStatus('Kamera siap. Hadap ke kamera dengan cahaya cukup.');
}
const stopCamera = v => { _faceStream?.getTracks().forEach(t => t.stop()); _faceStream = null; v.srcObject = null; };

function _overlay(canvas, video, box, label, color) {
  if (!canvas) return;
  canvas.width = video.videoWidth; canvas.height = video.videoHeight;
  const x = canvas.getContext('2d'); x.clearRect(0, 0, canvas.width, canvas.height);
  x.font = '18px monospace'; x.fillStyle = x.strokeStyle = color; x.lineWidth = 3;
  if (box) x.strokeRect(box.x, box.y, box.width, box.height);
  x.fillText(label, box ? box.x : 12, box ? Math.max(20, box.y - 8) : 26);
}

// Mengulang deteksi hingga cukup sampel atau timeout, lalu merata-ratakan descriptor.
async function captureFace(video, { canvas = null, onStatus = () => {}, samples = 3, timeoutMs = 20000 } = {}) {
  if (!video.srcObject) throw new Error('Nyalakan kamera dulu.');
  await loadFaceModels(onStatus);
  const opts = new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 }), got = [], t0 = performance.now();
  while (got.length < samples && performance.now() - t0 < timeoutMs) {
    if (!video.videoWidth) throw new Error('Video belum siap.');
    const det = await faceapi.detectSingleFace(video, opts).withFaceLandmarks().withFaceDescriptor();
    if (det) { got.push(det.descriptor); _overlay(canvas, video, det.detection.box, `Sampel ${got.length}/${samples}`, '#22d3ee'); onStatus(`Memindai wajah... ${got.length}/${samples}`); }
    else _overlay(canvas, video, null, 'Wajah tidak terdeteksi', '#fbbf24');
  }
  _overlay(canvas, video, null, '', '#000');
  if (got.length < samples) throw new Error('Wajah tidak terdeteksi jelas. Perbaiki cahaya, dekatkan wajah, lalu coba lagi.');
  const mean = new Float32Array(128);
  got.forEach(d => { for (let i = 0; i < 128; i++) mean[i] += d[i] / got.length; });
  return Array.from(mean);
}