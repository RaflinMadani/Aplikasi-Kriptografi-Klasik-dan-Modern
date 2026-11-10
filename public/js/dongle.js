// Dongle 3FA: berkas dongle-Vxxxxxx.key ({voterCode, token}) di flashdisk. Auto-lock jika flashdisk dicabut.
const dongleFileName = c => `dongle-${c}.key`;
function _parseDongle(raw, name) {
  let rec; try { rec = JSON.parse(raw); } catch { throw new Error('Berkas .key rusak.'); }
  if (!/^V\d{6}$/.test(rec.voterCode) || !/^[0-9a-f]{64}$/.test(rec.token)) throw new Error('Format dongle tidak valid.');
  return { rec, raw, name, handle: null };
}
async function saveDongle(rec) { // tulis ke flashdisk; jika tak didukung/dibatalkan, unduh berkas
  const name = dongleFileName(rec.voterCode), raw = JSON.stringify(rec);
  try {
    const h = await showDirectoryPicker({ mode: 'readwrite' });
    const w = await (await h.getFileHandle(name, { create: true })).createWritable(); await w.write(raw); await w.close(); return 'usb';
  } catch { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([raw])); a.download = name; a.click(); return 'download'; }
}
const readDongleFile = async f => _parseDongle(await f.text(), f.name);
async function readDongleUSB() {
  if (!window.showDirectoryPicker) throw new Error('Browser tidak mendukung akses flashdisk. Unggah berkas .key.');
  const dir = await showDirectoryPicker({ mode: 'read' });
  for await (const [name, h] of dir.entries()) if (/^dongle-V\d{6}\.key$/.test(name)) { const d = _parseDongle(await (await h.getFile()).text(), name); d.handle = dir; return d; }
  throw new Error('Tidak ada berkas dongle-V......key di folder itu.');
}
function watchDongle(dir, name, raw, onGone) { // heartbeat 2 detik
  const id = setInterval(async () => { try { if ((await (await (await dir.getFileHandle(name)).getFile()).text()) !== raw) throw 0; } catch { clearInterval(id); onGone(); } }, 2000);
  return () => clearInterval(id);
}
