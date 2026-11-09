// db.js - IndexedDB EVotingCryptoDB v1. Tabel votes TIDAK menyimpan identitas; voted hanya menyimpan hash penanda.
const DB_NAME = 'EVotingCryptoDB', DB_STORES = ['users', 'candidates', 'candidate_docs', 'votes', 'voted', 'tally', 'ledger'];
let _db;
function dbOpen() {
  return _db ? Promise.resolve(_db) : new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, 1);
    r.onupgradeneeded = () => {
      const d = r.result, k = { users: 'username', voted: 'voterHash', tally: 'id', ledger: 'index' };
      DB_STORES.forEach(s => d.createObjectStore(s, k[s] ? { keyPath: k[s] } : { keyPath: 'id', autoIncrement: true }));
    };
    r.onsuccess = () => { _db = r.result; res(_db); };
    r.onerror = () => rej(r.error);
  });
}
const _tx = async (s, m, f) => { const d = await dbOpen(); return new Promise((res, rej) => { const q = f(d.transaction(s, m).objectStore(s)); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); };
const dbPut = (s, v) => _tx(s, 'readwrite', o => o.put(v));
const dbGet = (s, k) => _tx(s, 'readonly', o => o.get(k));
const dbGetAll = s => _tx(s, 'readonly', o => o.getAll());
const dbResetAll = () => new Promise(r => { _db && _db.close(); _db = null; const q = indexedDB.deleteDatabase(DB_NAME); q.onsuccess = q.onerror = q.onblocked = () => r(); });
