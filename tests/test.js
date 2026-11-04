// Tests du laboratoire de cryptographie : node tests/test.js
// Les résultats sont comparés au module crypto de Node (OpenSSL) et aux vecteurs de test officiels.
const assert = require('assert');
const nc = require('crypto');
const C = require('../crypto.js');
let n = 0;
const eq = (a, b, msg) => { n++; assert.strictEqual(a, b, msg); };
let seed = 7;
const rng = () => ((seed = (seed * 16807) % 2147483647) & 255);
const randBuf = (len) => Uint8Array.from({ length: len }, rng);

// 1. SHA-256 : vecteurs officiels (FIPS 180-4) puis 500 messages au hasard comparés à Node
eq(C.toHex(C.sha256(C.utf8(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SHA-256("")');
eq(C.toHex(C.sha256(C.utf8('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256("abc")');
eq(C.toHex(C.sha256(C.utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))), '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1', 'SHA-256 sur deux blocs');
for (let k = 0; k < 500; k++) {
  const m = randBuf(k % 200 + (k > 450 ? 1000 : 0));
  eq(C.toHex(C.sha256(m)), nc.createHash('sha256').update(m).digest('hex'), 'SHA-256 aléatoire ' + k);
}
// effet avalanche : un bit changé modifie environ la moitié des bits (moyenne sur 200 essais)
{
  let tot = 0;
  for (let k = 0; k < 200; k++) { const m = randBuf(40), m2 = m.slice(); m2[k % 40] ^= 1 << (k % 8); tot += C.bitsDiff(C.sha256(m), C.sha256(m2)); }
  n++; assert.ok(Math.abs(tot / 200 - 128) < 4, 'avalanche moyenne ≈ 128 bits : ' + tot / 200);
}

// 2. HMAC et PBKDF2
eq(C.toHex(C.hmacSha256(C.utf8('key'), C.utf8('The quick brown fox jumps over the lazy dog'))), 'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8', 'HMAC-SHA256 (vecteur connu)');
for (let k = 0; k < 50; k++) {
  const key = randBuf(k * 3), msg = randBuf(k * 7 + 1);
  eq(C.toHex(C.hmacSha256(key, msg)), nc.createHmac('sha256', Buffer.from(key)).update(msg).digest('hex'), 'HMAC aléatoire ' + k);
}
for (const [it, len] of [[1, 32], [2, 32], [1000, 32], [4096, 20], [10, 64]]) {
  eq(C.toHex(C.pbkdf2(C.utf8('password'), C.utf8('salt'), it, len)), nc.pbkdf2Sync('password', 'salt', it, len, 'sha256').toString('hex'), 'PBKDF2 ' + it + ' itérations');
}

// 3. AES-128 : boîte S calculée, vecteur FIPS 197, puis CBC et CTR comparés à OpenSSL
eq(C.SBOX[0x00], 0x63, 'S(00)'); eq(C.SBOX[0x53], 0xed, 'S(53)'); eq(C.SBOX[0xff], 0x16, 'S(ff)');
n++; assert.ok(Array.from({ length: 256 }, (_, i) => C.INV[C.SBOX[i]] === i).every(Boolean), 'boîte S inverse');
eq(C.gmul(0x57, 0x83), 0xc1, 'multiplication dans GF(2⁸) (exemple FIPS 197)');
{
  const key = C.fromHex('000102030405060708090a0b0c0d0e0f'), pt = C.fromHex('00112233445566778899aabbccddeeff');
  const w = C.expandKey(key), ct = C.aesEncryptBlock(pt, w);
  eq(C.toHex(ct), '69c4e0d86a7b0430d8cdb78070b4c55a', 'AES-128 FIPS 197 annexe C.1');
  eq(C.toHex(C.aesDecryptBlock(ct, w)), C.toHex(pt), 'déchiffrement du bloc');
  const k2 = C.fromHex('2b7e151628aed2a6abf7158809cf4f3c');
  eq(C.toHex(C.expandKey(k2).slice(160, 176)), 'd014f9a8c9ee2589e13f0cc8b6630ca6', 'dernière clé de tour (FIPS 197 annexe A.1)');
  const trace = []; C.aesEncryptBlock(pt, w, trace);
  eq(trace.length, 1 + 1 + 9 * 4 + 3, 'nombre d’étapes tracées');
}
for (let k = 0; k < 200; k++) {
  const key = randBuf(16), iv = randBuf(16), msg = randBuf(k);
  const c1 = nc.createCipheriv('aes-128-cbc', key, iv), ref = Buffer.concat([c1.update(msg), c1.final()]);
  const ct = C.aesCbcEncrypt(key, iv, msg);
  eq(C.toHex(ct), ref.toString('hex'), 'AES-CBC aléatoire ' + k);
  eq(C.toHex(C.aesCbcDecrypt(key, iv, ct)), C.toHex(msg), 'AES-CBC aller-retour ' + k);
  const c2 = nc.createCipheriv('aes-128-ctr', key, iv), ref2 = Buffer.concat([c2.update(msg), c2.final()]);
  eq(C.toHex(C.aesCtr(key, iv, msg)), ref2.toString('hex'), 'AES-CTR aléatoire ' + k);
}
// compteur CTR qui déborde sur plusieurs octets
{
  const key = randBuf(16), iv = C.fromHex('00000000000000000000ffffffffffff'), msg = randBuf(80);
  const c = nc.createCipheriv('aes-128-ctr', key, iv);
  eq(C.toHex(C.aesCtr(key, iv, msg)), Buffer.concat([c.update(msg), c.final()]).toString('hex'), 'CTR avec retenue');
}
n++; assert.throws(() => C.unpad(Uint8Array.of(1, 2, 3, 0)), /padding/, 'rembourrage invalide détecté');

// 4. RSA
{
  eq(C.modPow(4n, 13n, 497n), 445n, 'exponentiation modulaire');
  eq((C.modInv(17n, 3120n) * 17n) % 3120n, 1n, 'inverse modulaire');
  const primes = [2n, 3n, 5n, 97n, 7919n, 2147483647n, 2305843009213693951n];
  primes.forEach((p) => { n++; assert.ok(C.isProbablePrime(p), p + ' premier'); });
  [1n, 4n, 561n, 1105n, 2147483649n, 3215031751n].forEach((c) => { n++; assert.ok(!C.isProbablePrime(c), c + ' composé (dont nombres de Carmichael)'); });
  for (const bits of [64, 256, 512, 1024]) {
    const k = C.rsaKeygen(bits, rng);
    eq(k.bits, bits, 'taille de n (' + bits + ' bits)');
    // primalité vérifiée par OpenSSL
    n++; assert.ok(nc.checkPrimeSync(k.p) && nc.checkPrimeSync(k.q), 'p et q premiers selon OpenSSL (' + bits + ' bits)');
    eq((k.e * k.d) % k.phi, 1n, 'e·d ≡ 1 mod φ');
    for (let i = 0; i < 5; i++) {
      const m = C.bytesToBig(randBuf(bits / 8 - 1));
      eq(C.rsaDecrypt(C.rsaEncrypt(m, k), k), m, 'chiffrer puis déchiffrer');
    }
    const msg = C.utf8('ordonnance n° 42');
    const s = C.rsaSign(msg, k);
    n++; assert.ok(C.rsaVerify(msg, s, k), 'signature valide');
    n++; assert.ok(!C.rsaVerify(C.utf8('ordonnance n° 43'), s, k), 'message modifié détecté');
  }
  // clé de 64 bits cassée par Pollard rho
  const small = C.rsaKeygen(64, rng), f = C.pollardRho(small.n);
  n++; assert.ok(f && small.n % f.factor === 0n && f.factor !== 1n && f.factor !== small.n, 'factorisation d’une clé de 64 bits');
  // conversions
  eq(C.fromUtf8(C.bigToBytes(C.bytesToBig(C.utf8('RDV 14h')))), 'RDV 14h', 'texte ↔ entier');
}

// 5. Force des mots de passe
{
  const s = (p) => C.passwordStrength(p);
  n++; assert.ok(s('123456').flags.includes('common') && s('123456').bits < 15, 'mot de passe courant');
  n++; assert.ok(s('azerty').flags.includes('common'), 'azerty');
  n++; assert.ok(s('Camille2024!').bits < 20, 'prénom + année + ! : faible');
  n++; assert.ok(s('aaaaaaaa').flags.includes('repeat'), 'répétition');
  n++; assert.ok(s('xk12345pq').flags.includes('sequence'), 'suite');
  n++; assert.ok(Math.abs(s('cheval pile agrafe correct').bits - 44) < 1e-9, 'phrase de 4 mots : 44 bits');
  n++; assert.ok(s('kT9#vQ2!xLp@7z').bits > 85, 'mot de passe aléatoire de 14 caractères');
  n++; assert.ok(s('kT9#vQ2!xLp@7z').bits > s('kT9#vQ2!') .bits, 'plus long = plus fort');
  eq(C.crackSeconds(2e10, 1e10), 1, 'temps moyen = la moitié de l’espace');
}

console.log('OK : ' + n + ' vérifications passent');
