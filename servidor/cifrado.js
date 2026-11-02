// ============================================================================
//  cifrado.js  -  Modulo de cifrado RSA
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION CORREGIDA <<<
//
//  [VULN-1] corregido: llave de 2048 bits y relleno OAEP con SHA-256
//  (NIST SP 800-57 / OWASP).  CWE-326 / CWE-780
// ============================================================================

const crypto = require('crypto');

const TAMANO_LLAVE = 2048;
const RELLENO = crypto.constants.RSA_PKCS1_OAEP_PADDING;
const HASH_OAEP = 'sha256';

// Maximo de bytes que admite RSA-OAEP-SHA256 con llave de 2048 bits:
// 256 - 2*32 - 2 = 190 bytes.
const MAX_BYTES = TAMANO_LLAVE / 8 - 2 * 32 - 2;

function generarLlaves() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: TAMANO_LLAVE,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

function cifrar(textoPlano, llavePublica) {
  const buffer = Buffer.from(String(textoPlano), 'utf8');
  const cifrado = crypto.publicEncrypt(
    { key: llavePublica, padding: RELLENO, oaepHash: HASH_OAEP },
    buffer
  );
  return cifrado.toString('base64');
}

function descifrar(textoCifradoBase64, llavePrivada) {
  const buffer = Buffer.from(String(textoCifradoBase64), 'base64');
  const descifrado = crypto.privateDecrypt(
    { key: llavePrivada, padding: RELLENO, oaepHash: HASH_OAEP },
    buffer
  );
  return descifrado.toString('utf8');
}

module.exports = { generarLlaves, cifrar, descifrar, TAMANO_LLAVE, MAX_BYTES };
