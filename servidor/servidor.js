// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION CORREGIDA <<<
//
//  Endpoints:
//    GET  /salud       -> estado del servicio
//    GET  /llave       -> entrega la llave publica
//    POST /cifrar      -> cifra un texto            (requiere token)
//    POST /descifrar   -> descifra un texto         (requiere token)
//    GET  /buscar      -> consulta la bitacora      (consulta parametrizada)
//    POST /calcular    -> suma segura de numeros    (sin eval)
//    GET  /diagnostico -> ping a un host validado   (sin shell)
// ============================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { execFile } = require('child_process');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requiereAuth } = require('./auth');

// API sin estado: la identidad viaja en un token Bearer (no en cookies), por
// eso no aplica un token anti-CSRF.
const app = express(); // nosemgrep

// En Codespaces las peticiones llegan a traves de un proxy (github.dev):
// se confia en un salto para identificar la IP real del cliente.
app.set('trust proxy', 1);

// Limite de tamano del cuerpo JSON (evita cuerpos enormes).  [VULN-7]
app.use(express.json({ limit: '10kb' }));

// [VULN-6] corregido: cabeceras de seguridad con Helmet (CSP, X-Content-Type-
// Options, Frame-Options, etc.) y sin la cabecera X-Powered-By.  CWE-693
app.use(helmet());
app.use((req, res, next) => {
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.set('Cache-Control', 'no-store');
  next();
});

// [VULN-5] corregido: CORS limitado a los origenes de confianza.  CWE-942
const origenes = config.ORIGEN_PERMITIDO
  ? config.ORIGEN_PERMITIDO.split(',').map((o) => o.trim())
  : false;
app.use(cors({ origin: origenes }));

// Limite de peticiones por cliente (mitiga denegacion de servicio).
app.use(rateLimit({ windowMs: 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'seguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

// [VULN-7] corregido: se valida tipo y tamano del texto.  CWE-20
// [VULN-8] corregido: errores genericos, sin stack ni mensaje interno.  CWE-209
app.post('/cifrar', requiereAuth, (req, res) => {
  const texto = req.body && req.body.texto;
  if (typeof texto !== 'string' || texto.length === 0 ||
      Buffer.byteLength(texto, 'utf8') > cifrado.MAX_BYTES) {
    return res.status(400).json({ error: 'Entrada invalida' });
  }
  try {
    return res.json({ cifrado: cifrado.cifrar(texto, llaves.publicKey) });
  } catch (e) {
    return res.status(400).json({ error: 'No se pudo cifrar' });
  }
});

app.post('/descifrar', requiereAuth, (req, res) => {
  const cifradoTxt = req.body && req.body.cifrado;
  if (typeof cifradoTxt !== 'string' || cifradoTxt.length === 0 || cifradoTxt.length > 1024) {
    return res.status(400).json({ error: 'Entrada invalida' });
  }
  try {
    return res.json({ descifrado: cifrado.descifrar(cifradoTxt, llaves.privateKey) });
  } catch (e) {
    return res.status(400).json({ error: 'No se pudo descifrar' });
  }
});

// [VULN-3] corregido en db.js (consulta parametrizada).  CWE-89
app.get('/buscar', requiereAuth, (req, res) => {
  const nombre = typeof req.query.nombre === 'string' ? req.query.nombre : '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [VULN-9] corregido: se elimino eval(); ahora es una suma de numeros validados.
//   CWE-95
app.post('/calcular', (req, res) => {
  const nums = Array.isArray(req.body && req.body.numeros) ? req.body.numeros : [];
  if (nums.length > 100 || !nums.every((n) => typeof n === 'number' && Number.isFinite(n))) {
    return res.status(400).json({ error: 'Entrada invalida' });
  }
  return res.json({ resultado: nums.reduce((a, b) => a + b, 0) });
});

// [VULN-10] corregido: el host se valida con una lista blanca de caracteres y
//   se usa execFile (sin shell) con los argumentos separados.  CWE-78
app.get('/diagnostico', (req, res) => {
  const host = typeof req.query.host === 'string' ? req.query.host : '127.0.0.1';
  if (!/^[a-zA-Z0-9.-]{1,64}$/.test(host)) {
    return res.status(400).json({ error: 'Host invalido' });
  }
  execFile('ping', ['-c', '1', host], { timeout: 5000 }, (err, stdout) => {
    res.json({ salida: stdout });
  });
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;
