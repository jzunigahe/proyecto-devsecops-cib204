// ============================================================================
//  auth.js  -  Gestion de identidad y acceso (IAM)
//  >>> VERSION CORREGIDA <<<
// ============================================================================
//
//  [VULN-4] corregido: el token JWT se valida contra las llaves publicas
//  (JWKS) de Keycloak, solo se acepta RS256 y se verifica el emisor.
//  CWE-347 / CWE-287 / CWE-306

const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const config = require('./config');

// Lista de identificadores de token (jti) revocados. En produccion viviria en
// una base de datos o cache compartida.
const tokensRevocados = new Set();

const validarJwt = expressjwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10,
    jwksUri: `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/certs`,
  }),
  algorithms: ['RS256'],
  issuer: config.KEYCLOAK_ISSUER,
  isRevoked: async (req, token) => tokensRevocados.has(token && token.payload && token.payload.jti),
});

function requiereAuth(req, res, next) {
  if (!config.AUTH_ENABLED) {
    return next();
  }
  return validarJwt(req, res, (err) => {
    if (err) {
      return res.status(401).json({ error: 'No autorizado' });
    }
    return next();
  });
}

module.exports = { requiereAuth, tokensRevocados };
