// ============================================================================
//  config.js  -  Configuracion del servicio
//  >>> VERSION CORREGIDA <<<
//  Los secretos se leen SOLO de variables de entorno (nunca del repositorio).
//  [VULN-2] corregido: se eliminaron las credenciales quemadas.  CWE-798
// ============================================================================

const config = {
  // Cadena de conexion a la base de datos: llega por variable de entorno.
  DATABASE_URL: process.env.DATABASE_URL,

  // Control de acceso ENCENDIDO por defecto. Solo se apaga si se pide
  // explicitamente (por ejemplo, en las pruebas automaticas).
  AUTH_ENABLED: process.env.AUTH_ENABLED !== 'false',

  // Keycloak (IAM)
  //  - KEYCLOAK_URL: direccion interna para descargar las llaves publicas (JWKS).
  //  - KEYCLOAK_ISSUER: emisor esperado dentro del token (campo "iss").
  KEYCLOAK_URL: process.env.KEYCLOAK_URL || 'http://localhost:8080',
  KEYCLOAK_REALM: process.env.KEYCLOAK_REALM || 'appmovil',
  KEYCLOAK_ISSUER: process.env.KEYCLOAK_ISSUER,

  // Origen(es) de la app que pueden llamar a la API (CORS). Separados por coma.
  ORIGEN_PERMITIDO: process.env.ORIGEN_PERMITIDO,

  PUERTO: process.env.PORT || 3000,
};

module.exports = config;
