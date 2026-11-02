// ============================================================================
//  db.js  -  Acceso a datos (bitacora de operaciones)
//  >>> VERSION CORREGIDA <<<
// ============================================================================
//
//  [VULN-3] corregido: consulta parametrizada (placeholder '?') con el
//  driver mysql2. La respuesta ya no devuelve el SQL ejecutado.  CWE-89
//
//  Nota didactica: no se necesita un MySQL real. Si no hay DATABASE_URL o la
//  conexion falla, se devuelve una lista vacia y el servicio sigue vivo.

const mysql = require('mysql2');
const config = require('./config');

let conexion = null;

function obtenerConexion() {
  if (conexion || !config.DATABASE_URL) {
    return conexion;
  }
  try {
    conexion = mysql.createConnection(config.DATABASE_URL);
    conexion.on('error', () => {
      conexion = null;
    });
  } catch (e) {
    conexion = null;
  }
  return conexion;
}

function buscarBitacora(nombre, callback) {
  const sql = 'SELECT * FROM bitacora WHERE usuario = ?';
  const con = obtenerConexion();
  if (!con) {
    return callback(null, { filas: [] });
  }
  con.query(sql, [String(nombre)], (err, filas) => {
    if (err) {
      return callback(null, { filas: [] });
    }
    return callback(null, { filas });
  });
}

module.exports = { buscarBitacora };
