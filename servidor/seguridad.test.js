// Pruebas de SEGURIDAD de la API (Jest + supertest)
// Verifican las correcciones de la Fase 2 (entrada, inyeccion y errores).
const request = require('supertest');
const app = require('./servidor');

describe('Controles de seguridad de la API', () => {
  test('rechaza un texto vacio con 400 (validacion de entrada)', async () => {
    const res = await request(app).post('/cifrar').send({ texto: '' });
    expect(res.statusCode).toBe(400);
  });

  test('rechaza un texto demasiado largo con 400', async () => {
    const res = await request(app).post('/cifrar').send({ texto: 'a'.repeat(500) });
    expect(res.statusCode).toBe(400);
  });

  test('un dato cifrado alterado da error generico, sin stack', async () => {
    const c = await request(app).post('/cifrar').send({ texto: 'hola' });
    const alterado = (c.body.cifrado[0] === 'A' ? 'B' : 'A') + c.body.cifrado.slice(1);
    const res = await request(app).post('/descifrar').send({ cifrado: alterado });
    expect(res.statusCode).toBe(400);
    expect(res.body.stack).toBeUndefined();
  });

  test('bloquea la inyeccion de comandos en /diagnostico', async () => {
    const res = await request(app).get('/diagnostico').query({ host: '8.8.8.8;id' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBe('Host invalido');
  });

  test('/calcular ya no ejecuta codigo (sin eval)', async () => {
    const res = await request(app).post('/calcular').send({ expresion: 'process.exit(1)' });
    expect(res.body.resultado).toBe(0);
    const suma = await request(app).post('/calcular').send({ numeros: [2, 3] });
    expect(suma.body.resultado).toBe(5);
  });

  test('responde con cabeceras de seguridad y sin X-Powered-By', async () => {
    const res = await request(app).get('/salud');
    expect(res.headers['content-security-policy']).toBeDefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
