// Pruebas del servidor. Correr con:  npm test   (no necesita instalar nada)
// Arranca server.js con una copia de los datos en una carpeta temporal,
// así nunca se toca el datos.json real.

const { test, before, after } = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PUERTO = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://localhost:${PUERTO}`;
const CLAVE = "clave-de-prueba-123";
let servidor, carpeta;

before(async () => {
  carpeta = fs.mkdtempSync(path.join(os.tmpdir(), "biblioteca-"));
  servidor = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    env: { ...process.env, PORT: PUERTO, CLAVE, CARPETA_DATOS: carpeta, RENDER: "", EN_INTERNET: "" },
    stdio: "ignore",
  });
  for (let i = 0; i < 50; i++) {
    try { await fetch(BASE + "/"); return; } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  throw new Error("El servidor no arrancó");
});

after(() => {
  servidor.kill();
  fs.rmSync(carpeta, { recursive: true, force: true });
});

async function entrar() {
  const r = await fetch(BASE + "/api/login", { method: "POST", headers: { "X-Clave": CLAVE } });
  assert.strictEqual(r.status, 200);
  return (await r.json()).sesion;
}

test("muestra la página de estudiantes, el panel y el logo", async () => {
  for (const [ruta, tipo] of [["/", "text/html"], ["/admin", "text/html"], ["/logo.png", "image/png"]]) {
    const r = await fetch(BASE + ruta);
    assert.strictEqual(r.status, 200, ruta);
    assert.ok(r.headers.get("content-type").startsWith(tipo), ruta);
  }
});

test("las páginas llevan la política de seguridad con la huella de sus scripts", async () => {
  const r = await fetch(BASE + "/");
  const csp = r.headers.get("content-security-policy");
  assert.match(csp, /script-src 'sha256-/);
  assert.match(csp, /img-src 'self'/);
  assert.strictEqual(r.headers.get("x-frame-options"), "DENY");
});

test("no deja descargar archivos internos", async () => {
  for (const ruta of ["/server.js", "/datos.json", "/config.json", "/package.json", "/../server.js", "/fotos/../server.js"]) {
    const r = await fetch(BASE + ruta);
    assert.strictEqual(r.status, 404, ruta);
  }
});

test("entrega los libros a los estudiantes", async () => {
  const r = await fetch(BASE + "/api/datos");
  assert.strictEqual(r.status, 200);
  const datos = await r.json();
  assert.ok(Array.isArray(datos.libros) && datos.libros.length > 0);
  assert.ok(datos.sitio && Array.isArray(datos.sitio.categorias));
});

test("rechaza una clave equivocada", async () => {
  const r = await fetch(BASE + "/api/login", { method: "POST", headers: { "X-Clave": "mala" } });
  assert.strictEqual(r.status, 401);
});

test("sin sesión no se puede guardar ni subir fotos", async () => {
  const datos = await (await fetch(BASE + "/api/datos")).json();
  const g = await fetch(BASE + "/api/datos", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(datos) });
  assert.strictEqual(g.status, 401);
  const f = await fetch(BASE + "/api/foto", { method: "POST", body: "{}" });
  assert.strictEqual(f.status, 401);
});

test("con sesión guarda los cambios y limpia lo peligroso", async () => {
  const sesion = await entrar();
  const datos = await (await fetch(BASE + "/api/datos")).json();
  datos.libros[0].titulo = "Título cambiado";
  datos.libros[0].disponibles = 999999;          // más que las unidades
  datos.libros[0].color = "red; background:url(x)";
  datos.sitio.redes.facebook = "javascript:alert(1)";
  const r = await fetch(BASE + "/api/datos", {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Sesion": sesion },
    body: JSON.stringify(datos),
  });
  assert.strictEqual(r.status, 200);

  const nuevo = await (await fetch(BASE + "/api/datos")).json();
  const l = nuevo.libros[0];
  assert.strictEqual(l.titulo, "Título cambiado");
  assert.strictEqual(l.disponibles, l.unidades);
  assert.strictEqual(l.color, "#2f7fe0");
  assert.strictEqual(nuevo.sitio.redes.facebook, "");
});

test("solo acepta fotos que de verdad son imágenes", async () => {
  const sesion = await entrar();
  const subir = imagen => fetch(BASE + "/api/foto", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Sesion": sesion },
    body: JSON.stringify({ imagen }),
  });

  const falsa = await subir("data:image/png;base64," + Buffer.from("<script>no soy foto</script>").toString("base64"));
  assert.strictEqual(falsa.status, 400);

  const png = fs.readFileSync(path.join(__dirname, "..", "logo.png")).toString("base64");
  const buena = await subir("data:image/png;base64," + png);
  assert.strictEqual(buena.status, 200);
  const { ruta } = await buena.json();
  assert.match(ruta, /^fotos\/\d+-[0-9a-f]{8}\.png$/);
  const ver = await fetch(BASE + "/" + ruta);
  assert.strictEqual(ver.status, 200);
  assert.strictEqual(ver.headers.get("content-type"), "image/png");
});

test("salir cierra la sesión", async () => {
  const sesion = await entrar();
  await fetch(BASE + "/api/logout", { method: "POST", headers: { "X-Sesion": sesion } });
  const r = await fetch(BASE + "/api/sesion", { headers: { "X-Sesion": sesion } });
  assert.strictEqual(r.status, 401);
});

// ---------- Reseñas ----------
const enviarResena = cuerpo => fetch(BASE + "/api/resenas", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(cuerpo),
});
const conSesion = (sesion, ruta, cuerpo) => fetch(BASE + ruta, {
  method: cuerpo ? "POST" : "GET",
  headers: { "Content-Type": "application/json", "X-Sesion": sesion },
  body: cuerpo ? JSON.stringify(cuerpo) : undefined,
});

test("una reseña nueva no se publica hasta que la aprueban", async () => {
  const { libros } = await (await fetch(BASE + "/api/datos")).json();
  const libroId = libros[1].id;
  const r = await enviarResena({ libroId, nombre: "Sofía, 7°", estrellas: 5, texto: "Me encantó <b>mucho</b> este libro" });
  assert.strictEqual(r.status, 200);

  let publico = await (await fetch(BASE + "/api/datos")).json();
  assert.ok(!publico.resenas.some(x => x.nombre === "Sofía, 7°"));

  const sesion = await entrar();
  const todas = await (await conSesion(sesion, "/api/resenas")).json();
  const mia = todas.find(x => x.nombre === "Sofía, 7°");
  assert.strictEqual(mia.aprobada, false);
  assert.strictEqual(mia.texto, "Me encantó <b>mucho</b> este libro"); // se guarda tal cual; la página la muestra como texto

  assert.strictEqual((await conSesion(sesion, "/api/resenas/aprobar", { id: mia.id })).status, 200);
  publico = await (await fetch(BASE + "/api/datos")).json();
  const visible = publico.resenas.find(x => x.id === mia.id);
  assert.deepStrictEqual(Object.keys(visible).sort(), ["estrellas", "fecha", "id", "libroId", "nombre", "texto"]);

  assert.strictEqual((await conSesion(sesion, "/api/resenas/borrar", { id: mia.id })).status, 200);
  publico = await (await fetch(BASE + "/api/datos")).json();
  assert.ok(!publico.resenas.some(x => x.id === mia.id));
});

test("rechaza reseñas incompletas o de libros que no existen", async () => {
  const { libros } = await (await fetch(BASE + "/api/datos")).json();
  const libroId = libros[0].id;
  for (const malo of [
    { libroId: "no-existe", nombre: "Ana", estrellas: 4, texto: "Muy bueno" },
    { libroId, nombre: "", estrellas: 4, texto: "Muy bueno" },
    { libroId, nombre: "Ana", estrellas: 9, texto: "Muy bueno" },
    { libroId, nombre: "Ana", estrellas: 0, texto: "Muy bueno" },
    { libroId, nombre: "Ana", estrellas: 3, texto: "ok" },
  ]) assert.strictEqual((await enviarResena(malo)).status, 400, JSON.stringify(malo));
});

test("los robots que llenan el campo trampa no dejan reseñas", async () => {
  const { libros } = await (await fetch(BASE + "/api/datos")).json();
  const r = await enviarResena({ libroId: libros[0].id, nombre: "Robot", estrellas: 5, texto: "Compra aquí", web: "spam.com" });
  assert.strictEqual(r.status, 200);
  const sesion = await entrar();
  const todas = await (await conSesion(sesion, "/api/resenas")).json();
  assert.ok(!todas.some(x => x.nombre === "Robot"));
});

test("sin sesión no se pueden ver pendientes, aprobar ni borrar", async () => {
  assert.strictEqual((await fetch(BASE + "/api/resenas")).status, 401);
  assert.strictEqual((await fetch(BASE + "/api/resenas/aprobar", { method: "POST", body: "{}" })).status, 401);
  assert.strictEqual((await fetch(BASE + "/api/resenas/borrar", { method: "POST", body: "{}" })).status, 401);
});

test("al eliminar un libro se van sus reseñas", async () => {
  const sesion = await entrar();
  const datos = await (await fetch(BASE + "/api/datos")).json();
  const libro = datos.libros[datos.libros.length - 1];
  await enviarResena({ libroId: libro.id, nombre: "Luis", estrellas: 3, texto: "Está bien, algo largo" });
  datos.libros = datos.libros.filter(l => l !== libro);
  const r = await fetch(BASE + "/api/datos", {
    method: "PUT", headers: { "Content-Type": "application/json", "X-Sesion": sesion }, body: JSON.stringify(datos),
  });
  assert.strictEqual(r.status, 200);
  const todas = await (await conSesion(sesion, "/api/resenas")).json();
  assert.ok(!todas.some(x => x.libroId === libro.id));
});
