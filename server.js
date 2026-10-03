// Servidor de la Biblioteca Virtual - Colegio San Cayetano
// Iniciar con:  node server.js   (o doble clic en iniciar.bat)
// No necesita instalar nada: usa solo módulos que ya vienen con Node.

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const PUERTO = process.env.PORT || process.env.PUERTO || 3000;
// Clave del panel de ejecutivos: variable de entorno CLAVE (en el hosting) o config.json (en el colegio).
// No se escribe aquí para que no quede pública en GitHub.
let CLAVE = process.env.CLAVE || "";
if (!CLAVE) try { CLAVE = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8")).clave || ""; } catch {}
if (!CLAVE) console.warn("\n  ⚠  No hay clave configurada: el panel de ejecutivos queda bloqueado. Lee LEEME.txt.");

const RAIZ = __dirname;
// En el hosting, CARPETA_DATOS apunta a un disco que no se borra al reiniciar
const CARPETA_DATOS = process.env.CARPETA_DATOS || RAIZ;
const DATOS = path.join(CARPETA_DATOS, "datos.json");
const FOTOS = path.join(CARPETA_DATOS, "fotos");
if (!fs.existsSync(FOTOS)) fs.mkdirSync(FOTOS, { recursive: true });
// La primera vez en un disco nuevo se copian los libros y fotos que vienen con el proyecto
if (CARPETA_DATOS !== RAIZ && !fs.existsSync(DATOS)) {
  fs.copyFileSync(path.join(RAIZ, "datos.json"), DATOS);
  for (const f of fs.readdirSync(path.join(RAIZ, "fotos"))) fs.copyFileSync(path.join(RAIZ, "fotos", f), path.join(FOTOS, f));
}

// Solo se pueden ver estos tipos de archivo (así nadie puede descargar server.js o config.json)
const TIPOS = {
  ".html": "text/html; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};

function leerDatos() { return JSON.parse(fs.readFileSync(DATOS, "utf8")); }

function responder(res, codigo, cuerpo) {
  res.writeHead(codigo, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(cuerpo));
}

function leerCuerpo(req, limite = 15 * 1024 * 1024) {
  return new Promise((ok, mal) => {
    let tam = 0; const partes = [];
    req.on("data", c => {
      tam += c.length;
      if (tam > limite) { mal(new Error("El archivo es demasiado grande")); req.destroy(); }
      else partes.push(c);
    });
    req.on("end", () => ok(Buffer.concat(partes).toString("utf8")));
    req.on("error", mal);
  });
}

// Bloqueo por 15 minutos tras 10 claves equivocadas desde la misma conexión
const intentos = new Map();
function ipDe(req) { return String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim(); }
function bloqueado(req) {
  const i = intentos.get(ipDe(req));
  return i && i.fallos >= 10 && Date.now() - i.desde < 15 * 60 * 1000;
}
function anotarFallo(req) {
  const ip = ipDe(req), i = intentos.get(ip);
  if (!i || Date.now() - i.desde > 15 * 60 * 1000) intentos.set(ip, { fallos: 1, desde: Date.now() });
  else i.fallos++;
}

function claveCorrecta(req) {
  if (!CLAVE || bloqueado(req)) return false;
  const dada = Buffer.from(String(req.headers["x-clave"] || ""));
  const real = Buffer.from(CLAVE);
  const ok = dada.length === real.length && crypto.timingSafeEqual(dada, real);
  if (!ok) anotarFallo(req);
  return ok;
}

// Borra las fotos que ya ningún libro usa (las de la última hora se respetan,
// por si alguien acaba de subir una y todavía no ha guardado el libro)
function limpiarFotos(datos) {
  const usadas = new Set(datos.libros.map(l => l.foto).filter(Boolean).map(f => path.basename(f)));
  const haceUnaHora = Date.now() - 60 * 60 * 1000;
  for (const f of fs.readdirSync(FOTOS)) {
    const archivo = path.join(FOTOS, f);
    if (!usadas.has(f) && fs.statSync(archivo).mtimeMs < haceUnaHora) fs.unlinkSync(archivo);
  }
}

const servidor = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  try {
    // ---------- API ----------
    if (url.pathname === "/api/datos" && req.method === "GET") {
      return responder(res, 200, leerDatos());
    }

    if (url.pathname === "/api/login" && req.method === "POST") {
      if (bloqueado(req)) return responder(res, 429, { error: "Demasiados intentos. Espera 15 minutos." });
      return claveCorrecta(req) ? responder(res, 200, { ok: true }) : responder(res, 401, { error: "Clave incorrecta" });
    }

    if (url.pathname === "/api/datos" && req.method === "PUT") {
      if (!claveCorrecta(req)) return responder(res, 401, { error: "Clave incorrecta" });
      const datos = JSON.parse(await leerCuerpo(req));
      if (!datos.sitio || !Array.isArray(datos.libros)) return responder(res, 400, { error: "Datos inválidos" });
      datos.actualizado = Date.now();
      // se guarda primero en un archivo temporal para no dañar datos.json si algo falla
      fs.writeFileSync(DATOS + ".tmp", JSON.stringify(datos, null, 2));
      fs.renameSync(DATOS + ".tmp", DATOS);
      limpiarFotos(datos);
      return responder(res, 200, { ok: true, actualizado: datos.actualizado });
    }

    if (url.pathname === "/api/foto" && req.method === "POST") {
      if (!claveCorrecta(req)) return responder(res, 401, { error: "Clave incorrecta" });
      const { imagen } = JSON.parse(await leerCuerpo(req));
      const m = /^data:image\/(jpeg|png|webp);base64,(.+)$/.exec(imagen || "");
      if (!m) return responder(res, 400, { error: "Formato de imagen no válido" });
      const nombre = Date.now() + "-" + crypto.randomBytes(4).toString("hex") + "." + (m[1] === "jpeg" ? "jpg" : m[1]);
      fs.writeFileSync(path.join(FOTOS, nombre), Buffer.from(m[2], "base64"));
      return responder(res, 200, { ruta: "fotos/" + nombre });
    }

    if (url.pathname.startsWith("/api/")) return responder(res, 404, { error: "No existe" });

    // ---------- Páginas y fotos ----------
    let ruta = decodeURIComponent(url.pathname);
    if (ruta === "/") ruta = "/index.html";
    if (ruta === "/admin") ruta = "/admin.html";
    const base = ruta.startsWith("/fotos/") ? CARPETA_DATOS : RAIZ;
    const archivo = path.normalize(path.join(base, ruta));
    const tipo = TIPOS[path.extname(archivo).toLowerCase()];
    if (!archivo.startsWith(path.resolve(base) + path.sep) || !tipo || !fs.existsSync(archivo)) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Página no encontrada");
    }
    res.writeHead(200, { "Content-Type": tipo, "Cache-Control": tipo.startsWith("text/html") ? "no-store" : "max-age=86400" });
    fs.createReadStream(archivo).pipe(res);
  } catch (e) {
    responder(res, 500, { error: e.message });
  }
});

servidor.listen(PUERTO, () => {
  console.log("\n  📚 Biblioteca Virtual - Colegio San Cayetano\n");
  console.log("  En este computador:");
  console.log(`     Estudiantes:  http://localhost:${PUERTO}`);
  console.log(`     Ejecutivos:   http://localhost:${PUERTO}/admin`);
  const ips = Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === "IPv4" && !i.internal);
  if (ips.length) {
    console.log("\n  Desde celulares o tablets conectados al mismo wifi:");
    for (const i of ips) console.log(`     http://${i.address}:${PUERTO}`);
  }
  console.log("\n  Deja esta ventana abierta mientras se use la página. Para apagar: Ctrl + C\n");
});
