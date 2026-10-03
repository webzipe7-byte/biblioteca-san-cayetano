// Servidor de la Biblioteca Virtual - Colegio San Cayetano
// Iniciar con:  node server.js   (o doble clic en iniciar.bat)
// No necesita instalar nada: usa solo módulos que ya vienen con Node.

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");

const PUERTO = process.env.PORT || process.env.PUERTO || 3000;
// En internet (Render) hay un proxy delante que maneja HTTPS y pasa la IP real del visitante
const EN_INTERNET = !!(process.env.RENDER || process.env.EN_INTERNET);

// Clave del panel de ejecutivos: variable de entorno CLAVE (en el hosting) o config.json (en el colegio).
// No se escribe aquí para que no quede pública en GitHub.
let CLAVE = process.env.CLAVE || "";
if (!CLAVE) try { CLAVE = JSON.parse(fs.readFileSync(path.join(__dirname, "config.json"), "utf8")).clave || ""; } catch {}
if (!CLAVE) console.warn("\n  ⚠  No hay clave configurada: el panel de ejecutivos queda bloqueado. Lee LEEME.txt.");
else if (EN_INTERNET && CLAVE.length < 12) console.warn("\n  ⚠  La clave es muy corta para internet. Usa al menos 12 caracteres.");

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

// Solo se pueden ver estos archivos (así nadie puede descargar server.js, config.json o datos.json directo)
const PUBLICOS = { "/index.html": 1, "/admin.html": 1, "/logo.png": 1 };
const TIPOS = {
  ".html": "text/html; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
};
const NOMBRE_FOTO = /^\d{10,16}-[0-9a-f]{8}\.(jpg|png|webp)$/;

// ---------- Cabeceras de seguridad ----------
// Política de contenido: solo se ejecutan los scripts propios de cada página (por su huella),
// así un texto malicioso guardado en los datos nunca puede correr como código.
const cachePaginas = new Map();
function leerPagina(archivo) {
  const mtime = fs.statSync(archivo).mtimeMs;
  const c = cachePaginas.get(archivo);
  if (c && c.mtime === mtime) return c;
  const html = fs.readFileSync(archivo);
  const huellas = [...html.toString("utf8").matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map(m => `'sha256-${crypto.createHash("sha256").update(m[1], "utf8").digest("base64")}'`);
  const csp = [
    "default-src 'none'",
    `script-src ${huellas.join(" ") || "'none'"}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(EN_INTERNET ? ["upgrade-insecure-requests"] : []),
  ].join("; ");
  const nueva = { mtime, html, csp };
  cachePaginas.set(archivo, nueva);
  return nueva;
}

function cabecerasBase(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  if (EN_INTERNET) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

function leerDatos() { return JSON.parse(fs.readFileSync(DATOS, "utf8")); }

function responder(res, codigo, cuerpo) {
  res.writeHead(codigo, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(cuerpo));
}

function leerCuerpo(req, limite) {
  return new Promise((ok, mal) => {
    if (+req.headers["content-length"] > limite) return mal(Object.assign(new Error("El envío es demasiado grande"), { codigo: 413 }));
    let tam = 0; const partes = [];
    req.on("data", c => {
      tam += c.length;
      if (tam > limite) { mal(Object.assign(new Error("El envío es demasiado grande"), { codigo: 413 })); req.destroy(); }
      else partes.push(c);
    });
    req.on("end", () => ok(Buffer.concat(partes).toString("utf8")));
    req.on("error", mal);
  });
}

function jsonDe(texto) {
  try { return JSON.parse(texto); }
  catch { throw Object.assign(new Error("Datos inválidos"), { codigo: 400 }); }
}

// ---------- Límite de intentos ----------
// IP del visitante. Detrás del proxy de Render, la IP real es la última que agrega el proxy
// (las anteriores las puede inventar cualquiera).
function ipDe(req) {
  if (EN_INTERNET && req.headers["x-forwarded-for"]) {
    const lista = String(req.headers["x-forwarded-for"]).split(",").map(s => s.trim()).filter(Boolean);
    if (lista.length) return lista[lista.length - 1];
  }
  return req.socket.remoteAddress || "";
}

// Ventanas de conteo por IP: { clave: { n, desde } }
const contadores = new Map();
function contar(tipo, req, maximo, minutos) {
  const k = tipo + "|" + ipDe(req), ahora = Date.now(), ventana = minutos * 60 * 1000;
  let c = contadores.get(k);
  if (!c || ahora - c.desde > ventana) { c = { n: 0, desde: ahora }; contadores.set(k, c); }
  c.n++;
  return c.n > maximo;
}
function excedido(tipo, req, maximo, minutos) {
  const c = contadores.get(tipo + "|" + ipDe(req));
  return !!c && Date.now() - c.desde <= minutos * 60 * 1000 && c.n >= maximo;
}
// Limpieza para que la memoria no crezca
setInterval(() => {
  const ahora = Date.now();
  for (const [k, c] of contadores) if (ahora - c.desde > 60 * 60 * 1000) contadores.delete(k);
  for (const [t, s] of sesiones) if (s.expira < ahora) sesiones.delete(t);
}, 10 * 60 * 1000).unref();

// ---------- Sesiones ----------
// Al entrar se entrega una sesión temporal; la clave nunca se guarda en el navegador.
const sesiones = new Map();
const DURACION_SESION = 8 * 60 * 60 * 1000;

function claveCorrecta(dada) {
  if (!CLAVE) return false;
  // Se comparan huellas de igual largo para no revelar nada por el tiempo de respuesta
  const a = crypto.createHash("sha256").update(String(dada)).digest();
  const b = crypto.createHash("sha256").update(CLAVE).digest();
  return crypto.timingSafeEqual(a, b);
}

function sesionValida(req) {
  const t = String(req.headers["x-sesion"] || "");
  const s = t && sesiones.get(t);
  if (!s) return false;
  if (s.expira < Date.now()) { sesiones.delete(t); return false; }
  return true;
}

// Las peticiones que cambian algo deben venir de esta misma página
function mismoOrigen(req) {
  const origen = req.headers.origin;
  if (!origen) return true; // navegadores viejos o la misma página sin Origin; la sesión igual se exige
  try { return new URL(origen).host === req.headers.host; } catch { return false; }
}

// ---------- Validación de datos ----------
const texto = (v, max) => String(v ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max);
const entero = (v, max) => { const n = Math.floor(Number(v)); return Number.isFinite(n) ? Math.min(Math.max(n, 0), max) : 0; };
const color = v => /^#[0-9a-fA-F]{6}$/.test(String(v)) ? String(v) : "#2f7fe0";
const enlace = v => {
  const s = texto(v, 300);
  if (!s) return "";
  try { const u = new URL(s); return u.protocol === "https:" ? u.href : ""; } catch { return ""; }
};
const foto = v => {
  const s = String(v ?? "");
  const m = /^fotos\/(.+)$/.exec(s);
  return m && NOMBRE_FOTO.test(m[1]) && fs.existsSync(path.join(FOTOS, m[1])) ? s : "";
};

function limpiarDatos(d) {
  if (!d || typeof d !== "object" || !d.sitio || typeof d.sitio !== "object" || !Array.isArray(d.libros)) return null;
  if (d.libros.length > 2000) return null;
  const s = d.sitio, redes = (s.redes && typeof s.redes === "object") ? s.redes : {};
  const categorias = (Array.isArray(s.categorias) ? s.categorias : [])
    .map(c => texto(c, 40)).filter(Boolean).filter((c, i, a) => a.indexOf(c) === i).slice(0, 50);
  const sitio = {
    seccion: texto(s.seccion, 60), subtitulo: texto(s.subtitulo, 80),
    titulo: texto(s.titulo, 80), tituloResaltado: texto(s.tituloResaltado, 80),
    bannerTitulo: texto(s.bannerTitulo, 100), bannerTexto: texto(s.bannerTexto, 500),
    catalogoTitulo: texto(s.catalogoTitulo, 100), pie: texto(s.pie, 200),
    redes: { facebook: enlace(redes.facebook), instagram: enlace(redes.instagram), youtube: enlace(redes.youtube) },
    categorias,
  };
  const ids = new Set();
  const libros = d.libros.filter(l => l && typeof l === "object").map(l => {
    let id = texto(l.id, 40).replace(/[^\w-]/g, "");
    if (!id || ids.has(id)) id = "l" + Date.now() + crypto.randomBytes(3).toString("hex");
    ids.add(id);
    const unidades = entero(l.unidades, 10000);
    return {
      id,
      titulo: texto(l.titulo, 150) || "Sin título",
      autor: texto(l.autor, 120),
      año: texto(l.año, 40),
      categoria: texto(l.categoria, 40),
      paginas: l.paginas === "" || l.paginas == null ? "" : entero(l.paginas, 100000),
      ubicacion: texto(l.ubicacion, 80),
      unidades,
      disponibles: Math.min(entero(l.disponibles, 10000), unidades),
      color: color(l.color),
      icono: texto(l.icono, 8) || "📘",
      descripcion: texto(l.descripcion, 3000),
      foto: foto(l.foto),
    };
  });
  return { sitio, libros };
}

// Revisa que el archivo sea de verdad una imagen mirando sus primeros bytes
function tipoReal(buf) {
  if (buf.length > 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return "jpg";
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))) return "png";
  if (buf.length > 12 && buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "webp";
  return null;
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
  cabecerasBase(res);
  let url;
  try { url = new URL(req.url, "http://x"); }
  catch { res.writeHead(400); return res.end(); }

  // En internet todo va por HTTPS
  if (EN_INTERNET && req.headers["x-forwarded-proto"] === "http") {
    res.writeHead(301, { Location: "https://" + req.headers.host + req.url });
    return res.end();
  }

  try {
    // ---------- API ----------
    if (url.pathname.startsWith("/api/")) {
      // Límite general: 300 peticiones a la API por minuto por conexión
      if (contar("api", req, 300, 1)) return responder(res, 429, { error: "Demasiadas peticiones. Espera un momento." });
      const cambia = req.method !== "GET" && req.method !== "HEAD";
      if (cambia && !mismoOrigen(req)) return responder(res, 403, { error: "Origen no permitido" });
      if (cambia && req.method !== "POST" && !/^application\/json\b/.test(req.headers["content-type"] || ""))
        return responder(res, 415, { error: "Formato no permitido" });

      if (url.pathname === "/api/datos" && req.method === "GET") {
        return responder(res, 200, leerDatos());
      }

      if (url.pathname === "/api/login" && req.method === "POST") {
        // Tras 10 claves equivocadas en 15 minutos, esa conexión queda bloqueada 15 minutos
        if (excedido("fallo", req, 10, 15)) return responder(res, 429, { error: "Demasiados intentos. Espera 15 minutos." });
        if (!claveCorrecta(req.headers["x-clave"] || "")) {
          contar("fallo", req, 10, 15);
          await new Promise(r => setTimeout(r, 400)); // frena a quien prueba claves en automático
          return responder(res, 401, { error: "Clave incorrecta" });
        }
        if (sesiones.size > 200) sesiones.delete(sesiones.keys().next().value);
        const token = crypto.randomBytes(32).toString("base64url");
        sesiones.set(token, { expira: Date.now() + DURACION_SESION });
        return responder(res, 200, { ok: true, sesion: token });
      }

      if (url.pathname === "/api/sesion" && req.method === "GET") {
        return sesionValida(req) ? responder(res, 200, { ok: true }) : responder(res, 401, { error: "Sesión vencida" });
      }

      if (url.pathname === "/api/logout" && req.method === "POST") {
        sesiones.delete(String(req.headers["x-sesion"] || ""));
        return responder(res, 200, { ok: true });
      }

      if (url.pathname === "/api/datos" && req.method === "PUT") {
        if (!sesionValida(req)) return responder(res, 401, { error: "Sesión vencida" });
        const datos = limpiarDatos(jsonDe(await leerCuerpo(req, 2 * 1024 * 1024)));
        if (!datos) return responder(res, 400, { error: "Datos inválidos" });
        datos.actualizado = Date.now();
        // se guarda primero en un archivo temporal para no dañar datos.json si algo falla
        fs.writeFileSync(DATOS + ".tmp", JSON.stringify(datos, null, 2));
        fs.renameSync(DATOS + ".tmp", DATOS);
        limpiarFotos(datos);
        return responder(res, 200, { ok: true, actualizado: datos.actualizado });
      }

      if (url.pathname === "/api/foto" && req.method === "POST") {
        if (!sesionValida(req)) return responder(res, 401, { error: "Sesión vencida" });
        if (contar("foto", req, 60, 60)) return responder(res, 429, { error: "Demasiadas fotos seguidas. Espera un rato." });
        const { imagen } = jsonDe(await leerCuerpo(req, 8 * 1024 * 1024)) || {};
        const m = /^data:image\/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(typeof imagen === "string" ? imagen : "");
        if (!m) return responder(res, 400, { error: "Formato de imagen no válido" });
        const buf = Buffer.from(m[2], "base64");
        const tipo = tipoReal(buf);
        if (!tipo) return responder(res, 400, { error: "Ese archivo no es una imagen válida" });
        const nombre = Date.now() + "-" + crypto.randomBytes(4).toString("hex") + "." + tipo;
        fs.writeFileSync(path.join(FOTOS, nombre), buf);
        return responder(res, 200, { ruta: "fotos/" + nombre });
      }

      return responder(res, 404, { error: "No existe" });
    }

    // ---------- Páginas y fotos ----------
    if (req.method !== "GET" && req.method !== "HEAD") {
      res.writeHead(405, { Allow: "GET, HEAD" });
      return res.end();
    }
    let ruta = url.pathname;
    if (ruta === "/") ruta = "/index.html";
    if (ruta === "/admin") ruta = "/admin.html";

    let archivo = null;
    if (PUBLICOS[ruta]) archivo = path.join(RAIZ, ruta);
    else if (ruta.startsWith("/fotos/") && NOMBRE_FOTO.test(ruta.slice(7))) archivo = path.join(FOTOS, ruta.slice(7));
    if (!archivo || !fs.existsSync(archivo)) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      return res.end("Página no encontrada");
    }
    const tipo = TIPOS[path.extname(archivo).toLowerCase()];
    if (tipo.startsWith("text/html")) {
      const p = leerPagina(archivo);
      const cab = { "Content-Type": tipo, "Cache-Control": "no-store", "Content-Security-Policy": p.csp };
      if (ruta === "/admin.html") cab["X-Robots-Tag"] = "noindex, nofollow";
      res.writeHead(200, cab);
      return res.end(req.method === "HEAD" ? undefined : p.html);
    }
    res.writeHead(200, { "Content-Type": tipo, "Cache-Control": "max-age=86400" });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(archivo).pipe(res);
  } catch (e) {
    // No se muestran detalles internos a los visitantes
    if (!e.codigo) console.error(e);
    if (!res.headersSent) responder(res, e.codigo || 500, { error: e.codigo ? e.message : "Error del servidor" });
  }
});

// Cierra conexiones lentas o colgadas
servidor.headersTimeout = 15 * 1000;
servidor.requestTimeout = 60 * 1000;
servidor.keepAliveTimeout = 5 * 1000;

servidor.listen(PUERTO, () => {
  console.log("\n  📚 Biblioteca Virtual - Colegio San Cayetano\n");
  if (EN_INTERNET) return console.log(`  Funcionando en internet (puerto ${PUERTO}).\n`);
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
