const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");

const ROOT = __dirname;
const CONTENT_FILE = path.join(ROOT, "content.json");
const OWNER_CONFIG_FILE = path.join(ROOT, "owner-config.json");
const PORT = Number(process.env.PORT || 3000);
const ENV_OWNER_EMAIL = (process.env.OWNER_EMAIL || "").trim().toLowerCase();
const ENV_OWNER_PASSWORD = process.env.OWNER_PASSWORD || "";
const ENV_SESSION_SECRET = process.env.SESSION_SECRET || "";
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const COOKIE_NAME = "suazo_owner";
const secureCookie = process.env.NODE_ENV === "production";
const loginAttempts = new Map();
const activeSessions = new Map();
let ownerEmail = "";
let passwordSalt;
let passwordHash;
let hmacKey;
let setupRequired = true;
let setupInProgress = false;

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

async function loadOwnerCredentials() {
  const hasEnvironmentConfig = Boolean(ENV_OWNER_EMAIL || ENV_OWNER_PASSWORD || ENV_SESSION_SECRET);
  if (hasEnvironmentConfig) {
    if (!isValidEmail(ENV_OWNER_EMAIL) || ENV_OWNER_PASSWORD.length < 14 || ENV_SESSION_SECRET.length < 32) {
      throw new Error(
        "Configura OWNER_EMAIL, OWNER_PASSWORD (mínimo 14 caracteres) y SESSION_SECRET (mínimo 32 caracteres)."
      );
    }
    ownerEmail = ENV_OWNER_EMAIL;
    passwordSalt = crypto.randomBytes(16);
    passwordHash = crypto.scryptSync(ENV_OWNER_PASSWORD, passwordSalt, 64);
    hmacKey = Buffer.from(ENV_SESSION_SECRET, "utf8");
    setupRequired = false;
    return;
  }

  let savedConfig;
  try {
    savedConfig = JSON.parse(await fs.readFile(OWNER_CONFIG_FILE, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw new Error(`No se pudo leer ${path.basename(OWNER_CONFIG_FILE)}: ${error.message}`);
  }

  if (!savedConfig || typeof savedConfig.email !== "string" || !isValidEmail(savedConfig.email) ||
      typeof savedConfig.passwordSalt !== "string" ||
      typeof savedConfig.passwordHash !== "string" ||
      typeof savedConfig.sessionSecret !== "string") {
    throw new Error(`${path.basename(OWNER_CONFIG_FILE)} no tiene una configuración válida.`);
  }

  const savedSalt = Buffer.from(savedConfig.passwordSalt, "base64url");
  const savedHash = Buffer.from(savedConfig.passwordHash, "base64url");
  if (savedSalt.length !== 16 || savedHash.length !== 64 || savedConfig.sessionSecret.length < 32) {
    throw new Error(`${path.basename(OWNER_CONFIG_FILE)} no tiene una configuración válida.`);
  }

  ownerEmail = savedConfig.email;
  passwordSalt = savedSalt;
  passwordHash = savedHash;
  hmacKey = Buffer.from(savedConfig.sessionSecret, "utf8");
  setupRequired = false;
}

function sendJson(res, status, value) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(value));
}

function safeEqual(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function sessionCookie(value, maxAge = SESSION_TTL_SECONDS) {
  const attributes = [
    `${COOKIE_NAME}=${value}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAge}`
  ];
  if (secureCookie) attributes.push("Secure");
  return attributes.join("; ");
}

function signSession(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", hmacKey).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function readSession(req) {
  const cookieHeader = req.headers.cookie || "";
  const cookie = cookieHeader.split(";").map((part) => part.trim())
    .find((part) => part.startsWith(`${COOKIE_NAME}=`));
  if (!cookie) return null;

  const token = cookie.slice(COOKIE_NAME.length + 1);
  if (token.length > 2048) return null;
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) return null;

  const expected = crypto.createHmac("sha256", hmacKey).update(encoded).digest("base64url");
  if (!safeEqual(signature, expected)) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (payload.email !== ownerEmail || payload.exp < Date.now() || !payload.csrf ||
        activeSessions.get(payload.sid) !== payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function isSameOrigin(req) {
  const origin = req.headers.origin;
  const host = req.headers.host;
  if (!origin || !host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

async function readJson(req, limit = 32 * 1024) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > limit) {
      const error = new Error("La solicitud es demasiado grande.");
      error.status = 413;
      throw error;
    }
  }
  try {
    return JSON.parse(body);
  } catch {
    const error = new Error("El formato de la solicitud no es válido.");
    error.status = 400;
    throw error;
  }
}

function validateContent(value) {
  const fields = ["brandName", "pageTitle", "metaDescription", "tagline"];
  const maximums = { brandName: 40, pageTitle: 80, metaDescription: 250, tagline: 100 };
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;

  const result = {};
  for (const field of fields) {
    if (typeof value[field] !== "string") return null;
    result[field] = value[field].trim();
    if (!result[field] || result[field].length > maximums[field]) return null;
  }

  if (!Array.isArray(value.services) || value.services.length < 1 || value.services.length > 30) return null;
  result.services = [];
  for (const service of value.services) {
    if (!service || typeof service !== "object") return null;
    const clean = {};
    for (const [field, maximum] of [["name", 50], ["description", 220], ["duration", 30], ["price", 8]]) {
      if (typeof service[field] !== "string") return null;
      clean[field] = service[field].trim();
      if (!clean[field] || clean[field].length > maximum) return null;
    }
    if (!/^\d{1,4}(?:[.,]\d{1,2})?$/.test(clean.price)) return null;
    result.services.push(clean);
  }
  return result;
}

function loginIsLimited(key) {
  const now = Date.now();
  const attempt = loginAttempts.get(key);
  if (!attempt || now - attempt.startedAt >= 15 * 60 * 1000) {
    loginAttempts.set(key, { startedAt: now, count: 0 });
    return false;
  }
  return attempt.count >= 5;
}

function recordLoginFailure(key) {
  const attempt = loginAttempts.get(key);
  if (attempt) attempt.count += 1;
}

function clearLoginFailures(key) {
  loginAttempts.delete(key);
}

function isLoopback(address) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function isLocalRequest(req) {
  if (!isLoopback(req.socket.remoteAddress || "")) return false;
  try {
    const hostname = new URL(`http://${req.headers.host}`).hostname.toLowerCase();
    return hostname === "localhost" || hostname === "127.0.0.1";
  } catch {
    return false;
  }
}

function createOwnerSession(res) {
  const session = {
    email: ownerEmail,
    sid: crypto.randomBytes(24).toString("base64url"),
    csrf: crypto.randomBytes(32).toString("base64url"),
    exp: Date.now() + SESSION_TTL_SECONDS * 1000
  };
  activeSessions.set(session.sid, session.exp);
  res.setHeader("Set-Cookie", sessionCookie(signSession(session)));
}

async function handleRequest(req, res) {
  const url = new URL(req.url, "http://localhost");
  const pathname = url.pathname;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self' 'unsafe-inline'; img-src 'self' https://d375139ucebi94.cloudfront.net data:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-src https://maps.google.com https://www.google.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");

  if (req.method === "GET" && pathname === "/api/content") {
    try {
      const content = JSON.parse(await fs.readFile(CONTENT_FILE, "utf8"));
      return sendJson(res, 200, content);
    } catch (error) {
      console.error("No se pudo leer content.json:", error);
      return sendJson(res, 500, { error: "No se pudo cargar el contenido." });
    }
  }

  if (req.method === "POST" && pathname === "/api/setup") {
    if (!setupRequired || setupInProgress) {
      return sendJson(res, 409, { error: "El acceso del dueño ya está configurado." });
    }
    if (!isSameOrigin(req) || !isLocalRequest(req)) {
      return sendJson(res, 403, { error: "La configuración inicial solo se permite desde este ordenador." });
    }

    const body = await readJson(req, 4096);
    const email = body && typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = body && typeof body.password === "string" ? body.password : "";
    if (!isValidEmail(email) || email.length > 254 || password.length < 14 || password.length > 128) {
      return sendJson(res, 400, { error: "Introduce un correo válido y una contraseña de 14 a 128 caracteres." });
    }
    if (!setupRequired || setupInProgress) {
      return sendJson(res, 409, { error: "El acceso del dueño ya está configurado." });
    }

    setupInProgress = true;
    const salt = crypto.randomBytes(16);
    const sessionSecret = crypto.randomBytes(48).toString("base64url");
    const config = {
      email,
      passwordSalt: salt.toString("base64url"),
      passwordHash: crypto.scryptSync(password, salt, 64).toString("base64url"),
      sessionSecret
    };
    const temporaryFile = `${OWNER_CONFIG_FILE}.${process.pid}.tmp`;
    try {
      await fs.writeFile(temporaryFile, `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      await fs.rename(temporaryFile, OWNER_CONFIG_FILE);
      ownerEmail = config.email;
      passwordSalt = salt;
      passwordHash = Buffer.from(config.passwordHash, "base64url");
      hmacKey = Buffer.from(sessionSecret, "utf8");
      setupRequired = false;
      createOwnerSession(res);
      return sendJson(res, 200, { ok: true });
    } catch (error) {
      console.error("No se pudo guardar la configuración del dueño:", error);
      return sendJson(res, 500, { error: "No se pudo guardar el acceso del dueño." });
    } finally {
      setupInProgress = false;
    }
  }

  if (req.method === "POST" && pathname === "/api/login") {
    if (setupRequired) return sendJson(res, 409, { setupRequired: true, error: "Primero configura el acceso del dueño." });
    if (!isSameOrigin(req)) return sendJson(res, 403, { error: "Solicitud no permitida." });
    const key = req.socket.remoteAddress || "unknown";
    if (loginAttempts.size > 5000) loginAttempts.clear();
    if (loginIsLimited(key)) return sendJson(res, 429, { error: "Demasiados intentos. Espera 15 minutos." });
    const body = await readJson(req, 4096);
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return sendJson(res, 400, { error: "Introduce el correo y la contraseña." });
    }
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const candidateHash = crypto.scryptSync(password, passwordSalt, 64);
    if (!safeEqual(email, OWNER_EMAIL) || !crypto.timingSafeEqual(candidateHash, passwordHash)) {
      recordLoginFailure(key);
      return sendJson(res, 401, { error: "Correo o contraseña incorrectos." });
    }

    clearLoginFailures(key);
    for (const [sid, expiry] of activeSessions) {
      if (expiry < Date.now()) activeSessions.delete(sid);
    }
    createOwnerSession(res);
    return sendJson(res, 200, { ok: true });
  }

  if (pathname.startsWith("/api/")) {
    if (setupRequired && req.method === "GET" && pathname === "/api/session") {
      return sendJson(res, 409, { setupRequired: true, error: "Configura el acceso del dueño para empezar." });
    }
    const session = readSession(req);
    if (!session) return sendJson(res, 401, { error: "Inicia sesión para continuar." });

    if (req.method === "GET" && pathname === "/api/session") {
      return sendJson(res, 200, { email: session.email, csrf: session.csrf });
    }

    if (!isSameOrigin(req) || req.headers["x-csrf-token"] !== session.csrf) {
      return sendJson(res, 403, { error: "La solicitud no superó la validación de seguridad." });
    }

    if (req.method === "POST" && pathname === "/api/logout") {
      activeSessions.delete(session.sid);
      res.setHeader("Set-Cookie", sessionCookie("", 0));
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === "PUT" && pathname === "/api/content") {
      const content = validateContent(await readJson(req));
      if (!content) return sendJson(res, 400, { error: "Revisa los campos y servicios introducidos." });
      const temporaryFile = `${CONTENT_FILE}.tmp`;
      try {
        await fs.writeFile(temporaryFile, `${JSON.stringify(content, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
        await fs.rename(temporaryFile, CONTENT_FILE);
        return sendJson(res, 200, { ok: true });
      } catch (error) {
        console.error("No se pudo guardar content.json:", error);
        return sendJson(res, 500, { error: "No se pudieron guardar los cambios." });
      }
    }
    return sendJson(res, 404, { error: "Ruta no encontrada." });
  }

  if (req.method === "GET") {
    if (setupRequired && (pathname === "/admin" || pathname === "/admin.html") && !isLocalRequest(req)) {
      return sendJson(res, 404, { error: "No encontrado." });
    }
    const files = {
      "/": "index.html",
      "/index.html": "index.html",
      "/admin": "admin.html",
      "/admin.html": "admin.html"
    };
    const file = files[pathname];
    if (file) {
      try {
        const content = await fs.readFile(path.join(ROOT, file));
        res.writeHead(200, {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store"
        });
        return res.end(content);
      } catch (error) {
        console.error(`No se pudo servir ${file}:`, error);
        return sendJson(res, 500, { error: "No se pudo servir la página." });
      }
    }
  }

  return sendJson(res, 404, { error: "No encontrado." });
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((error) => {
    console.error("Error procesando solicitud:", error);
    if (!res.headersSent) sendJson(res, error.status || 500, { error: error.status ? error.message : "Error interno del servidor." });
    else res.destroy();
  });
});

loadOwnerCredentials().then(() => {
  const host = setupRequired ? "127.0.0.1" : (process.env.HOST || "0.0.0.0");
  server.listen(PORT, host, () => {
    console.log(`Web de Suazo Barber 504 disponible en http://localhost:${PORT}`);
    console.log(`Panel del dueño: http://localhost:${PORT}/admin`);
    if (setupRequired) console.log("Configuración inicial: crea el acceso del dueño desde este ordenador.");
  });
}).catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
