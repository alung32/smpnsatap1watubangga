
const encoder = new TextEncoder();
const ITERATIONS = 210000;
const COOKIE = "__Host-school_session";

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  return `pbkdf2$${ITERATIONS}$${base64url(salt)}$${base64url(bits)}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterations, saltText, hashText] = stored.split("$");
    if (algorithm !== "pbkdf2") return false;

    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt: fromBase64url(saltText),
      iterations: Number(iterations),
      hash: "SHA-256"
    }, key, 256);

    const actual = new Uint8Array(bits);
    const expected = fromBase64url(hashText);

    if (actual.length !== expected.length) return false;

    let diff = 0;
    for (let i = 0; i < actual.length; i++) {
      diff |= actual[i] ^ expected[i];
    }
    return diff === 0;
  } catch {
    return false;
  }
}

async function secretMatches(a, b) {
  if (!a || !b) return false;
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);
  const aa = new Uint8Array(x);
  const bb = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}

async function signSession(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );

  const data = base64url(encoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign(
    "HMAC", key, encoder.encode(data)
  );

  return `${data}.${base64url(signature)}`;
}

async function readSession(request, secret) {
  try {
    if (!secret) return null;

    const cookie = request.headers.get("Cookie") || "";
    const item = cookie.split(";").map(v => v.trim())
      .find(v => v.startsWith(COOKIE + "="));

    if (!item) return null;

    const token = item.slice(COOKIE.length + 1);
    const [data, signature] = token.split(".");
    if (!data || !signature) return null;

    const key = await crypto.subtle.importKey(
      "raw", encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false, ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC", key, fromBase64url(signature), encoder.encode(data)
    );

    if (!valid) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64url(data))
    );

    if (!payload.exp || payload.exp < Date.now()) return null;

    return payload;
  } catch {
    return null;
  }
}

function sessionCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`;
}

function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

async function body(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function validCredentials(email, password) {
  return typeof email === "string" &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    typeof password === "string" &&
    password.length >= 12 &&
    password.length <= 128;
}

async function requireLogin(request, env) {
  const session = await readSession(
    request,
    env.AUTH_SECRET
  );

  if (!session || !session.id) {
    return null;
  }

  const user = await env.DB.prepare(`
    SELECT id, email, role
    FROM admins
    WHERE id = ?
    LIMIT 1
  `).bind(session.id).first();

  if (!user) {
    return null;
  }

  if (!["kepala_sekolah", "operator"].includes(user.role)) {
    return null;
  }

  return user;
}
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // HEALTH CHECK
      if (path === "/api/health" && method === "GET") {
        await env.DB.prepare("SELECT 1").first();
        return json({
          success: true,
          message: "Backend website sekolah aktif",
          database: "connected"
        });
      }

      // ONE-TIME KEPALA SEKOLAH REGISTRATION
      if (path === "/api/auth/bootstrap" && method === "POST") {
        const input = await body(request);

        if (!env.BOOTSTRAP_SECRET) {
          return json({ success: false, message: "Bootstrap tidak dikonfigurasi" }, 503);
        }

        if (!input || !await secretMatches(
          input.bootstrapSecret, env.BOOTSTRAP_SECRET
        )) {
          return json({ success: false, message: "Kode pendaftaran tidak valid" }, 403);
        }

        const email = String(input.email || "").trim().toLowerCase();
        const password = input.password;

        if (!validCredentials(email, password)) {
          return json({
            success: false,
            message: "Email atau password tidak memenuhi ketentuan. Password minimal 12 karakter."
          }, 400);
        }

        const passwordHash = await hashPassword(password);

        const result = await env.DB.prepare(`
          INSERT INTO admins (email, password_hash, role)
          SELECT ?, ?, 'kepala_sekolah'
          WHERE NOT EXISTS (SELECT 1 FROM admins)
        `).bind(email, passwordHash).run();

        if (result.meta.changes !== 1) {
          return json({
            success: false,
            message: "Pendaftaran awal sudah ditutup karena akun administrator telah tersedia."
          }, 409);
        }

        return json({
          success: true,
          message: "Akun Kepala Sekolah berhasil dibuat. Silakan login."
        }, 201);
      }

      // LOGIN
      if (path === "/api/auth/login" && method === "POST") {
        if (!env.AUTH_SECRET) {
          return json({ success: false, message: "AUTH_SECRET belum dikonfigurasi" }, 503);
        }

        const input = await body(request);
        const email = String(input?.email || "").trim().toLowerCase();
        const password = input?.password;

        if (!email || typeof password !== "string") {
          return json({ success: false, message: "Email dan password wajib diisi" }, 400);
        }

        const admin = await env.DB.prepare(
          "SELECT id, email, password_hash, role FROM admins WHERE email = ? LIMIT 1"
        ).bind(email).first();

        if (!admin || !await verifyPassword(password, admin.password_hash)) {
          return json({ success: false, message: "Email atau password salah" }, 401);
        }

        if (!["kepala_sekolah", "operator"].includes(admin.role)) {
          return json({ success: false, message: "Hak akses tidak valid" }, 403);
        }

        await env.DB.prepare(
          "UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?"
        ).bind(admin.id).run();

        const token = await signSession({
          id: admin.id,
          email: admin.email,
          role: admin.role,
          exp: Date.now() + 8 * 60 * 60 * 1000
        }, env.AUTH_SECRET);

        return json({
          success: true,
          message: "Login berhasil",
          user: {
            id: admin.id,
            email: admin.email,
            role: admin.role
          }
        }, 200, { "Set-Cookie": sessionCookie(token) });
      }

      // CHECK CURRENT SESSION
      if (path === "/api/auth/me" && method === "GET") {
        const user = await requireLogin(request, env);
        if (!user) return json({ success: false, message: "Belum login" }, 401);

        return json({ success: true, user });
      }

      // LOGOUT
      if (path === "/api/auth/logout" && method === "POST") {
        return json({
          success: true,
          message: "Logout berhasil"
        }, 200, { "Set-Cookie": clearCookie() });
      }

      // ADMINISTRATOR PROTECTION
      if (path.startsWith("/api/admin/")) {
        const user = await requireLogin(request, env);

        if (!user) {
          return json({ success: false, message: "Silakan login terlebih dahulu" }, 401);
        }

        // LIST OPERATORS
        if (path === "/api/admin/operators" && method === "GET") {
          if (user.role !== "kepala_sekolah") {
            return json({ success: false, message: "Akses ditolak" }, 403);
          }

          const result = await env.DB.prepare(`
            SELECT id, email, role, created_at, last_login
            FROM admins WHERE role = 'operator'
            ORDER BY id DESC
          `).all();

          return json({ success: true, operators: result.results });
        }

        // CREATE OPERATOR
        if (path === "/api/admin/operators" && method === "POST") {
          if (user.role !== "kepala_sekolah") {
            return json({ success: false, message: "Akses ditolak" }, 403);
          }

          const input = await body(request);
          const email = String(input?.email || "").trim().toLowerCase();
          const password = input?.password;

          if (!validCredentials(email, password)) {
            return json({
              success: false,
              message: "Email tidak valid atau password kurang dari 12 karakter"
            }, 400);
          }

          const passwordHash = await hashPassword(password);

          try {
            await env.DB.prepare(`
              INSERT INTO admins (email, password_hash, role)
              VALUES (?, ?, 'operator')
            `).bind(email, passwordHash).run();

            return json({
              success: true,
              message: "Akun operator berhasil dibuat"
            }, 201);
          } catch (error) {
            if (String(error).toLowerCase().includes("unique")) {
              return json({ success: false, message: "Email sudah digunakan" }, 409);
            }
            throw error;
          }
        }

        // DELETE OPERATOR
        const match = path.match(/^\/api\/admin\/operators\/(\d+)$/);

        if (match && method === "DELETE") {
          if (user.role !== "kepala_sekolah") {
            return json({ success: false, message: "Akses ditolak" }, 403);
          }

          const result = await env.DB.prepare(`
            DELETE FROM admins WHERE id = ? AND role = 'operator'
          `).bind(Number(match[1])).run();

          if (result.meta.changes !== 1) {
            return json({ success: false, message: "Operator tidak ditemukan" }, 404);
          }

          return json({ success: true, message: "Akun operator berhasil dihapus" });
        }

        return json({ success: false, message: "API administrator tidak ditemukan" }, 404);
      }

      // OTHER API PATHS
      if (path.startsWith("/api/")) {
        return json({ success: false, message: "API tidak ditemukan" }, 404);
      }

      // PUBLIC WEBSITE
      return env.ASSETS.fetch(request);

    } catch (error) {
      console.error("Backend error:", error);
      return json({
        success: false,
        message: "Terjadi kesalahan pada server"
      }, 500);
    }
  }
};
