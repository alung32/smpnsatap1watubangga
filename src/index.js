const encoder = new TextEncoder();
const ITERATIONS = 210000;
const COOKIE = "__Host-school_session";

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store", ...headers }
  });
}
function base64url(bytes) {
  let binary = "";
  for (const b of new Uint8Array(bytes)) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256"
  }, key, 256);
  return `pbkdf2$${ITERATIONS}$${base64url(salt)}$${base64url(bits)}`;
}
async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterations, saltText, hashText] = stored.split("$");
    if (algorithm !== "pbkdf2") return false;
    const rounds = Number(iterations);
    if (!Number.isInteger(rounds) || rounds < 100000 || rounds > 600000) return false;
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2", salt: fromBase64url(saltText), iterations: rounds, hash: "SHA-256"
    }, key, 256);
    const actual = new Uint8Array(bits), expected = fromBase64url(hashText);
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}
async function secretMatches(a, b) {
  if (!a || !b) return false;
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);
  const aa = new Uint8Array(x), bb = new Uint8Array(y);
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i] ^ bb[i];
  return diff === 0;
}
async function signSession(payload, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const data = base64url(encoder.encode(JSON.stringify(payload)));
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(data));
  return `${data}.${base64url(signature)}`;
}
async function readSession(request, secret) {
  try {
    if (!secret) return null;
    const cookie = request.headers.get("Cookie") || "";
    const item = cookie.split(";").map(v => v.trim()).find(v => v.startsWith(COOKIE + "="));
    if (!item) return null;
    const token = item.slice(COOKIE.length + 1);
    const [data, signature] = token.split(".");
    if (!data || !signature) return null;
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify("HMAC", key, fromBase64url(signature), encoder.encode(data));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(data)));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}
function sessionCookie(token) {
  return `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`;
}
function clearCookie() {
  return `${COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}
async function body(request) {
  try { return await request.json(); } catch { return null; }
}
function validCredentials(email, password) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) &&
    typeof password === "string" && password.length >= 12 && password.length <= 128;
}
async function requireLogin(request, env) {
  const session = await readSession(request, env.AUTH_SECRET);
  if (!session || !session.id) return null;
  const user = await env.DB.prepare(`
    SELECT id, email, role FROM admins WHERE id = ? LIMIT 1
  `).bind(session.id).first();
  if (!user || !["kepala_sekolah", "operator"].includes(user.role)) return null;
  return user;
}
function isHead(user) { return user?.role === "kepala_sekolah"; }
function cleanText(value, max = 20000) {
  if (value === null || value === undefined) return null;
  return String(value).trim().slice(0, max);
}
function makeSlug(value) {
  const slug = String(value || "").toLowerCase().normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "").slice(0, 100);
  return slug || `berita-${Date.now()}`;
}

/*
 * Kolom-kolom berikut mengikuti skema D1 yang sudah digunakan proyek:
 * teachers, news, announcements, gallery, school_profile, admins.
 * students adalah tabel tambahan pada migrasi 0002.
 */
const RESOURCES = {
  teachers: {
    table: "teachers", order: "sort_order ASC, id DESC",
    fields: ["name", "position", "subject", "photo_key", "bio", "sort_order", "is_active"],
    required: ["name"],
    normalize(input) {
      return {
        name: cleanText(input.name, 180),
        position: cleanText(input.position, 180),
        subject: cleanText(input.subject, 180),
        photo_key: cleanText(input.photo_key, 1000),
        bio: cleanText(input.bio, 10000),
        sort_order: Number.isFinite(Number(input.sort_order)) ? Number(input.sort_order) : 0,
        is_active: input.is_active === false || Number(input.is_active) === 0 ? 0 : 1
      };
    }
  },
  students: {
    table: "students", order: "class_name ASC, name COLLATE NOCASE ASC",
    fields: ["name", "nis", "class_name", "gender", "birth_date", "guardian", "phone", "address", "status"],
    required: ["name", "class_name"],
    normalize(input) {
      const status = ["aktif", "pindah", "lulus", "nonaktif"].includes(input.status) ? input.status : "aktif";
      return {
        name: cleanText(input.name, 180), nis: cleanText(input.nis, 40),
        class_name: cleanText(input.class_name, 40), gender: cleanText(input.gender, 30),
        birth_date: cleanText(input.birth_date, 20), guardian: cleanText(input.guardian, 180),
        phone: cleanText(input.phone, 40), address: cleanText(input.address, 2000), status
      };
    }
  },
  news: {
    table: "news", order: "created_at DESC, id DESC",
    fields: ["title", "slug", "excerpt", "content", "image_key", "status"],
    required: ["title"],
    normalize(input) {
      const status = input.status === "published" ? "published" : "draft";
      return {
        title: cleanText(input.title, 220),
        slug: makeSlug(input.slug || input.title),
        excerpt: cleanText(input.excerpt, 1000),
        content: cleanText(input.content, 50000),
        image_key: cleanText(input.image_key, 1000),
        status
      };
    }
  },
  announcements: {
    table: "announcements", order: "created_at DESC, id DESC",
    fields: ["title", "content", "status"],
    required: ["title"],
    normalize(input) {
      return {
        title: cleanText(input.title, 220),
        content: cleanText(input.content, 20000),
        status: input.status === "published" ? "published" : "draft"
      };
    }
  },
  gallery: {
    table: "gallery", order: "created_at DESC, id DESC",
    fields: ["title", "description", "image_key", "category"],
    required: ["title", "image_key"],
    normalize(input) {
      return {
        title: cleanText(input.title, 220),
        description: cleanText(input.description, 3000),
        image_key: cleanText(input.image_key, 1000),
        category: cleanText(input.category, 100)
      };
    }
  }
};

async function listResource(env, key) {
  const cfg = RESOURCES[key];
  const result = await env.DB.prepare(`SELECT * FROM ${cfg.table} ORDER BY ${cfg.order}`).all();
  return result.results || [];
}
async function createResource(env, key, input) {
  const cfg = RESOURCES[key], data = cfg.normalize(input || {});
  for (const field of cfg.required) {
    if (!data[field] || (typeof data[field] === "string" && !data[field].trim())) {
      return { error: `Kolom ${field} wajib diisi` };
    }
  }
  if (key === "news") {
    const exists = await env.DB.prepare("SELECT id FROM news WHERE slug = ?").bind(data.slug).first();
    if (exists) data.slug = `${data.slug}-${Date.now().toString(36)}`;
  }
  const cols = Object.keys(data);
  const values = cols.map(k => data[k]);
  const placeholders = cols.map(() => "?").join(", ");
  let sql = `INSERT INTO ${cfg.table} (${cols.join(", ")}) VALUES (${placeholders})`;
  if (key === "news" && data.status === "published") {
    sql = `INSERT INTO news (${cols.join(", ")}, published_at) VALUES (${placeholders}, CURRENT_TIMESTAMP)`;
  } else if (key === "announcements" && data.status === "published") {
    sql = `INSERT INTO announcements (${cols.join(", ")}, published_at) VALUES (${placeholders}, CURRENT_TIMESTAMP)`;
  }
  const result = await env.DB.prepare(sql).bind(...values).run();
  return { id: result.meta?.last_row_id ?? null };
}
async function updateResource(env, key, id, input) {
  const cfg = RESOURCES[key], data = cfg.normalize(input || {});
  const cols = Object.keys(data).filter(k => input && Object.prototype.hasOwnProperty.call(input, k));
  if (!cols.length) return { error: "Tidak ada data yang diubah" };
  const patch = Object.fromEntries(cols.map(k => [k, data[k]]));
  for (const field of cfg.required) {
    if (Object.prototype.hasOwnProperty.call(patch, field) && !patch[field]) return { error: `Kolom ${field} wajib diisi` };
  }
  if (key === "news" && patch.slug) {
    const exists = await env.DB.prepare("SELECT id FROM news WHERE slug = ? AND id != ?").bind(patch.slug, id).first();
    if (exists) patch.slug = `${patch.slug}-${Date.now().toString(36)}`;
  }
  const set = Object.keys(patch).map(k => `${k} = ?`);
  const vals = Object.values(patch);
  if (key === "news" || key === "announcements") {
    if (patch.status === "published") set.push("published_at = COALESCE(published_at, CURRENT_TIMESTAMP)");
    if (patch.status === "draft") set.push("published_at = NULL");
  }
  if (key === "news" || key === "students") set.push("updated_at = CURRENT_TIMESTAMP");
  const result = await env.DB.prepare(`UPDATE ${cfg.table} SET ${set.join(", ")} WHERE id = ?`)
    .bind(...vals, id).run();
  return { changes: result.meta?.changes ?? 0 };
}
async function deleteResource(env, key, id) {
  const cfg = RESOURCES[key];
  const result = await env.DB.prepare(`DELETE FROM ${cfg.table} WHERE id = ?`).bind(id).run();
  return result.meta?.changes ?? 0;
}
async function adminApi(request, env, user, path, method) {
  // Ringkasan statistik untuk dashboard
  if (path === "/api/admin/dashboard" && method === "GET") {
    const queries = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS n FROM teachers").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM students").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM news").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM announcements").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM gallery").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM admins WHERE role = 'operator'").first()
    ]);
    return json({ success: true, counts: {
      teachers: queries[0]?.n || 0, students: queries[1]?.n || 0,
      news: queries[2]?.n || 0, announcements: queries[3]?.n || 0,
      gallery: queries[4]?.n || 0, operators: queries[5]?.n || 0
    }});
  }

  // Profil sekolah: dibatasi untuk Kepala Sekolah
  if (path === "/api/admin/school-profile") {
    if (!isHead(user)) return json({ success: false, message: "Hanya Kepala Sekolah yang dapat mengubah profil sekolah" }, 403);
    if (method === "GET") {
      const profile = await env.DB.prepare("SELECT * FROM school_profile WHERE id = 1").first();
      return json({ success: true, profile });
    }
    if (method === "PUT" || method === "PATCH") {
      const input = await body(request) || {};
      const allowed = ["school_name", "address", "history", "vision", "mission", "principal_name", "principal_message", "email", "phone"];
      const patch = {};
      for (const k of allowed) if (Object.prototype.hasOwnProperty.call(input, k)) patch[k] = cleanText(input[k], k === "history" || k === "mission" ? 10000 : 3000);
      if (!Object.keys(patch).length) return json({ success: false, message: "Tidak ada data yang diubah" }, 400);
      await env.DB.prepare("INSERT OR IGNORE INTO school_profile (id, school_name) VALUES (1, 'SMP Negeri Satap 1 Watubangga')").run();
      const set = Object.keys(patch).map(k => `${k} = ?`).join(", ");
      await env.DB.prepare(`UPDATE school_profile SET ${set}, updated_at = CURRENT_TIMESTAMP WHERE id = 1`)
        .bind(...Object.values(patch)).run();
      const profile = await env.DB.prepare("SELECT * FROM school_profile WHERE id = 1").first();
      return json({ success: true, message: "Profil sekolah diperbarui", profile });
    }
    return json({ success: false, message: "Metode tidak didukung" }, 405);
  }

  // Akun operator hanya dapat dikelola Kepala Sekolah.
  if (path === "/api/admin/operators" && method === "GET") {
    if (!isHead(user)) return json({ success: false, message: "Akses ditolak" }, 403);
    const result = await env.DB.prepare(`
      SELECT id, email, role, created_at, last_login FROM admins
      WHERE role = 'operator' ORDER BY id DESC
    `).all();
    return json({ success: true, operators: result.results || [] });
  }
  if (path === "/api/admin/operators" && method === "POST") {
    if (!isHead(user)) return json({ success: false, message: "Akses ditolak" }, 403);
    const input = await body(request);
    const email = String(input?.email || "").trim().toLowerCase(), password = input?.password;
    if (!validCredentials(email, password)) return json({ success: false, message: "Email tidak valid atau password minimal 12 karakter" }, 400);
    const passwordHash = await hashPassword(password);
    try {
      await env.DB.prepare("INSERT INTO admins (email, password_hash, role) VALUES (?, ?, 'operator')")
        .bind(email, passwordHash).run();
      return json({ success: true, message: "Akun operator berhasil dibuat" }, 201);
    } catch (error) {
      if (String(error).toLowerCase().includes("unique")) return json({ success: false, message: "Email sudah digunakan" }, 409);
      throw error;
    }
  }
  const operatorMatch = path.match(/^\/api\/admin\/operators\/(\d+)$/);
  if (operatorMatch && (method === "DELETE" || method === "PUT")) {
    if (!isHead(user)) return json({ success: false, message: "Akses ditolak" }, 403);
    const id = Number(operatorMatch[1]);
    if (method === "DELETE") {
      const result = await env.DB.prepare("DELETE FROM admins WHERE id = ? AND role = 'operator'")
        .bind(id).run();
      if (result.meta.changes !== 1) return json({ success: false, message: "Operator tidak ditemukan" }, 404);
      return json({ success: true, message: "Akun operator berhasil dihapus" });
    }
    const input = await body(request) || {};
    const updates = [];
    const values = [];
    if (input.email !== undefined) {
      const email = String(input.email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ success: false, message: "Email tidak valid" }, 400);
      updates.push("email = ?"); values.push(email);
    }
    if (input.password !== undefined) {
      if (typeof input.password !== "string" || input.password.length < 12 || input.password.length > 128)
        return json({ success: false, message: "Password minimal 12 karakter" }, 400);
      updates.push("password_hash = ?"); values.push(await hashPassword(input.password));
    }
    if (!updates.length) return json({ success: false, message: "Tidak ada perubahan" }, 400);
    try {
      const result = await env.DB.prepare(`UPDATE admins SET ${updates.join(", ")} WHERE id = ? AND role = 'operator'`)
        .bind(...values, id).run();
      if (result.meta.changes !== 1) return json({ success: false, message: "Operator tidak ditemukan" }, 404);
      return json({ success: true, message: "Akun operator berhasil diperbarui" });
    } catch (error) {
      if (String(error).toLowerCase().includes("unique")) return json({ success: false, message: "Email sudah digunakan" }, 409);
      throw error;
    }
  }

  // CRUD konten sekolah: Kepala Sekolah dan Operator.
  const match = path.match(/^\/api\/admin\/(teachers|students|news|announcements|gallery)(?:\/(\d+))?$/);
  if (match) {
    const key = match[1], id = match[2] ? Number(match[2]) : null;
    if (method === "GET" && !id) {
      const items = await listResource(env, key);
      return json({ success: true, items });
    }
    if (method === "POST" && !id) {
      const input = await body(request);
      if (!input || typeof input !== "object") return json({ success: false, message: "Data tidak valid" }, 400);
      const result = await createResource(env, key, input);
      if (result.error) return json({ success: false, message: result.error }, 400);
      return json({ success: true, message: "Data berhasil ditambahkan", id: result.id }, 201);
    }
    if ((method === "PUT" || method === "PATCH") && id) {
      const input = await body(request);
      if (!input || typeof input !== "object") return json({ success: false, message: "Data tidak valid" }, 400);
      const result = await updateResource(env, key, id, input);
      if (result.error) return json({ success: false, message: result.error }, 400);
      if (!result.changes) return json({ success: false, message: "Data tidak ditemukan atau tidak berubah" }, 404);
      return json({ success: true, message: "Data berhasil diperbarui" });
    }
    if (method === "DELETE" && id) {
      const changes = await deleteResource(env, key, id);
      if (!changes) return json({ success: false, message: "Data tidak ditemukan" }, 404);
      return json({ success: true, message: "Data berhasil dihapus" });
    }
    return json({ success: false, message: "Metode atau alamat API tidak didukung" }, 405);
  }

  return json({ success: false, message: "API administrator tidak ditemukan" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url), path = url.pathname, method = request.method;
    try {
      // HEALTH CHECK
      if (path === "/api/health" && method === "GET") {
        await env.DB.prepare("SELECT 1").first();
        return json({ success: true, message: "Backend website sekolah aktif", database: "connected" });
      }

      // ONE-TIME KEPALA SEKOLAH REGISTRATION
      if (path === "/api/auth/bootstrap" && method === "POST") {
        const input = await body(request);
        if (!env.BOOTSTRAP_SECRET) return json({ success: false, message: "Bootstrap tidak dikonfigurasi" }, 503);
        if (!input || !await secretMatches(input.bootstrapSecret, env.BOOTSTRAP_SECRET))
          return json({ success: false, message: "Kode pendaftaran tidak valid" }, 403);
        const email = String(input.email || "").trim().toLowerCase(), password = input.password;
        if (!validCredentials(email, password)) return json({
          success: false, message: "Email atau password tidak memenuhi ketentuan. Password minimal 12 karakter."
        }, 400);
        const passwordHash = await hashPassword(password);
        const result = await env.DB.prepare(`
          INSERT INTO admins (email, password_hash, role)
          SELECT ?, ?, 'kepala_sekolah' WHERE NOT EXISTS (SELECT 1 FROM admins)
        `).bind(email, passwordHash).run();
        if (result.meta.changes !== 1) return json({
          success: false, message: "Pendaftaran awal sudah ditutup karena akun administrator telah tersedia."
        }, 409);
        return json({ success: true, message: "Akun Kepala Sekolah berhasil dibuat. Silakan login." }, 201);
      }

      // LOGIN — algoritma hash, cookie, dan durasi sesi dipertahankan.
      if (path === "/api/auth/login" && method === "POST") {
        if (!env.AUTH_SECRET) return json({ success: false, message: "AUTH_SECRET belum dikonfigurasi" }, 503);
        const input = await body(request);
        const email = String(input?.email || "").trim().toLowerCase(), password = input?.password;
        if (!email || typeof password !== "string") return json({ success: false, message: "Email dan password wajib diisi" }, 400);
        const admin = await env.DB.prepare(
          "SELECT id, email, password_hash, role FROM admins WHERE email = ? LIMIT 1"
        ).bind(email).first();
        if (!admin || !await verifyPassword(password, admin.password_hash))
          return json({ success: false, message: "Email atau password salah" }, 401);
        if (!["kepala_sekolah", "operator"].includes(admin.role))
          return json({ success: false, message: "Hak akses tidak valid" }, 403);
        await env.DB.prepare("UPDATE admins SET last_login = CURRENT_TIMESTAMP WHERE id = ?").bind(admin.id).run();
        const token = await signSession({
          id: admin.id, email: admin.email, role: admin.role,
          exp: Date.now() + 8 * 60 * 60 * 1000
        }, env.AUTH_SECRET);
        return json({ success: true, message: "Login berhasil", user: {
          id: admin.id, email: admin.email, role: admin.role
        }}, 200, { "Set-Cookie": sessionCookie(token) });
      }

      if (path === "/api/auth/me" && method === "GET") {
        const user = await requireLogin(request, env);
        if (!user) return json({ success: false, message: "Belum login" }, 401);
        return json({ success: true, user });
      }
      if (path === "/api/auth/logout" && method === "POST") {
        return json({ success: true, message: "Logout berhasil" }, 200, { "Set-Cookie": clearCookie() });
      }
// CEK STATUS HASIL SELEKSI PPDB
if (
  path === "/api/public/ppdb/status" &&
  method === "GET"
) {
  const registrationNo = String(
    url.searchParams.get("registration_no") || ""
  ).trim().toUpperCase();

  if (!/^PPDB-\d{8}-[A-F0-9]{8}$/.test(registrationNo)) {
    return json({
      success: false,
      message: "Format nomor pendaftaran tidak valid."
    }, 400);
  }

  const applicant = await env.DB.prepare(`
    SELECT registration_no, student_name, status
    FROM ppdb_applications
    WHERE registration_no = ?
    LIMIT 1
  `).bind(registrationNo).first();

  if (!applicant) {
    return json({
      success: false,
      message: "Nomor pendaftaran tidak ditemukan."
    }, 404);
  }

  const statusLabels = {
    baru: "Baru",
    diverifikasi: "Diverifikasi",
    diterima: "Diterima",
    cadangan: "Cadangan",
    ditolak: "Ditolak"
  };

  return json({
    success: true,
    registration_no: applicant.registration_no,
    student_name: applicant.student_name,
    status: statusLabels[applicant.status] || applicant.status
  });
}// BERITA PUBLIK
if (path === "/api/public/news" && method === "GET") {
  const result = await env.DB.prepare(`
    SELECT
      id,
      title,
      slug,
      excerpt,
      image_key,
      published_at,
      created_at
    FROM news
    WHERE status = 'published'
    ORDER BY COALESCE(published_at, created_at) DESC, id DESC
    LIMIT 12
  `).all();

  return json({
    success: true,
    data: result.results || []
  });
}
      // PENGUMUMAN PUBLIK - hanya menampilkan status published
if (path === "/api/public/announcements" && method === "GET") {
  const result = await env.DB.prepare(`
    SELECT
      id,
      title,
      content,
      published_at,
      created_at
    FROM announcements
    WHERE status = 'published'
    ORDER BY COALESCE(published_at, created_at) DESC, id DESC
    LIMIT 20
  `).all();

  return json({
    success: true,
    data: result.results || []
  });
}
      // GALERI PUBLIK - menampilkan dokumentasi foto sekolah
if (path === "/api/public/gallery" && method === "GET") {
  const result = await env.DB.prepare(`
    SELECT
      id,
      title,
      description,
      image_key,
      category,
      created_at
    FROM gallery
    ORDER BY created_at DESC, id DESC
    LIMIT 30
  `).all();

  return json({
    success: true,
    data: result.results || []
  });
}
      
// DATA GURU PUBLIK
if (path === "/api/public/teachers" && method === "GET") {
  const result = await env.DB.prepare(`
    SELECT
      id,
      name,
      position,
      subject,
      photo_key,
      bio
    FROM teachers
    WHERE is_active = 1
    ORDER BY sort_order ASC, id DESC
  `).all();

  return json({
    success: true,
    data: result.results || []
  });
}

      if (path.startsWith("/api/admin/")) {
        const user = await requireLogin(request, env);
        if (!user) return json({ success: false, message: "Silakan login terlebih dahulu" }, 401);
        return await adminApi(request, env, user, path, method);
      }
      if (path.startsWith("/api/")) return json({ success: false, message: "API tidak ditemukan" }, 404);
      return env.ASSETS.fetch(request);
    } catch (error) {
      console.error("Backend error:", error);
      return json({ success: false, message: "Terjadi kesalahan pada server" }, 500);
    }
  }
};
