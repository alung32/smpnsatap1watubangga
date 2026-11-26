
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1").first();

        return Response.json({
          success: true,
          message: "Backend website sekolah aktif",
          database: "connected"
        });
      } catch (error) {
        console.error(error);

        return Response.json({
          success: false,
          message: "Database belum dapat dihubungi"
        }, { status: 500 });
      }
    }

    if (url.pathname.startsWith("/api/")) {
      return Response.json({
        success: false,
        message: "API tidak ditemukan"
      }, { status: 404 });
    }

    return env.ASSETS.fetch(request);
  }
};
