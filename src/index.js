export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 测试 Worker 是否运行
    if (url.pathname === "/api/test") {
      return Response.json({
        ok: true,
        message: "Woi backend is running"
      });
    }

    // 测试 D1 数据库连接
    if (url.pathname === "/api/db-test") {
      try {
        const result = await env.DB
          .prepare("SELECT COUNT(*) AS count FROM users")
          .first();

        return Response.json({
          ok: true,
          message: "D1 database is connected",
          users: result.count
        });
      } catch (error) {
        return Response.json({
          ok: false,
          error: error.message
        }, { status: 500 });
      }
    }

    // 其他请求继续显示原来的 Woi 网站
    return env.ASSETS.fetch(request);
  }
};
