export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 暂时只做一个后端测试接口
    if (url.pathname === "/api/test") {
      return Response.json({
        ok: true,
        message: "Woi backend is running"
      });
    }

    // 其他请求继续交给现有 Woi 网站
    return env.ASSETS.fetch(request);
  }
};
