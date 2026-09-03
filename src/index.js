const PBKDF2_ITERATIONS = 100000;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: PBKDF2_ITERATIONS
    },
    keyMaterial,
    256
  );

  return bytesToBase64(new Uint8Array(bits));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Worker 测试
    if (url.pathname === "/api/test") {
      return Response.json({
        ok: true,
        message: "Woi backend is running"
      });
    }

    // D1 测试
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
        return Response.json(
          { ok: false, error: error.message },
          { status: 500 }
        );
      }
    }

    // 管理员创建账号
    if (url.pathname === "/api/admin/create-user" && request.method === "POST") {
      try {
        const adminSecret = request.headers.get("X-Admin-Secret");

        if (!adminSecret || adminSecret !== env.ADMIN_SECRET) {
          return Response.json(
            { ok: false, error: "Unauthorized" },
            { status: 401 }
          );
        }

        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (username.length < 3 || username.length > 50) {
          return Response.json(
            { ok: false, error: "Username must be 3-50 characters" },
            { status: 400 }
          );
        }

        if (password.length < 8 || password.length > 200) {
          return Response.json(
            { ok: false, error: "Password must be at least 8 characters" },
            { status: 400 }
          );
        }

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const passwordHash = await hashPassword(password, salt);
        const saltBase64 = bytesToBase64(salt);

        await env.DB
          .prepare(`
            INSERT INTO users (
              username,
              password_hash,
              password_salt
            )
            VALUES (?, ?, ?)
          `)
          .bind(username, passwordHash, saltBase64)
          .run();

        return Response.json({
          ok: true,
          message: "User created",
          username
        });

      } catch (error) {
        if (
          String(error.message).includes("UNIQUE") ||
          String(error.message).includes("unique")
        ) {
          return Response.json(
            { ok: false, error: "Username already exists" },
            { status: 409 }
          );
        }

        return Response.json(
          { ok: false, error: "Failed to create user" },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
