const PBKDF2_ITERATIONS = 100000;
const SESSION_DAYS = 30;

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
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

async function sha256(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return bytesToBase64(new Uint8Array(hash));
}

function randomToken() {
  return bytesToBase64(
    crypto.getRandomValues(new Uint8Array(32))
  );
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";

  for (const part of cookie.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");

    if (key === name) {
      return valueParts.join("=");
    }
  }

  return null;
}

async function getCurrentUser(request, env) {
  const token = getCookie(request, "woi_session");

  if (!token) return null;

  const tokenHash = await sha256(token);

  const user = await env.DB.prepare(`
    SELECT
      id,
      username,
      disabled,
      session_expires_at
    FROM users
    WHERE active_session_hash = ?
  `)
    .bind(tokenHash)
    .first();

  if (!user) return null;
  if (user.disabled) return null;

  if (
    !user.session_expires_at ||
    new Date(user.session_expires_at).getTime() <= Date.now()
  ) {
    return null;
  }

  return user;
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

    // 管理员创建用户
    if (
      url.pathname === "/api/admin/create-user" &&
      request.method === "POST"
    ) {
      try {
        const adminSecret =
          request.headers.get("X-Admin-Secret");

        if (
          !adminSecret ||
          adminSecret !== env.ADMIN_SECRET
        ) {
          return Response.json(
            { ok: false, error: "Unauthorized" },
            { status: 401 }
          );
        }

        const body = await request.json();

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        if (
          username.length < 3 ||
          username.length > 50
        ) {
          return Response.json(
            {
              ok: false,
              error: "Username must be 3-50 characters"
            },
            { status: 400 }
          );
        }

        if (
          password.length < 8 ||
          password.length > 200
        ) {
          return Response.json(
            {
              ok: false,
              error: "Password must be at least 8 characters"
            },
            { status: 400 }
          );
        }

        const salt =
          crypto.getRandomValues(new Uint8Array(16));

        const passwordHash =
          await hashPassword(password, salt);

        const saltBase64 =
          bytesToBase64(salt);

        await env.DB.prepare(`
          INSERT INTO users (
            username,
            password_hash,
            password_salt
          )
          VALUES (?, ?, ?)
        `)
          .bind(
            username,
            passwordHash,
            saltBase64
          )
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
            {
              ok: false,
              error: "Username already exists"
            },
            { status: 409 }
          );
        }

        return Response.json(
          {
            ok: false,
            error: "Failed to create user"
          },
          { status: 500 }
        );
      }
    }

    // 登录
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const username =
          String(body.username || "").trim();

        const password =
          String(body.password || "");

        const user = await env.DB.prepare(`
          SELECT
            id,
            username,
            password_hash,
            password_salt,
            disabled
          FROM users
          WHERE username = ?
        `)
          .bind(username)
          .first();

        if (!user || user.disabled) {
          return Response.json(
            {
              ok: false,
              error: "Invalid username or password"
            },
            { status: 401 }
          );
        }

        const salt =
          base64ToBytes(user.password_salt);

        const passwordHash =
          await hashPassword(password, salt);

        if (passwordHash !== user.password_hash) {
          return Response.json(
            {
              ok: false,
              error: "Invalid username or password"
            },
            { status: 401 }
          );
        }

        // 每次登录生成一个全新的 session。
        // 数据库只保存最新 session 的 hash，
        // 所以上一台设备的 session 会自动失效。
        const token = randomToken();
        const tokenHash = await sha256(token);

        const expires = new Date(
          Date.now() +
          SESSION_DAYS * 24 * 60 * 60 * 1000
        ).toISOString();

        await env.DB.prepare(`
          UPDATE users
          SET
            active_session_hash = ?,
            session_expires_at = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(
            tokenHash,
            expires,
            user.id
          )
          .run();

        return Response.json(
          {
            ok: true,
            username: user.username
          },
          {
            headers: {
              "Set-Cookie":
                `woi_session=${token}; ` +
                `HttpOnly; Secure; SameSite=Lax; ` +
                `Path=/; Max-Age=${SESSION_DAYS * 86400}`
            }
          }
        );

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: "Login failed"
          },
          { status: 500 }
        );
      }
    }

    // 查询“我是谁”
    if (
      url.pathname === "/api/me" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return Response.json(
            {
              ok: false,
              authenticated: false
            },
            { status: 401 }
          );
        }

        return Response.json({
          ok: true,
          authenticated: true,
          user: {
            id: user.id,
            username: user.username
          }
        });

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: "Authentication check failed"
          },
          { status: 500 }
        );
      }
    }

    // 退出登录
    if (
      url.pathname === "/api/logout" &&
      request.method === "POST"
    ) {
      try {
        const token =
          getCookie(request, "woi_session");

        if (token) {
          const tokenHash =
            await sha256(token);

          await env.DB.prepare(`
            UPDATE users
            SET
              active_session_hash = NULL,
              session_expires_at = NULL,
              updated_at = CURRENT_TIMESTAMP
            WHERE active_session_hash = ?
          `)
            .bind(tokenHash)
            .run();
        }

        return Response.json(
          { ok: true },
          {
            headers: {
              "Set-Cookie":
                "woi_session=; HttpOnly; Secure; " +
                "SameSite=Lax; Path=/; Max-Age=0"
            }
          }
        );

      } catch (error) {
        return Response.json(
          {
            ok: false,
            error: "Logout failed"
          },
          { status: 500 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
