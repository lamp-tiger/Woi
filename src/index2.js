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

function unauthorized() {
  return Response.json(
    {
      ok: false,
      authenticated: false,
      error: "Unauthorized"
    },
    { status: 401 }
  );
}

function getVocabTable(lang) {
  if (lang === "en") return "vocab_words";
  if (lang === "ja") return "vocab_gois";
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // -----------------------------
    // 基础测试
    // -----------------------------

    if (url.pathname === "/api/test") {
      return Response.json({
        ok: true,
        message: "Woi backend is running"
      });
    }

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
          {
            ok: false,
            error: error.message
          },
          { status: 500 }
        );
      }
    }

    // -----------------------------
    // 管理员创建用户
    // -----------------------------

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
            {
              ok: false,
              error: "Unauthorized"
            },
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

    // -----------------------------
    // 登录
    // -----------------------------

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

    // -----------------------------
    // 当前登录用户
    // -----------------------------

    if (
      url.pathname === "/api/me" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return unauthorized();
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

    // -----------------------------
    // 退出登录
    // -----------------------------

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

    // =========================================================
    // D1 词库 API
    // =========================================================

    // -----------------------------
    // 获取当前用户词库
    //
    // GET /api/vocab?lang=en
    // GET /api/vocab?lang=ja
    // -----------------------------

    if (
      url.pathname === "/api/vocab" &&
      request.method === "GET"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return unauthorized();
        }

        const lang =
          String(url.searchParams.get("lang") || "");

        const table =
          getVocabTable(lang);

        if (!table) {
          return Response.json(
            {
              ok: false,
              error: "Invalid language"
            },
            { status: 400 }
          );
        }

        const result = await env.DB.prepare(`
          SELECT
            id,
            word,
            orig_jp,
            gen_jp,
            orig_cn,
            gen_cn,
            status,
            next_time,
            review_count,
            deleted
          FROM ${table}
          WHERE user_id = ?
            AND deleted = 0
        `)
          .bind(user.id)
          .all();

        return Response.json({
          ok: true,
          words: result.results || []
        });

      } catch (error) {
        console.error(
          "Load vocab failed:",
          error
        );

        return Response.json(
          {
            ok: false,
            error: "Failed to load vocabulary"
          },
          { status: 500 }
        );
      }
    }

    // -----------------------------
    // 新增 / 更新单词
    //
    // POST /api/vocab
    // -----------------------------

    if (
      url.pathname === "/api/vocab" &&
      request.method === "POST"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return unauthorized();
        }

        const body =
          await request.json();

        const lang =
          String(body.lang || "");

        const table =
          getVocabTable(lang);

        if (!table) {
          return Response.json(
            {
              ok: false,
              error: "Invalid language"
            },
            { status: 400 }
          );
        }

        const id =
          String(body.id || "").trim();

        const word =
          String(body.word || "").trim();

        if (!id || !word) {
          return Response.json(
            {
              ok: false,
              error: "id and word are required"
            },
            { status: 400 }
          );
        }

        const origJp =
          body.orig_jp == null
            ? null
            : String(body.orig_jp);

        const genJp =
          body.gen_jp == null
            ? null
            : String(body.gen_jp);

        const origCn =
          body.orig_cn == null
            ? null
            : String(body.orig_cn);

        const genCn =
          body.gen_cn == null
            ? null
            : String(body.gen_cn);

        const status =
          String(body.status || "new");

        const nextTime =
          body.next_time
            ? String(body.next_time)
            : new Date().toISOString();

        const reviewCount =
          Number.isFinite(Number(body.review_count))
            ? Math.max(
                0,
                Math.trunc(Number(body.review_count))
              )
            : 0;

        const deleted =
          body.deleted ? 1 : 0;

        // 先检查这个 ID 是否已经属于其他用户。
        // 防止用户通过伪造 UUID 覆盖别人的数据。
        const existing =
          await env.DB.prepare(`
            SELECT user_id
            FROM ${table}
            WHERE id = ?
          `)
            .bind(id)
            .first();

        if (
          existing &&
          Number(existing.user_id) !== Number(user.id)
        ) {
          return Response.json(
            {
              ok: false,
              error: "Forbidden"
            },
            { status: 403 }
          );
        }

        await env.DB.prepare(`
          INSERT INTO ${table} (
            id,
            user_id,
            word,
            orig_jp,
            gen_jp,
            orig_cn,
            gen_cn,
            status,
            next_time,
            review_count,
            deleted
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

          ON CONFLICT(id) DO UPDATE SET
            word = excluded.word,
            orig_jp = excluded.orig_jp,
            gen_jp = excluded.gen_jp,
            orig_cn = excluded.orig_cn,
            gen_cn = excluded.gen_cn,
            status = excluded.status,
            next_time = excluded.next_time,
            review_count = excluded.review_count,
            deleted = excluded.deleted
        `)
          .bind(
            id,
            user.id,
            word,
            origJp,
            genJp,
            origCn,
            genCn,
            status,
            nextTime,
            reviewCount,
            deleted
          )
          .run();

        return Response.json({
          ok: true,
          id
        });

      } catch (error) {
        console.error(
          "Save vocab failed:",
          error
        );

        return Response.json(
          {
            ok: false,
            error: "Failed to save vocabulary"
          },
          { status: 500 }
        );
      }
    }

    // -----------------------------
    // 软删除单词
    //
    // DELETE /api/vocab/:id?lang=en
    // DELETE /api/vocab/:id?lang=ja
    // -----------------------------

    if (
      url.pathname.startsWith("/api/vocab/") &&
      request.method === "DELETE"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return unauthorized();
        }

        const lang =
          String(url.searchParams.get("lang") || "");

        const table =
          getVocabTable(lang);

        if (!table) {
          return Response.json(
            {
              ok: false,
              error: "Invalid language"
            },
            { status: 400 }
          );
        }

        const id =
          decodeURIComponent(
            url.pathname.slice("/api/vocab/".length)
          );

        if (!id) {
          return Response.json(
            {
              ok: false,
              error: "Missing vocabulary id"
            },
            { status: 400 }
          );
        }

        const result =
          await env.DB.prepare(`
            UPDATE ${table}
            SET deleted = 1
            WHERE id = ?
              AND user_id = ?
          `)
            .bind(
              id,
              user.id
            )
            .run();

        return Response.json({
          ok: true,
          id,
          changed:
            result.meta?.changes || 0
        });

      } catch (error) {
        console.error(
          "Delete vocab failed:",
          error
        );

        return Response.json(
          {
            ok: false,
            error: "Failed to delete vocabulary"
          },
          { status: 500 }
        );
      }
    }

    // -----------------------------
    // 清空当前语言词库
    //
    // DELETE /api/vocab?lang=en
    // DELETE /api/vocab?lang=ja
    // -----------------------------

    if (
      url.pathname === "/api/vocab" &&
      request.method === "DELETE"
    ) {
      try {
        const user =
          await getCurrentUser(request, env);

        if (!user) {
          return unauthorized();
        }

        const lang =
          String(url.searchParams.get("lang") || "");

        const table =
          getVocabTable(lang);

        if (!table) {
          return Response.json(
            {
              ok: false,
              error: "Invalid language"
            },
            { status: 400 }
          );
        }

        const result =
          await env.DB.prepare(`
            UPDATE ${table}
            SET deleted = 1
            WHERE user_id = ?
              AND deleted = 0
          `)
            .bind(user.id)
            .run();

        return Response.json({
          ok: true,
          changed:
            result.meta?.changes || 0
        });

      } catch (error) {
        console.error(
          "Clear vocab failed:",
          error
        );

        return Response.json(
          {
            ok: false,
            error: "Failed to clear vocabulary"
          },
          { status: 500 }
        );
      }
    }

    // -----------------------------
    // 其他请求继续返回静态网站
    // -----------------------------

    return env.ASSETS.fetch(request);
  }
};
