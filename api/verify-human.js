const crypto = require("crypto");

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
}

function b64urlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signPayload(payloadB64, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(payloadB64)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function makeSessionToken() {
  const secret = process.env.HUMAN_TOKEN_SECRET || "change-this-human-token-secret";
  const payload = {
    exp: Date.now() + 10 * 60 * 1000,
    nonce: crypto.randomBytes(8).toString("hex"),
  };
  const payloadB64 = b64urlEncode(JSON.stringify(payload));
  const sig = signPayload(payloadB64, secret);
  return `${payloadB64}.${sig}`;
}

function tryParseJson(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseBody(req) {
  const body = req.body;

  if (body && typeof body === "object") {
    return body;
  }

  if (typeof body === "string") {
    const raw = body.trim();
    if (!raw) return {};

    const json = tryParseJson(raw);
    if (json && typeof json === "object") {
      return json;
    }

    const form = new URLSearchParams(raw);
    return {
      provider: form.get("provider") || "",
      token: form.get("token") || "",
      lot_number: form.get("lot_number") || "",
      captcha_output: form.get("captcha_output") || "",
      pass_token: form.get("pass_token") || "",
      gen_time: form.get("gen_time") || "",
    };
  }

  if (Buffer.isBuffer(body)) {
    const raw = body.toString("utf8").trim();
    if (!raw) return {};
    const json = tryParseJson(raw);
    if (json && typeof json === "object") {
      return json;
    }
  }

  return {};
}

async function verifyTurnstile(payload, ip) {
  const turnstileSecret = process.env.TURNSTILE_SECRET_KEY;
  if (!turnstileSecret) {
    return { ok: false, status: 500, message: "TURNSTILE_SECRET_KEY 未配置" };
  }

  const token = String(payload.token || "").trim();
  if (!token) {
    return { ok: false, status: 400, message: "缺少 token" };
  }

  try {
    const verifyResp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: turnstileSecret,
        response: token,
        remoteip: ip || "",
      }),
    });

    const verifyData = await verifyResp.json();
    if (!verifyData || verifyData.success !== true) {
      const codes = Array.isArray(verifyData?.["error-codes"]) ? verifyData["error-codes"] : [];
      return {
        ok: false,
        status: 200,
        message: "Turnstile 校验未通过",
        detail: { "error-codes": codes },
      };
    }

    return { ok: true };
  } catch (err) {
    const error = String(err?.message || err || "unknown");
    return {
      ok: false,
      status: 200,
      message: `Turnstile 校验服务异常: ${error}`,
      detail: { error },
    };
  }
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input || "")).digest("hex");
}

async function verifyGeetest(payload) {
  const captchaId = process.env.GEETEST_CAPTCHA_ID;
  const captchaKey = process.env.GEETEST_CAPTCHA_KEY;

  if (!captchaId || !captchaKey) {
    return { ok: false, status: 500, message: "GEETEST_CAPTCHA_ID 或 GEETEST_CAPTCHA_KEY 未配置" };
  }

  const lotNumber = String(payload.lot_number || "").trim();
  const captchaOutput = String(payload.captcha_output || "").trim();
  const passToken = String(payload.pass_token || "").trim();
  const genTime = String(payload.gen_time || "").trim();

  if (!lotNumber || !captchaOutput || !passToken || !genTime) {
    return {
      ok: false,
      status: 400,
      message: "极验参数不完整",
      detail: { required: ["lot_number", "captcha_output", "pass_token", "gen_time"] },
    };
  }

  const signToken = sha256Hex(lotNumber + captchaKey);

  try {
    const resp = await fetch("https://gcaptcha4.geetest.com/validate", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        captcha_id: captchaId,
        lot_number: lotNumber,
        captcha_output: captchaOutput,
        pass_token: passToken,
        gen_time: genTime,
        sign_token: signToken,
      }),
    });

    const data = await resp.json();
    if (!data || data.result !== "success") {
      return {
        ok: false,
        status: 200,
        message: "极验校验未通过",
        detail: {
          result: data?.result || "unknown",
          reason: data?.reason || "",
          captcha_args: data?.captcha_args || null,
        },
      };
    }

    return { ok: true };
  } catch (err) {
    const error = String(err?.message || err || "unknown");
    return {
      ok: false,
      status: 200,
      message: `极验校验服务异常: ${error}`,
      detail: { error },
    };
  }
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "POST") {
    res.status(405).json({ ok: false, message: "method not allowed" });
    return;
  }

  const payload = parseBody(req);
  const provider = String(payload.provider || "turnstile").toLowerCase();
  const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || "";

  const result = provider === "geetest"
    ? await verifyGeetest(payload)
    : await verifyTurnstile(payload, ip);

  if (!result.ok) {
    res.status(result.status || 200).json({
      ok: false,
      provider,
      message: result.message || "验证失败",
      detail: result.detail || null,
    });
    return;
  }

  res.status(200).json({
    ok: true,
    provider,
    sessionToken: makeSessionToken(),
    expiresInSeconds: 600,
  });
};
