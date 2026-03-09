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

function extractToken(req) {
  const body = req.body;

  if (body && typeof body === "object") {
    return String(body.token || "").trim();
  }

  if (typeof body === "string") {
    const raw = body.trim();
    if (!raw) return "";

    const json = tryParseJson(raw);
    if (json && typeof json === "object") {
      return String(json.token || "").trim();
    }

    const formToken = new URLSearchParams(raw).get("token");
    return String(formToken || "").trim();
  }

  if (Buffer.isBuffer(body)) {
    const raw = body.toString("utf8").trim();
    if (!raw) return "";

    const json = tryParseJson(raw);
    if (json && typeof json === "object") {
      return String(json.token || "").trim();
    }

    const formToken = new URLSearchParams(raw).get("token");
    return String(formToken || "").trim();
  }

  return "";
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

  const turnstileSecret = process.env.TURNSTILE_SECRET_KEY;
  if (!turnstileSecret) {
    res.status(500).json({ ok: false, message: "TURNSTILE_SECRET_KEY 未配置" });
    return;
  }

  const token = extractToken(req);
  if (!token) {
    res.status(400).json({
      ok: false,
      message: "缺少 token",
      detail: {
        contentType: String(req.headers["content-type"] || ""),
        bodyType: typeof req.body,
      },
    });
    return;
  }

  const ip = req.headers["x-forwarded-for"]?.toString().split(",")[0].trim() || "";

  try {
    const verifyResp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: turnstileSecret,
        response: token,
        remoteip: ip,
      }),
    });

    const verifyData = await verifyResp.json();
    if (!verifyData || verifyData.success !== true) {
      const codes = Array.isArray(verifyData?.["error-codes"])
        ? verifyData["error-codes"]
        : [];
      res.status(200).json({
        ok: false,
        message: "Turnstile 校验未通过",
        codes,
        detail: { "error-codes": codes },
      });
      return;
    }

    res.status(200).json({
      ok: true,
      sessionToken: makeSessionToken(),
      expiresInSeconds: 600,
    });
  } catch (err) {
    const error = String(err?.message || err || "unknown");
    res.status(200).json({
      ok: false,
      message: `Turnstile 校验服务异常: ${error}`,
      detail: { error },
    });
  }
};
