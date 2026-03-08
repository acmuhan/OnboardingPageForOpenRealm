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

  const token = String(req.body?.token || "").trim();
  if (!token) {
    res.status(400).json({ ok: false, message: "缺少 token" });
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
      const codes = Array.isArray(verifyData && verifyData["error-codes"])
        ? verifyData["error-codes"]
        : [];
      const detail = codes.length ? `（${codes.join(",")}）` : "";
      res.status(200).json({ ok: false, message: `Turnstile 校验未通过${detail}`, codes });
      return;
    }

    res.status(200).json({
      ok: true,
      sessionToken: makeSessionToken(),
      expiresInSeconds: 600,
    });
  } catch (error) {
    const msg = error && error.message ? `: ${error.message}` : "";
    res.status(200).json({ ok: false, message: `Turnstile 校验服务异常${msg}` });
  }
};
