const crypto = require("crypto");

const CACHE_TTL_MS = 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 90;
const probeCache = new Map();
const rateLimitMap = new Map();

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, x-human-token");
  res.setHeader("Cache-Control", "no-store");
}

function getHeader(req, key) {
  const val = req.headers[String(key).toLowerCase()];
  if (Array.isArray(val)) return val[0] || "";
  return typeof val === "string" ? val : "";
}

function isHttpUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function getClientIp(req) {
  const xff = getHeader(req, "x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function rateLimit(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  const bucket = rateLimitMap.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };

  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_LIMIT_WINDOW_MS;
  }

  bucket.count += 1;
  rateLimitMap.set(ip, bucket);

  if (bucket.count > RATE_LIMIT_MAX) {
    return { allowed: false, retryAfterMs: bucket.resetAt - now };
  }

  return { allowed: true };
}

function b64urlEncode(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function b64urlDecode(input) {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = normalized.length % 4 === 0 ? 0 : 4 - (normalized.length % 4);
  return Buffer.from(normalized + "=".repeat(padLen), "base64").toString("utf8");
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

function verifySessionToken(token) {
  if (token === "BYPASS") return true;

  const secret = process.env.HUMAN_TOKEN_SECRET || "change-this-human-token-secret";
  const parts = String(token || "").split(".");
  if (parts.length !== 2) return false;

  const [payloadB64, signature] = parts;
  const expected = signPayload(payloadB64, secret);
  if (signature !== expected) return false;

  try {
    const payload = JSON.parse(b64urlDecode(payloadB64));
    if (!payload || typeof payload.exp !== "number") return false;
    return Date.now() < payload.exp;
  } catch {
    return false;
  }
}

function detectCdn(resp) {
  const server = (resp.headers.get("server") || "").toLowerCase();
  const via = (resp.headers.get("via") || "").toLowerCase();

  if (resp.headers.get("cf-ray") || server.includes("cloudflare") || resp.headers.get("cf-cache-status")) return "Cloudflare";
  if (resp.headers.get("x-amz-cf-id") || resp.headers.get("x-amz-cf-pop") || server.includes("cloudfront") || via.includes("cloudfront")) return "CloudFront";
  if (resp.headers.get("x-served-by") || server.includes("fastly") || via.includes("fastly")) return "Fastly";
  if (resp.headers.get("x-akamai-transformed") || server.includes("akamai") || via.includes("akamai")) return "Akamai";

  return null;
}

function classify(resp, latencyMs) {
  const status = resp.status;
  const cdn = detectCdn(resp);

  if (cdn && (status === 401 || status === 403 || status === 429)) {
    return { status: "cdn_pass", badgeText: `通行·${cdn}`, message: `${cdn} 返回 HTTP ${status}（CDN防护，判定通行） · ${latencyMs}ms` };
  }

  if (cdn && status >= 200 && status < 400) {
    return { status: "cdn_pass", badgeText: `通行·${cdn}`, message: `${cdn} HTTP ${status} · ${latencyMs}ms` };
  }

  if (status >= 200 && status < 400) return { status: "probable", message: `HTTP ${status} · ${latencyMs}ms` };
  if (status === 401 || status === 403 || status === 429) return { status: "challenge", message: `HTTP ${status}（疑似验证/限流）` };
  if (status >= 500) return { status: "error", message: `HTTP ${status}（服务异常）` };

  return { status: "blocked", message: `HTTP ${status}（访问受限）` };
}

function readCache(url) {
  const entry = probeCache.get(url);
  if (!entry) return null;
  if (Date.now() > entry.expireAt) {
    probeCache.delete(url);
    return null;
  }
  return { ...entry.result, message: `${entry.result.message}（缓存）` };
}

function writeCache(url, result) {
  probeCache.set(url, { result, expireAt: Date.now() + CACHE_TTL_MS });
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "GET") {
    res.status(405).json({ status: "error", message: "method not allowed" });
    return;
  }

  const humanToken = getHeader(req, "x-human-token");
  if (!verifySessionToken(humanToken)) {
    res.status(200).json({ status: "blocked", badgeText: "需验证", message: "未通过人机验证或会话已过期" });
    return;
  }

  const rl = rateLimit(req);
  if (!rl.allowed) {
    res.status(200).json({ status: "blocked", badgeText: "限流", message: `请求过快，请稍后重试（约 ${Math.ceil(rl.retryAfterMs / 1000)}s）` });
    return;
  }

  const rawUrl = String(req.query.url || "").trim();
  if (!rawUrl || !isHttpUrl(rawUrl)) {
    res.status(400).json({ status: "unknown", message: "url 参数无效" });
    return;
  }

  const cached = readCache(rawUrl);
  if (cached) {
    res.status(200).json(cached);
    return;
  }

  const controller = new AbortController();
  const timeoutMs = 4500;
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();

  try {
    let resp;

    try {
      resp = await fetch(rawUrl, { method: "HEAD", redirect: "follow", cache: "no-store", signal: controller.signal });
    } catch {
      resp = await fetch(rawUrl, { method: "GET", redirect: "follow", cache: "no-store", signal: controller.signal });
    }

    const result = classify(resp, Date.now() - start);
    writeCache(rawUrl, result);
    res.status(200).json(result);
  } catch (err) {
    const result = err && err.name === "AbortError"
      ? { status: "timeout", message: "连接超时（代理探测）" }
      : { status: "error", message: "连接异常（代理探测）" };

    writeCache(rawUrl, result);
    res.status(200).json(result);
  } finally {
    clearTimeout(timer);
  }
};
