const fs = require("fs/promises");
const path = require("path");

const countryCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
}

function getHeader(req, key) {
  const val = req.headers[String(key).toLowerCase()];
  if (Array.isArray(val)) return val[0] || "";
  return typeof val === "string" ? val : "";
}

function getClientIp(req) {
  const xff = getHeader(req, "x-forwarded-for");
  if (xff) {
    return xff.split(",")[0].trim();
  }
  return req.socket?.remoteAddress || "";
}

function normalizeIp(raw) {
  const ip = String(raw || "").trim();
  if (!ip) return "";
  if (ip.startsWith("::ffff:")) return ip.slice(7);
  return ip;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === "127.0.0.1" || ip === "::1") return true;
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  if (ip.startsWith("fc") || ip.startsWith("fd")) return true;
  return false;
}

function readCountryCache(ip) {
  const entry = countryCache.get(ip);
  if (!entry) return "";
  if (Date.now() > entry.expireAt) {
    countryCache.delete(ip);
    return "";
  }
  return entry.country;
}

function writeCountryCache(ip, country) {
  countryCache.set(ip, {
    country,
    expireAt: Date.now() + CACHE_TTL_MS,
  });
}

async function fetchCountryByIp9(ip) {
  const cached = readCountryCache(ip);
  if (cached) return cached;

  const endpoint = `https://www.ip9.com.cn/get?ip=${encodeURIComponent(ip)}`;
  const resp = await fetch(endpoint, { method: "GET", cache: "no-store" });
  if (!resp.ok) return "";

  const data = await resp.json();
  const countryCode = String(data?.data?.country_code || "").toUpperCase();
  if (!countryCode) return "";

  writeCountryCache(ip, countryCode);
  return countryCode;
}

async function readAppConfig() {
  const fullPath = path.join(process.cwd(), "cfg", "app.json");
  const text = await fs.readFile(fullPath, "utf8");
  return JSON.parse(text.replace(/^\uFEFF/, ""));
}

function pickProviderByStrategy(strategy, country, geetestReady) {
  if (strategy === "turnstile") return "turnstile";
  if (strategy === "geetest") return geetestReady ? "geetest" : "turnstile";

  if (country === "CN" && geetestReady) {
    return "geetest";
  }

  return "turnstile";
}

module.exports = async function handler(req, res) {
  setCors(res);

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  if (req.method !== "GET") {
    res.status(405).json({ ok: false, message: "method not allowed" });
    return;
  }

  try {
    const cfg = await readAppConfig();
    const anti = cfg && cfg.antiCrawler ? cfg.antiCrawler : {};
    const strategy = String(anti.verifyProvider || "auto").toLowerCase();

    const geetest = anti && anti.geetest ? anti.geetest : {};
    const geetestReady = geetest.enabled !== false && typeof geetest.captchaId === "string" && geetest.captchaId.trim().length > 0;

    let country = String(getHeader(req, "cf-ipcountry") || "").toUpperCase();
    let source = "cf-ipcountry";

    if (!country || country === "XX") {
      source = "ip9";
      const ip = normalizeIp(getClientIp(req));

      if (!isPrivateIp(ip)) {
        try {
          country = await fetchCountryByIp9(ip);
        } catch {
          country = "";
          source = "unknown";
        }
      } else {
        source = "private-ip";
      }
    }

    const provider = pickProviderByStrategy(strategy, country, geetestReady);

    res.status(200).json({
      ok: true,
      provider,
      strategy,
      country: country || "UNKNOWN",
      source,
    });
  } catch {
    res.status(200).json({
      ok: true,
      provider: "turnstile",
      strategy: "fallback",
      country: "UNKNOWN",
      source: "fallback",
    });
  }
};
