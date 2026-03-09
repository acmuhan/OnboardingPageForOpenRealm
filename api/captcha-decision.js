const fs = require("fs/promises");
const path = require("path");

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

    const country = String(getHeader(req, "cf-ipcountry") || "").toUpperCase();
    const provider = pickProviderByStrategy(strategy, country, geetestReady);

    res.status(200).json({
      ok: true,
      provider,
      strategy,
      country: country || "UNKNOWN",
    });
  } catch {
    res.status(200).json({
      ok: true,
      provider: "turnstile",
      strategy: "fallback",
      country: "UNKNOWN",
    });
  }
};
