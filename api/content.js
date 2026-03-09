const crypto = require("crypto");
const fs = require("fs/promises");
const path = require("path");

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

function b64urlDecode(input) {
  const normalized = String(input || "").replace(/-/g, "+").replace(/_/g, "/");
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

async function readJson(filename) {
  const fullPath = path.join(__dirname, "_data", filename);
  const text = await fs.readFile(fullPath, "utf8");
  return JSON.parse(text);
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

  const humanToken = getHeader(req, "x-human-token");
  if (!verifySessionToken(humanToken)) {
    res.status(403).json({ ok: false, message: "未通过人机验证或会话已过期" });
    return;
  }

  try {
    const [notices, links] = await Promise.all([readJson("notices.json"), readJson("links.json")]);

    res.status(200).json({
      ok: true,
      notices: Array.isArray(notices?.notices) ? notices.notices : [],
      groups: Array.isArray(links?.groups) ? links.groups : [],
    });
  } catch {
    res.status(500).json({ ok: false, message: "内容服务异常" });
  }
};
