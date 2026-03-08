const CACHE_TTL_MS = 60 * 1000;
const probeCache = new Map();

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Cache-Control", "no-store");
}

function isHttpUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function detectCdn(resp) {
  const server = (resp.headers.get("server") || "").toLowerCase();
  const via = (resp.headers.get("via") || "").toLowerCase();

  if (resp.headers.get("cf-ray") || server.includes("cloudflare") || resp.headers.get("cf-cache-status")) {
    return "Cloudflare";
  }

  if (
    resp.headers.get("x-amz-cf-id") ||
    resp.headers.get("x-amz-cf-pop") ||
    server.includes("cloudfront") ||
    via.includes("cloudfront")
  ) {
    return "CloudFront";
  }

  if (resp.headers.get("x-served-by") || server.includes("fastly") || via.includes("fastly")) {
    return "Fastly";
  }

  if (resp.headers.get("x-akamai-transformed") || server.includes("akamai") || via.includes("akamai")) {
    return "Akamai";
  }

  return null;
}

function classify(resp, latencyMs) {
  const status = resp.status;
  const cdn = detectCdn(resp);

  if (cdn && (status === 401 || status === 403 || status === 429)) {
    return {
      status: "cdn_pass",
      badgeText: `通行·${cdn}`,
      message: `${cdn} 返回 HTTP ${status}（CDN防护，判定通行） · ${latencyMs}ms`,
    };
  }

  if (cdn && status >= 200 && status < 400) {
    return {
      status: "cdn_pass",
      badgeText: `通行·${cdn}`,
      message: `${cdn} HTTP ${status} · ${latencyMs}ms`,
    };
  }

  if (status >= 200 && status < 400) {
    return { status: "probable", message: `HTTP ${status} · ${latencyMs}ms` };
  }

  if (status === 401 || status === 403 || status === 429) {
    return { status: "challenge", message: `HTTP ${status}（疑似验证/限流）` };
  }

  if (status >= 500) {
    return { status: "error", message: `HTTP ${status}（服务异常）` };
  }

  return { status: "blocked", message: `HTTP ${status}（访问受限）` };
}

function readCache(url) {
  const entry = probeCache.get(url);
  if (!entry) return null;

  if (Date.now() > entry.expireAt) {
    probeCache.delete(url);
    return null;
  }

  return {
    ...entry.result,
    message: `${entry.result.message}（缓存）`,
  };
}

function writeCache(url, result) {
  probeCache.set(url, {
    result,
    expireAt: Date.now() + CACHE_TTL_MS,
  });

  if (probeCache.size > 500) {
    for (const [k, v] of probeCache.entries()) {
      if (Date.now() > v.expireAt) {
        probeCache.delete(k);
      }
    }
  }
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
      resp = await fetch(rawUrl, {
        method: "HEAD",
        redirect: "follow",
        cache: "no-store",
        signal: controller.signal,
      });
    } catch {
      resp = await fetch(rawUrl, {
        method: "GET",
        redirect: "follow",
        cache: "no-store",
        signal: controller.signal,
      });
    }

    const latencyMs = Date.now() - start;
    const result = classify(resp, latencyMs);
    writeCache(rawUrl, result);
    res.status(200).json(result);
  } catch (err) {
    const aborted = err && err.name === "AbortError";
    if (aborted) {
      const timeoutResult = { status: "timeout", message: "连接超时（代理探测）" };
      writeCache(rawUrl, timeoutResult);
      res.status(200).json(timeoutResult);
      return;
    }

    const errorResult = { status: "error", message: "连接异常（代理探测）" };
    writeCache(rawUrl, errorResult);
    res.status(200).json(errorResult);
  } finally {
    clearTimeout(timer);
  }
};
