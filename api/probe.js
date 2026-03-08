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

function classify(status, latencyMs) {
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
    const result = classify(resp.status, latencyMs);
    res.status(200).json(result);
  } catch (err) {
    const aborted = err && err.name === "AbortError";
    if (aborted) {
      res.status(200).json({ status: "timeout", message: "连接超时（代理探测）" });
      return;
    }
    res.status(200).json({ status: "error", message: "连接异常（代理探测）" });
  } finally {
    clearTimeout(timer);
  }
};
