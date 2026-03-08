import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function readJson(relPath) {
  const abs = path.join(root, relPath);
  const raw = fs.readFileSync(abs, "utf8").replace(/^\uFEFF/, "");
  return JSON.parse(raw);
}

function fail(errors) {
  if (!errors.length) return;
  console.error("Validation failed:\n" + errors.map((e) => `- ${e}`).join("\n"));
  process.exit(1);
}

function validate() {
  const errors = [];
  const app = readJson("cfg/app.json");
  const links = readJson("data/links.json");
  const notices = readJson("data/notices.json");

  if (!app.siteTitle || !app.siteSubtitle) errors.push("cfg/app.json: siteTitle/siteSubtitle 不能为空");
  if (!Number.isFinite(app.pollingSeconds) || app.pollingSeconds < 10) errors.push("cfg/app.json: pollingSeconds 必须 >= 10");

  const anti = app?.antiCrawler?.antiDebug || {};
  if (anti.enforcementMode && !["lock", "warn"].includes(anti.enforcementMode)) {
    errors.push("cfg/app.json: antiCrawler.antiDebug.enforcementMode 仅支持 lock|warn");
  }

  if (!Array.isArray(links.groups)) errors.push("data/links.json: groups 必须是数组");
  else {
    links.groups.forEach((g, gi) => {
      if (!g.id || !g.groupTitle) errors.push(`data/links.json: groups[${gi}] 缺少 id/groupTitle`);
      if (!Array.isArray(g.items)) errors.push(`data/links.json: groups[${gi}].items 必须是数组`);
      else {
        g.items.forEach((it, ii) => {
          if (!it.id || !it.name) errors.push(`data/links.json: groups[${gi}].items[${ii}] 缺少 id/name`);
          const hasUrl = typeof it.url === "string" && it.url.trim();
          const hasEncoded = typeof it.urlEncoded === "string" && it.urlEncoded.trim();
          if (!hasUrl && !hasEncoded) errors.push(`data/links.json: groups[${gi}].items[${ii}] 需提供 url 或 urlEncoded`);
        });
      }
    });
  }

  if (!Array.isArray(notices.notices)) errors.push("data/notices.json: notices 必须是数组");
  else {
    notices.notices.forEach((n, i) => {
      if (!n.id || !n.title || !n.markdown) errors.push(`data/notices.json: notices[${i}] 缺少 id/title/markdown`);
    });
  }

  fail(errors);
  console.log("Validation passed.");
}

validate();
