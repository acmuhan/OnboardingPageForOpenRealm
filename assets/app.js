(function () {
  "use strict";

  const DEFAULT_LABELS = {
    noticeTitle: "公告",
    navTitle: "导航",
  };

  const DEFAULT_SECURITY = {
    requireHumanCheck: true,
    useObfuscatedLinks: true,
    probeRateLimitMs: 1000,
    antiDebug: {
      enabled: true,
      lockOnDetect: true,
      detectIntervalMs: 1200,
      devtoolsThreshold: 160,
      blockContextMenu: true,
      blockKeyShortcuts: true,
      enforcementMode: "lock",
    },
    turnstile: {
      enabled: true,
      siteKey: "",
      apiUrl: "https://challenges.cloudflare.com/turnstile/v0/api.js",
      hl: "zh-CN",
      theme: "light",
      size: "normal",
      tokenTTLSeconds: 110,
    },
  };

  const STATUS_META = {
    probable: { text: "可达", className: "status-probable" },
    cdn_pass: { text: "通行", className: "status-probable" },
    challenge: { text: "疑似验证", className: "status-challenge" },
    blocked: { text: "策略拦截", className: "status-challenge" },
    timeout: { text: "超时", className: "status-timeout" },
    unknown: { text: "未知", className: "status-unknown" },
    error: { text: "异常", className: "status-error" },
  };

  const state = {
    config: null,
    noticesData: null,
    linksData: null,
    rawGroups: [],
    pollTimerId: null,
    linksForProbe: [],
    checking: false,
    pollingSeconds: 60,
    lastProbeAt: 0,
    security: cloneSecurityDefaults(),
    verification: {
      verified: false,
      token: "",
      sessionToken: "",
      tokenExpireTimerId: null,
    },
    turnstile: {
      widgetId: null,
      apiPromise: null,
      apiReady: false,
    },
    debugGuard: {
      active: false,
      monitorId: null,
      warned: false,
    },
  };

  document.addEventListener("DOMContentLoaded", init);

  async function init() {
    bindActions();

    try {
      if (window.location.protocol === "file:") {
        showError("检测到 file:// 打开方式，浏览器通常会阻止读取 JSON。请使用静态服务器访问此页面。");
      }

      const cfg = await loadJson("cfg/app.json", "主配置(cfg)");
      validateConfig(cfg);

      state.config = cfg;
      state.pollingSeconds = normalizePollingSeconds(cfg.pollingSeconds);
      state.security = resolveSecurityConfig(cfg.antiCrawler);
      updateHeader(cfg);

      const [noticesData, linksData] = await Promise.all([
        loadJson(cfg.noticeSource, "公告数据(data/notices)"),
        loadJson(cfg.linkSource, "链接数据(data/links)"),
      ]);

      validateNotices(noticesData);
      validateLinks(linksData);

      state.noticesData = noticesData;
      state.linksData = linksData;
      state.rawGroups = linksData.groups;

      renderLabels(cfg.customLabels);
      renderNotices(noticesData.notices);

      setupAntiDebugGuards();
      await initializeVerificationFlow();
      document.addEventListener("visibilitychange", onVisibilityChange);
    } catch (error) {
      showError(error.message || String(error));
      renderFallbackPlaceholders();
    }
  }

  function bindActions() {
    const checkNowButton = document.getElementById("check-now-btn");
    if (checkNowButton) {
      checkNowButton.addEventListener("click", function () {
        runLinkChecks("manual");
      });
    }

    const refreshCaptchaButton = document.getElementById("refresh-captcha-btn");
    if (refreshCaptchaButton) {
      refreshCaptchaButton.addEventListener("click", function () {
        if (state.debugGuard.active) {
          return;
        }

        if (window.turnstile && state.turnstile.widgetId !== null) {
          window.turnstile.reset(state.turnstile.widgetId);
          setVerifyFeedback("验证码已刷新，请重新勾选。", "warn");
        } else {
          initializeVerificationFlow();
        }
      });
    }
  }

  function setupAntiDebugGuards() {
    const antiDebug = state.security.antiDebug;
    if (!antiDebug.enabled) {
      return;
    }

    if (antiDebug.blockContextMenu) {
      document.addEventListener("contextmenu", function (event) {
        event.preventDefault();
      });
    }

    if (antiDebug.blockKeyShortcuts) {
      document.addEventListener("keydown", function (event) {
        const key = String(event.key || "").toUpperCase();
        const ctrlShift = event.ctrlKey && event.shiftKey;

        if (key === "F12") {
          event.preventDefault();
          triggerAntiDebugLock("检测到调试快捷键，站点已锁定。请关闭调试工具后刷新。");
          return;
        }

        if (ctrlShift && (key === "I" || key === "J" || key === "C")) {
          event.preventDefault();
          triggerAntiDebugLock("检测到调试快捷键，站点已锁定。请关闭调试工具后刷新。");
          return;
        }

        if (event.ctrlKey && (key === "U" || key === "S")) {
          event.preventDefault();
        }
      });
    }

    startDevtoolsMonitor();
  }

  function startDevtoolsMonitor() {
    const antiDebug = state.security.antiDebug;

    if (!antiDebug.enabled) {
      return;
    }

    stopDevtoolsMonitor();

    state.debugGuard.monitorId = window.setInterval(function () {
      if (state.debugGuard.active) {
        return;
      }

      if (isDevtoolsLikelyOpen()) {
        triggerAntiDebugLock("检测到控制台/调试器，站点已锁定。请关闭调试工具后刷新页面。");
      }
    }, antiDebug.detectIntervalMs);
  }

  function stopDevtoolsMonitor() {
    if (state.debugGuard.monitorId) {
      clearInterval(state.debugGuard.monitorId);
      state.debugGuard.monitorId = null;
    }
  }

  function isDevtoolsLikelyOpen() {
    const threshold = state.security.antiDebug.devtoolsThreshold;
    const widthGap = window.outerWidth - window.innerWidth;
    const heightGap = window.outerHeight - window.innerHeight;
    return widthGap > threshold || heightGap > threshold;
  }

  function triggerAntiDebugLock(reason) {
    if (state.debugGuard.active) {
      return;
    }

    if (!state.security.antiDebug.lockOnDetect) {
      return;
    }

    if (state.security.antiDebug.enforcementMode === "warn") {
      if (!state.debugGuard.warned) {
        state.debugGuard.warned = true;
        updatePollingLabel("检测到调试行为（宽松模式：仅提示，不锁站）");
      }
      return;
    }

    state.debugGuard.active = true;
    state.verification.verified = false;
    state.verification.token = "";
    lockNavigation("站点已锁定：检测到调试行为。请关闭调试工具并刷新页面。", true);
    hideVerifyModal();
    showDebugShield(reason);
  }

  function showDebugShield(message) {
    const shield = document.getElementById("debug-shield");
    const text = document.getElementById("debug-shield-text");

    shield.classList.remove("hidden");
    if (text) {
      text.textContent = message;
    }

    applySiteMask(true);
  }

  async function initializeVerificationFlow() {
    if (state.debugGuard.active) {
      return;
    }

    if (!state.security.requireHumanCheck || !state.security.turnstile.enabled) {
      hideVerifyModal();
      clearTurnstileExpiry();
      state.verification.verified = true;
      state.verification.token = "BYPASS";
      state.verification.sessionToken = "BYPASS";
      setVerifyFeedback("人机验证已关闭，已直接放行。", "ok");
      unlockNavigation();
      return;
    }

    lockNavigation("请先完成人机验证，验证前不会显示导航。", true);
    showVerifyModal();

    if (!state.security.turnstile.siteKey || state.security.turnstile.siteKey === "YOUR_TURNSTILE_SITE_KEY") {
      setVerifyFeedback("请在 cfg/app.json 配置有效的 Turnstile Site Key。", "error");
      return;
    }

    setVerifyFeedback("正在加载 Turnstile 组件...", "warn");

    try {
      await ensureTurnstileApiLoaded();
      renderTurnstileWidget();
    } catch (error) {
      setVerifyFeedback(error.message || "Turnstile 加载失败，请稍后重试。", "error");
      lockNavigation("验证服务不可用，导航继续保持隐藏。", true);
      showVerifyModal();
    }
  }

  function ensureTurnstileApiLoaded() {
    if (state.turnstile.apiReady && window.turnstile && typeof window.turnstile.render === "function") {
      return Promise.resolve();
    }

    if (state.turnstile.apiPromise) {
      return state.turnstile.apiPromise;
    }

    state.turnstile.apiPromise = new Promise(function (resolve, reject) {
      window.onTurnstileApiLoaded = function () {
        state.turnstile.apiReady = true;
        resolve();
      };

      const script = document.createElement("script");
      script.src = buildTurnstileApiUrl(state.security.turnstile.apiUrl, state.security.turnstile.hl);
      script.async = true;
      script.defer = true;
      script.onerror = function () {
        reject(new Error("Turnstile 脚本加载失败，请检查网络或 apiUrl 配置。"));
      };

      document.head.appendChild(script);

      window.setTimeout(function () {
        if (!state.turnstile.apiReady) {
          reject(new Error("Turnstile 加载超时，请稍后重试。"));
        }
      }, 15000);
    }).catch(function (error) {
      state.turnstile.apiPromise = null;
      throw error;
    });

    return state.turnstile.apiPromise;
  }

  function buildTurnstileApiUrl(baseUrl, hl) {
    const connector = baseUrl.indexOf("?") >= 0 ? "&" : "?";
    return baseUrl + connector + "onload=onTurnstileApiLoaded&render=explicit&hl=" + encodeURIComponent(hl || "zh-CN");
  }

  function renderTurnstileWidget() {
    if (!window.turnstile || typeof window.turnstile.render !== "function") {
      setVerifyFeedback("Turnstile 未就绪，请稍后重试。", "error");
      return;
    }

    if (state.turnstile.widgetId !== null) {
      window.turnstile.reset(state.turnstile.widgetId);
      return;
    }

    try {
      state.turnstile.widgetId = window.turnstile.render("turnstile-container", {
        sitekey: state.security.turnstile.siteKey,
        theme: state.security.turnstile.theme,
        size: state.security.turnstile.size,
        callback: handleTurnstileSuccess,
        "expired-callback": handleTurnstileExpired,
        "error-callback": handleTurnstileError,
      });
      setVerifyFeedback("请完成勾选验证。", "warn");
    } catch (error) {
      setVerifyFeedback("Turnstile 渲染失败，请检查 Site Key。", "error");
    }
  }

  async function handleTurnstileSuccess(token) {
    if (state.debugGuard.active) {
      return;
    }

    if (!token) {
      setVerifyFeedback("未获取到验证令牌，请重试。", "error");
      return;
    }

    setVerifyFeedback("正在校验 Turnstile 结果...", "warn");

    try {
      const sessionToken = await verifyTurnstileToken(token);
      state.verification.verified = true;
      state.verification.token = token;
      state.verification.sessionToken = sessionToken;

      setVerifyFeedback("验证成功，正在解锁导航...", "ok");
      hideVerifyModal();
      unlockNavigation();
      scheduleTurnstileExpiry();
    } catch (error) {
      state.verification.verified = false;
      state.verification.token = "";
      state.verification.sessionToken = "";
      setVerifyFeedback(error.message || "Turnstile 校验失败", "error");
      showVerifyModal();
      lockNavigation("验证失败，导航继续保持隐藏。", true);
    }
  }

  async function verifyTurnstileToken(token) {
    const resp = await fetch("/api/verify-human", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token }),
      cache: "no-store",
      credentials: "same-origin",
    });

    if (!resp.ok) {
      throw new Error("验证服务不可用");
    }

    const data = await resp.json();
    if (!data || data.ok !== true || !data.sessionToken) {
      throw new Error((data && data.message) || "Turnstile 服务端校验失败");
    }

    return data.sessionToken;
  }

  function handleTurnstileExpired() {
    if (state.debugGuard.active) {
      return;
    }

    state.verification.verified = false;
    state.verification.token = "";
    state.verification.sessionToken = "";
    lockNavigation("验证已过期，请重新进行人机验证。", true);
    showVerifyModal();
    setVerifyFeedback("验证已过期，请重新勾选。", "warn");
  }

  function handleTurnstileError() {
    if (state.debugGuard.active) {
      return;
    }

    state.verification.verified = false;
    state.verification.token = "";
    state.verification.sessionToken = "";
    lockNavigation("验证失败，导航继续保持隐藏。", true);
    showVerifyModal();
    setVerifyFeedback("验证组件异常，请点击“刷新验证”。", "error");
  }

  function scheduleTurnstileExpiry() {
    clearTurnstileExpiry();
    const ttlMs = state.security.turnstile.tokenTTLSeconds * 1000;

    state.verification.tokenExpireTimerId = window.setTimeout(function () {
      if (state.debugGuard.active) {
        return;
      }
      state.verification.verified = false;
      state.verification.token = "";
      state.verification.sessionToken = "";
      lockNavigation("验证状态失效，请重新验证。", true);
      showVerifyModal();
      if (window.turnstile && state.turnstile.widgetId !== null) {
        window.turnstile.reset(state.turnstile.widgetId);
      }
      setVerifyFeedback("验证已失效，请重新勾选。", "warn");
    }, ttlMs);
  }

  function clearTurnstileExpiry() {
    if (state.verification.tokenExpireTimerId) {
      clearTimeout(state.verification.tokenExpireTimerId);
      state.verification.tokenExpireTimerId = null;
    }
  }

  function showVerifyModal() {
    document.getElementById("verify-modal").classList.remove("hidden");
    applySiteMask(true);
  }

  function hideVerifyModal() {
    document.getElementById("verify-modal").classList.add("hidden");
  }

  function lockNavigation(message, keepMasked) {
    stopPolling();
    clearTurnstileExpiry();
    state.verification.verified = false;
    state.verification.sessionToken = "";
    setCheckNowEnabled(false);

    const groupsEl = document.getElementById("link-groups");
    groupsEl.innerHTML = '<p class="placeholder">等待验证通过后加载导航链接...</p>';

    const tipEl = document.getElementById("locked-tip");
    tipEl.classList.remove("hidden");
    tipEl.textContent = message;

    if (keepMasked !== false) {
      applySiteMask(true);
    }

    updatePollingLabel("等待验证通过后开启自动检测");
  }

  function unlockNavigation() {
    if (state.debugGuard.active) {
      return;
    }

    if (!state.rawGroups.length) {
      return;
    }

    const unlockedGroups = buildUnlockedGroups(state.rawGroups);
    renderLinkGroups(unlockedGroups);

    document.getElementById("locked-tip").classList.add("hidden");

    setCheckNowEnabled(true);
    applySiteMask(false);
    runLinkChecks("manual");
    startPolling();
  }

  function applySiteMask(masked) {
    if (masked) {
      document.body.classList.add("site-masked");
    } else {
      document.body.classList.remove("site-masked");
    }
  }

  function buildUnlockedGroups(groups) {
    return groups.map(function (group) {
      return {
        id: group.id,
        groupTitle: group.groupTitle,
        groupSubtitle: group.groupSubtitle || "",
        items: group.items.map(function (item) {
          const resolvedUrl = resolveLinkUrl(item);
          return {
            id: item.id,
            name: item.name,
            url: resolvedUrl || "#",
            desc: item.desc || (resolvedUrl ? "" : "链接解码失败"),
            tag: item.tag || "",
          };
        }),
      };
    });
  }

  function resolveLinkUrl(item) {
    if (typeof item.url === "string" && item.url.trim()) {
      return item.url.trim();
    }

    if (typeof item.urlEncoded === "string" && item.urlEncoded.trim()) {
      const raw = item.urlEncoded.trim();

      // Compatibility: allow plain URL accidentally put into urlEncoded.
      if (/^(https?:|mailto:|tel:|magnet:)/i.test(raw)) {
        return raw;
      }

      if (state.security.useObfuscatedLinks) {
        return decodeObfuscatedUrl(raw);
      }
    }

    return null;
  }

  function decodeObfuscatedUrl(rawEncoded) {
    try {
      const reversed = atob(rawEncoded);
      return reversed.split("").reverse().join("");
    } catch (error) {
      return null;
    }
  }

  function setCheckNowEnabled(enabled) {
    const btn = document.getElementById("check-now-btn");
    btn.disabled = !enabled;
  }

  function setVerifyFeedback(text, level) {
    const el = document.getElementById("verify-feedback");
    el.className = "verify-feedback";

    if (level === "ok") {
      el.classList.add("ok");
    } else if (level === "warn") {
      el.classList.add("warn");
    } else if (level === "error") {
      el.classList.add("error");
    }

    el.textContent = text;
  }

  function renderFallbackPlaceholders() {
    const noticeList = document.getElementById("notice-list");
    const linkGroups = document.getElementById("link-groups");

    if (noticeList && !noticeList.children.length) {
      noticeList.innerHTML = '<p class="placeholder">公告加载失败</p>';
    }
    if (linkGroups && !linkGroups.children.length) {
      linkGroups.innerHTML = '<p class="placeholder">导航加载失败</p>';
    }
  }

  function updateHeader(cfg) {
    const siteTitle = document.getElementById("site-title");
    const siteSubtitle = document.getElementById("site-subtitle");

    siteTitle.textContent = cfg.siteTitle;
    siteSubtitle.textContent = cfg.siteSubtitle;
    document.title = cfg.siteTitle;
  }

  function renderLabels(customLabels) {
    const labels = Object.assign({}, DEFAULT_LABELS, customLabels || {});
    document.getElementById("notice-title").textContent = labels.noticeTitle;
    document.getElementById("nav-title").textContent = labels.navTitle;
  }

  function renderNotices(notices) {
    const listEl = document.getElementById("notice-list");
    listEl.innerHTML = "";

    if (!notices.length) {
      listEl.innerHTML = '<p class="placeholder">暂无公告</p>';
      return;
    }

    const sorted = notices.slice().sort(function (a, b) {
      if (Boolean(a.pinned) !== Boolean(b.pinned)) {
        return a.pinned ? -1 : 1;
      }
      const ad = a.date ? new Date(a.date).getTime() : 0;
      const bd = b.date ? new Date(b.date).getTime() : 0;
      return bd - ad;
    });

    for (const notice of sorted) {
      const card = document.createElement("article");
      card.className = "notice-card";

      const head = document.createElement("div");
      head.className = "notice-head";

      const title = document.createElement("h3");
      title.className = "notice-title";
      title.textContent = notice.title;
      head.appendChild(title);

      if (notice.pinned) {
        const pin = document.createElement("span");
        pin.className = "notice-pin";
        pin.textContent = "置顶";
        head.appendChild(pin);
      }

      if (notice.date) {
        const date = document.createElement("span");
        date.className = "notice-date";
        date.textContent = formatDate(notice.date);
        head.appendChild(date);
      }

      const body = document.createElement("div");
      body.className = "notice-body";

      try {
        body.innerHTML = window.MarkdownRenderer.renderLimitedMarkdown(notice.markdown);
      } catch (error) {
        body.innerHTML = window.MarkdownRenderer.renderPlainText(notice.markdown);
      }

      card.appendChild(head);
      card.appendChild(body);
      listEl.appendChild(card);
    }
  }

  function renderLinkGroups(groups) {
    state.linksForProbe = [];
    const groupsEl = document.getElementById("link-groups");
    groupsEl.innerHTML = "";

    if (!groups.length) {
      groupsEl.innerHTML = '<p class="placeholder">暂无导航链接</p>';
      return;
    }

    for (const group of groups) {
      const section = document.createElement("section");
      section.className = "link-group";

      const heading = document.createElement("h3");
      heading.className = "link-group-title";
      heading.textContent = group.groupTitle;
      section.appendChild(heading);

      if (group.groupSubtitle) {
        const subtitle = document.createElement("p");
        subtitle.className = "link-group-subtitle";
        subtitle.textContent = group.groupSubtitle;
        section.appendChild(subtitle);
      }

      const ul = document.createElement("ul");
      ul.className = "link-list";

      for (const item of group.items) {
        const li = document.createElement("li");
        li.className = "link-item";

        const row = document.createElement("div");
        row.className = "link-row";

        const anchor = document.createElement("a");
        anchor.className = "link-anchor";
        anchor.href = toSafeHref(item.url);
        anchor.target = "_blank";
        anchor.rel = "noopener noreferrer";
        anchor.textContent = item.name;

        const statusBadge = document.createElement("span");
        statusBadge.className = "status-badge status-unknown";
        statusBadge.textContent = "未检测";

        row.appendChild(anchor);
        row.appendChild(statusBadge);

        const meta = document.createElement("div");
        meta.className = "link-meta";

        if (item.desc) {
          const desc = document.createElement("span");
          desc.textContent = item.desc;
          meta.appendChild(desc);
        }

        if (item.tag) {
          const tag = document.createElement("span");
          tag.className = "link-tag";
          tag.textContent = item.tag;
          meta.appendChild(tag);
        }

        const time = document.createElement("span");
        time.textContent = "尚未检测";
        meta.appendChild(time);

        li.appendChild(row);
        li.appendChild(meta);
        ul.appendChild(li);

        state.linksForProbe.push({
          url: item.url,
          badgeEl: statusBadge,
          timeEl: time,
        });
      }

      section.appendChild(ul);
      groupsEl.appendChild(section);
    }
  }

  async function runLinkChecks(trigger) {
    if (state.security.requireHumanCheck && !state.verification.verified) {
      return;
    }

    if (state.checking || !state.linksForProbe.length) {
      return;
    }

    if (trigger === "manual") {
      const span = Date.now() - state.lastProbeAt;
      if (span < state.security.probeRateLimitMs) {
        updatePollingLabel("操作过快，请稍后再试");
        return;
      }
    }

    state.checking = true;
    state.lastProbeAt = Date.now();

    try {
      await Promise.all(
        state.linksForProbe.map(async function (entry) {
          const probeResult = await probeUrl(entry.url);
          applyProbeResult(entry, probeResult);
        })
      );

      const nowText = "最近检测：" + formatDateTime(new Date());
      document.getElementById("last-updated").textContent = nowText;
      updatePollingLabel();
    } finally {
      state.checking = false;
    }
  }

  function applyProbeResult(entry, result) {
    const meta = STATUS_META[result.status] || STATUS_META.unknown;
    entry.badgeEl.className = "status-badge " + meta.className;
    entry.badgeEl.textContent =
      typeof result.badgeText === "string" && result.badgeText ? result.badgeText : meta.text;
    entry.timeEl.textContent = result.message + " · " + formatDateTime(new Date());
  }

  async function probeUrl(rawUrl) {
    const parsed = parseHttpUrl(rawUrl);
    if (!parsed) {
      return { status: "unknown", message: "协议不支持检测" };
    }

    // Probe via same-origin API to avoid browser-side CORS/CORP differences.
    const apiPath = "/api/probe?url=" + encodeURIComponent(parsed.href);

    try {
      const headers = {};
      if (state.verification.sessionToken) {
        headers["x-human-token"] = state.verification.sessionToken;
      }

      const response = await fetch(apiPath, {
        method: "GET",
        headers,
        cache: "no-store",
        credentials: "same-origin",
      });

      if (!response.ok) {
        return {
          status: "error",
          message: "探测服务异常(" + response.status + ")",
        };
      }

      const payload = await response.json();
      if (!payload || typeof payload.status !== "string") {
        return {
          status: "error",
          message: "探测结果无效",
        };
      }

      return {
        status: payload.status,
        message: typeof payload.message === "string" && payload.message ? payload.message : "已完成检测",
      };
    } catch (error) {
      return {
        status: "error",
        message: "探测服务不可用",
      };
    }
  }

  function getErrorText(error) {
    if (!error) {
      return "";
    }

    const parts = [];
    if (typeof error.name === "string") {
      parts.push(error.name);
    }
    if (typeof error.message === "string") {
      parts.push(error.message);
    }
    return parts.join(" ").toLowerCase();
  }

  function looksLikePolicyBlocked(errorText) {
    if (!errorText) {
      return false;
    }

    return (
      errorText.indexOf("blocked_by_response") >= 0 ||
      errorText.indexOf("notsameorigin") >= 0 ||
      errorText.indexOf("corp") >= 0 ||
      errorText.indexOf("cors") >= 0 ||
      errorText.indexOf("typeerror") >= 0
    );
  }
  function probeImageReachability(parsedUrl, timeoutMs) {
    return new Promise(function (resolve) {
      const img = new Image();
      let settled = false;
      const start = performance.now();
      const probeUrl = parsedUrl.origin + "/favicon.ico?__probe=" + Date.now();

      const done = function (result) {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        img.onload = null;
        img.onerror = null;
        resolve(result);
      };

      const timer = setTimeout(function () {
        done({ ok: false, timeout: true, latencyMs: Math.round(performance.now() - start) });
      }, timeoutMs);

      img.onload = function () {
        done({ ok: true, timeout: false, latencyMs: Math.round(performance.now() - start) });
      };

      img.onerror = function () {
        done({ ok: false, timeout: false, latencyMs: Math.round(performance.now() - start) });
      };

      img.referrerPolicy = "no-referrer";
      img.src = probeUrl;
    });
  }

  function startPolling() {
    stopPolling();

    if (state.security.requireHumanCheck && !state.verification.verified) {
      updatePollingLabel("等待验证通过后开启自动检测");
      return;
    }

    state.pollTimerId = window.setInterval(function () {
      if (!document.hidden) {
        runLinkChecks("auto");
      }
    }, state.pollingSeconds * 1000);

    updatePollingLabel();
  }

  function stopPolling() {
    if (state.pollTimerId) {
      clearInterval(state.pollTimerId);
      state.pollTimerId = null;
    }
  }

  function onVisibilityChange() {
    if (document.hidden) {
      stopPolling();
      updatePollingLabel("自动检测已暂停（页面不可见）");
      return;
    }

    if (state.security.requireHumanCheck && !state.verification.verified) {
      updatePollingLabel("等待验证通过后开启自动检测");
      return;
    }

    runLinkChecks("auto");
    startPolling();
  }

  function updatePollingLabel(extraMessage) {
    const labelEl = document.getElementById("polling-label");
    if (extraMessage) {
      labelEl.textContent = extraMessage;
      return;
    }

    if (state.security.requireHumanCheck && !state.verification.verified) {
      labelEl.textContent = "等待验证通过后开启自动检测";
      return;
    }

    labelEl.textContent = "自动检测间隔：每 " + state.pollingSeconds + " 秒（HTTP Ping/验证探测）";
  }

  async function loadJson(path, label) {
    let response;
    try {
      response = await fetch(path, { cache: "no-store" });
    } catch (error) {
      throw new Error(label + " 读取失败：" + path);
    }

    if (!response.ok) {
      throw new Error(label + " HTTP 状态异常：" + response.status + "（" + path + "）");
    }

    try {
      return await response.json();
    } catch (error) {
      throw new Error(label + " JSON 解析失败：" + path);
    }
  }

  function validateConfig(cfg) {
    const errors = [];
    requireString(cfg, "siteTitle", errors, "cfg/app.json");
    requireString(cfg, "siteSubtitle", errors, "cfg/app.json");
    requireString(cfg, "noticeSource", errors, "cfg/app.json");
    requireString(cfg, "linkSource", errors, "cfg/app.json");

    if (typeof cfg.pollingSeconds !== "number" || !Number.isFinite(cfg.pollingSeconds)) {
      errors.push("cfg/app.json.pollingSeconds 必须是数字");
    }

    if (typeof cfg.customLabels !== "object" || cfg.customLabels === null) {
      errors.push("cfg/app.json.customLabels 必须是对象");
    } else {
      requireString(cfg.customLabels, "noticeTitle", errors, "cfg/app.json.customLabels");
      requireString(cfg.customLabels, "navTitle", errors, "cfg/app.json.customLabels");
    }

    if (cfg.antiCrawler !== undefined && (typeof cfg.antiCrawler !== "object" || cfg.antiCrawler === null)) {
      errors.push("cfg/app.json.antiCrawler 必须是对象");
    }

    if (errors.length) {
      throw new Error(errors.join("\n"));
    }
  }

  function validateNotices(noticesData) {
    const errors = [];

    if (!noticesData || !Array.isArray(noticesData.notices)) {
      errors.push("data/notices.json.notices 必须是数组");
    } else {
      noticesData.notices.forEach(function (notice, index) {
        requireString(notice, "id", errors, "data/notices.json.notices[" + index + "]");
        requireString(notice, "title", errors, "data/notices.json.notices[" + index + "]");
        requireString(notice, "markdown", errors, "data/notices.json.notices[" + index + "]");
      });
    }

    if (errors.length) {
      throw new Error(errors.join("\n"));
    }
  }

  function validateLinks(linksData) {
    const errors = [];

    if (!linksData || !Array.isArray(linksData.groups)) {
      errors.push("data/links.json.groups 必须是数组");
    } else {
      linksData.groups.forEach(function (group, groupIndex) {
        const groupBase = "data/links.json.groups[" + groupIndex + "]";
        requireString(group, "id", errors, groupBase);
        requireString(group, "groupTitle", errors, groupBase);

        if (!Array.isArray(group.items)) {
          errors.push(groupBase + ".items 必须是数组");
          return;
        }

        group.items.forEach(function (item, itemIndex) {
          const itemBase = groupBase + ".items[" + itemIndex + "]";
          requireString(item, "id", errors, itemBase);
          requireString(item, "name", errors, itemBase);

          const hasUrl = typeof item.url === "string" && item.url.trim();
          const hasEncoded = typeof item.urlEncoded === "string" && item.urlEncoded.trim();
          if (!hasUrl && !hasEncoded) {
            errors.push(itemBase + " 需要提供 url 或 urlEncoded");
          }
        });
      });
    }

    if (errors.length) {
      throw new Error(errors.join("\n"));
    }
  }

  function resolveSecurityConfig(input) {
    const source = typeof input === "object" && input !== null ? input : {};
    const sourceTurnstile = typeof source.turnstile === "object" && source.turnstile !== null ? source.turnstile : {};
    const sourceAntiDebug = typeof source.antiDebug === "object" && source.antiDebug !== null ? source.antiDebug : {};

    return {
      requireHumanCheck: source.requireHumanCheck !== false,
      useObfuscatedLinks: source.useObfuscatedLinks !== false,
      probeRateLimitMs: normalizeNumber(source.probeRateLimitMs, DEFAULT_SECURITY.probeRateLimitMs, 300, 5000),
      antiDebug: {
        enabled: sourceAntiDebug.enabled !== false,
        lockOnDetect: sourceAntiDebug.lockOnDetect !== false,
        detectIntervalMs: normalizeNumber(sourceAntiDebug.detectIntervalMs, DEFAULT_SECURITY.antiDebug.detectIntervalMs, 300, 5000),
        devtoolsThreshold: normalizeNumber(sourceAntiDebug.devtoolsThreshold, DEFAULT_SECURITY.antiDebug.devtoolsThreshold, 80, 400),
        blockContextMenu: sourceAntiDebug.blockContextMenu !== false,
        blockKeyShortcuts: sourceAntiDebug.blockKeyShortcuts !== false,
        enforcementMode: sourceAntiDebug.enforcementMode === "warn" ? "warn" : "lock",
      },
      turnstile: {
        enabled: sourceTurnstile.enabled !== false,
        siteKey: typeof sourceTurnstile.siteKey === "string" ? sourceTurnstile.siteKey.trim() : "",
        apiUrl: typeof sourceTurnstile.apiUrl === "string" && sourceTurnstile.apiUrl.trim() ? sourceTurnstile.apiUrl.trim() : DEFAULT_SECURITY.turnstile.apiUrl,
        hl: typeof sourceTurnstile.hl === "string" && sourceTurnstile.hl.trim() ? sourceTurnstile.hl.trim() : DEFAULT_SECURITY.turnstile.hl,
        theme: sourceTurnstile.theme === "dark" ? "dark" : "light",
        size: sourceTurnstile.size === "compact" ? "compact" : "normal",
        tokenTTLSeconds: normalizeNumber(sourceTurnstile.tokenTTLSeconds, DEFAULT_SECURITY.turnstile.tokenTTLSeconds, 60, 600),
      },
    };
  }

  function cloneSecurityDefaults() {
    return {
      requireHumanCheck: DEFAULT_SECURITY.requireHumanCheck,
      useObfuscatedLinks: DEFAULT_SECURITY.useObfuscatedLinks,
      probeRateLimitMs: DEFAULT_SECURITY.probeRateLimitMs,
      antiDebug: Object.assign({}, DEFAULT_SECURITY.antiDebug),
      turnstile: Object.assign({}, DEFAULT_SECURITY.turnstile),
    };
  }

  function normalizeNumber(value, fallback, min, max) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
      return fallback;
    }
    return Math.min(max, Math.max(min, Math.floor(numeric)));
  }

  function requireString(obj, key, errors, base) {
    if (!obj || typeof obj[key] !== "string" || !obj[key].trim()) {
      errors.push(base + "." + key + " 必须是非空字符串");
    }
  }

  function normalizePollingSeconds(value) {
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) {
      return 60;
    }
    return Math.max(10, Math.floor(numeric));
  }

  function parseHttpUrl(rawUrl) {
    if (typeof rawUrl !== "string") {
      return null;
    }

    try {
      const parsed = new URL(rawUrl, window.location.href);
      if (parsed.protocol === "http:" || parsed.protocol === "https:") {
        return parsed;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  function toSafeHref(rawUrl) {
    if (typeof rawUrl !== "string") {
      return "#";
    }

    try {
      const parsed = new URL(rawUrl, window.location.href);
      const allowed = new Set(["http:", "https:", "mailto:", "tel:", "magnet:"]);
      return allowed.has(parsed.protocol) ? parsed.href : "#";
    } catch (error) {
      return "#";
    }
  }

  function formatDate(rawDate) {
    const d = new Date(rawDate);
    if (Number.isNaN(d.getTime())) {
      return rawDate;
    }
    return d.toLocaleDateString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
  }

  function formatDateTime(date) {
    const d = date instanceof Date ? date : new Date(date);
    return d.toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  }

  function showError(message) {
    const panel = document.getElementById("error-panel");
    panel.classList.remove("hidden");
    panel.innerHTML = String(message)
      .split("\n")
      .map(function (line) {
        return "<div>• " + window.MarkdownRenderer.escapeHtml(line) + "</div>";
      })
      .join("");
  }
})();






