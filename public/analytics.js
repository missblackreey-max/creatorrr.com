(() => {
  const API_BASE = "https://api.creatorrr.com";
  const ENDPOINT = `${API_BASE}/analytics/pageview`;

  function safeString(value, max = 512) {
    const text = String(value || "").trim();
    return text.slice(0, max);
  }

  function safeQueryString(search) {
    if (!search) return "";

    const params = new URLSearchParams(search);
    const safeParams = new URLSearchParams();

    for (const [key] of params.entries()) {
      safeParams.append(key, "1");
    }

    const normalizedQuery = safeParams.toString();
    return normalizedQuery ? safeString(`?${normalizedQuery}`, 1024) : "";
  }

  function payload() {
    const referrer = document.referrer ? safeString(document.referrer, 1024) : null;
    return {
      path: safeString(window.location.pathname || "/", 512),
      query: safeQueryString(window.location.search),
      referrer,
      title: safeString(document.title || "", 512),
      tz: safeString(Intl.DateTimeFormat().resolvedOptions().timeZone || "", 128) || null,
      screen: window.screen ? `${window.screen.width}x${window.screen.height}` : null,
      lang: safeString(navigator.language || "", 64) || null,
    };
  }

  function sendPageView() {
    const body = JSON.stringify(payload());
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      navigator.sendBeacon(ENDPOINT, blob);
      return;
    }
    fetch(ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", sendPageView, { once: true });
  } else {
    sendPageView();
  }
})();
