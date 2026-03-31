(() => {
  const API_BASE = "https://api.creatorrr.com";
  const ENDPOINT = `${API_BASE}/analytics/pageview`;

  function safeString(value, max = 512) {
    const text = String(value || "").trim();
    return text.slice(0, max);
  }

  function payload() {
    const referrer = document.referrer ? safeString(document.referrer, 1024) : null;
    return {
      path: safeString(window.location.pathname || "/", 512),
      query: safeString(window.location.search || "", 1024),
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
