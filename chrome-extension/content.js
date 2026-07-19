// content.js — runs on every page, scrapes text, scores it, sends to background.
(function () {
  "use strict";
  if (!window.scamShield) return;

  function scrape() {
    // body text minus scripts/styles/iframes
    const clone = document.body ? document.body.cloneNode(true) : null;
    if (!clone) return "";
    clone.querySelectorAll("script, style, noscript, iframe, svg, link").forEach(n => n.remove());
    let t = (clone.innerText || "").trim();
    if (t.length > 50000) t = t.slice(0, 50000);
    return t;
  }

  function go() {
    const text = scrape();
    if (!text || text.length < 30) return;
    const r = window.scamShield.analyzeText(text);
    if (r.verdict === "clean") return;
    try {
      chrome.runtime.sendMessage({
        kind: "page-scored",
        url: location.href,
        title: document.title,
        score: r.score,
        verdict: r.verdict,
        scam_type: r.scam_type,
        signals: r.signals.slice(0, 10),
        entities: {
          phones: r.entities.phones.slice(0, 5),
          emails: r.entities.emails.slice(0, 5),
          urls:   r.entities.urls.slice(0, 5),
          money:  r.entities.money.slice(0, 5),
        },
      });
    } catch (e) { /* extension reloading, ignore */ }
  }

  // run after load, and again on significant DOM changes (debounced)
  setTimeout(go, 1500);
  let timer = null;
  const obs = new MutationObserver(() => {
    if (timer) return;
    timer = setTimeout(() => { timer = null; go(); }, 2000);
  });
  if (document.body) {
    obs.observe(document.body, { childList: true, subtree: true });
  }
})();
