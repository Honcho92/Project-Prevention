// background.js — service worker. Receives scores from content scripts,
// updates the toolbar badge, and serves the popup.

const STATE = {
  perTab: new Map(),  // tabId -> { score, verdict, scam_type, signals, entities, url, title }
  globalVerdict: "clean",
  globalScore: 0,
};

function badgeFor(verdict) {
  if (verdict === "scam")         return { text: "!!",  color: "#b00020" };
  if (verdict === "likely_scam")  return { text: "?",   color: "#d97706" };
  if (verdict === "suspicious")   return { text: "..",  color: "#ca8a04" };
  return { text: "", color: "#16a34a" };
}

function applyTabState(tabId) {
  const s = STATE.perTab.get(tabId);
  if (!s) {
    chrome.action.setBadgeText({ tabId, text: "" });
    return;
  }
  const b = badgeFor(s.verdict);
  chrome.action.setBadgeText({ tabId, text: b.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.kind === "page-scored" && sender.tab) {
    const tabId = sender.tab.id;
    STATE.perTab.set(tabId, {
      url:    msg.url,
      title:  msg.title,
      score:  msg.score,
      verdict: msg.verdict,
      scam_type: msg.scam_type,
      signals: msg.signals,
      entities: msg.entities,
    });
    applyTabState(tabId);
    sendResponse({ ok: true });
    return true;
  }
  if (msg && msg.kind === "get-current") {
    // popup is asking for the current tab's score
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0] && tabs[0].id;
      const s = tabId != null ? STATE.perTab.get(tabId) : null;
      sendResponse({ ok: true, state: s || null });
    });
    return true;
  }
  if (msg && msg.kind === "analyze-selection") {
    try {
      const r = self.scamShield ? self.scamShield.analyzeText(msg.text) : null;
      sendResponse({ ok: !!r, result: r });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => { STATE.perTab.delete(tabId); });
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    STATE.perTab.delete(tabId);
    applyTabState(tabId);
  }
});
