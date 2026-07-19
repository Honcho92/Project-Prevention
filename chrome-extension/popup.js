// popup.js — load detector, ask background for current tab score, render.
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);

  function fmtEntities(e) {
    const out = [];
    if (e.phones && e.phones.length) out.push("Phones: " + e.phones.join(", "));
    if (e.emails && e.emails.length) out.push("Emails: " + e.emails.join(", "));
    if (e.urls   && e.urls.length)   out.push("URLs:   " + e.urls.join(", "));
    if (e.money  && e.money.length)  out.push("Money:  " + e.money.join(", "));
    return out;
  }

  function render(state) {
    const empty = $("empty");
    const page  = $("page-score");
    if (!state) {
      empty.classList.remove("hidden");
      page.classList.add("hidden");
      $("badge").textContent = "clean";
      return;
    }
    empty.classList.add("hidden");
    page.classList.remove("hidden");

    $("badge").textContent = state.verdict;
    $("page-url").textContent = state.url;
    const v = $("verdict");
    v.textContent = state.verdict.toUpperCase();
    v.className = "verdict " + state.verdict;
    $("score").textContent = state.score + "/100";
    $("scam-type").textContent = "Type: " + state.scam_type;

    const sigs = $("signals");
    sigs.innerHTML = "";
    $("signals-count").textContent = state.signals.length;
    for (const s of state.signals) {
      const li = document.createElement("li");
      li.textContent = `[${s.scam_type}] ${s.category}  —  ${JSON.stringify(s.snippet)}`;
      sigs.appendChild(li);
    }

    const ents = $("entities");
    ents.innerHTML = "";
    for (const line of fmtEntities(state.entities)) {
      const li = document.createElement("li");
      li.textContent = line;
      ents.appendChild(li);
    }

    // re-analyze locally so we can attach advice + questions (background didn't send them)
    const r = window.scamShield.analyzeText(state.signals.map(s => s.snippet).join(" "));
    const adv = $("advice");
    adv.innerHTML = "";
    for (const a of (r.advice || []).slice(0, 5)) {
      const li = document.createElement("li");
      li.textContent = a;
      adv.appendChild(li);
    }
    const qs = window.scamShield.pickQuestions(state.scam_type, 3);
    const qEl = $("questions");
    qEl.innerHTML = "";
    for (const q of qs) {
      const li = document.createElement("li");
      const b = document.createElement("strong");
      b.textContent = "Q: ";
      li.appendChild(b);
      li.appendChild(document.createTextNode(q.q));
      const w = document.createElement("div");
      w.style.color = "#475569";
      w.textContent = "Why: " + q.w;
      li.appendChild(w);
      qEl.appendChild(li);
    }
  }

  // get current tab state
  chrome.runtime.sendMessage({ kind: "get-current" }, (resp) => {
    if (resp && resp.ok) render(resp.state);
    else render(null);
  });

  // manual paste-and-score
  $("manual-go").addEventListener("click", () => {
    const txt = $("manual").value;
    if (!txt.trim()) return;
    const r = window.scamShield.analyzeText(txt);
    const v = $("verdict");
    const out = $("manual-out");
    out.innerHTML = "";
    const div = document.createElement("div");
    div.innerHTML = `<div class="verdict ${r.verdict}">${r.verdict.toUpperCase()}  ${r.score}/100  (${r.scam_type})</div>`;
    out.appendChild(div);
    const ul = document.createElement("ul");
    for (const a of r.advice.slice(0, 4)) {
      const li = document.createElement("li");
      li.textContent = a;
      ul.appendChild(li);
    }
    out.appendChild(ul);
  });
})();
