// detector.js — port of the Python detector to vanilla JS.
// Same pattern bank, same scoring, same verdict buckets. No deps.

const SCAM_PATTERNS = [
  // tech support
  { scam_type: "tech_support", category: "claims to be Microsoft/Apple/Geek Squad/Amazon support", weight: 25,
    re: /\b(microsoft|apple support|geek squad|amazon (?:support|security)|norton|mcafee|avast)\b/i },
  { scam_type: "tech_support", category: "remote-access request (AnyDesk, TeamViewer, Quick Support)", weight: 30,
    re: /\b(anydesk|teamviewer|quick ?support|rustdesk|supremo|connectwise)\b/i },
  { scam_type: "tech_support", category: "asks to install software / grant access", weight: 15,
    re: /\b(install|download|run|open|type)\b.{0,40}\b(software|program|app|command|cmd|terminal|this (?:link|file))\b/i },

  // government
  { scam_type: "government", category: "claims to be IRS/SSA/FBI/marshall/court", weight: 30,
    re: /\b(internal revenue|IRS|social security (?:administration|office)|SSA|FBI|U\.?S\.? Marshal|Department of Justice|federal court|warrant (?:for your )?arrest)\b/i },
  { scam_type: "government", category: "demands payment to avoid arrest", weight: 25,
    re: /\b(arrest|jail|prison|legal action|criminal charges|warrant)\b.{0,80}\b(pay|payment|owe|back\s*taxes|unpaid)\b/i },
  { scam_type: "government", category: "asks for gift cards / wire / crypto as tax payment", weight: 30,
    re: /\b(gift ?cards?|itunes|google play|steam cards?|bitcoin|crypto ?wallet|wire transfer|western union|moneygram)\b/i },

  // bank impersonation
  { scam_type: "bank_impersonation", category: "claims to be bank fraud / Visa / Mastercard security", weight: 25,
    re: /\b(bank (?:fraud|security)|visa (?:security|fraud)|mastercard (?:security|fraud)|fraud (?:department|unit|team)|account (?:is )?compromised|unauthorized (?:charge|transaction))\b/i },
  { scam_type: "bank_impersonation", category: "asks for full card / PIN / SSN / online banking password", weight: 35,
    re: /\b(card number|cvv|security code|pin (?:number|code)|social security number|ssn|online (?:banking|password)|one[- ]time (?:code|password|passcode)|otp)\b/i },
  { scam_type: "bank_impersonation", category: "asks you to move money to 'safe' account", weight: 25,
    re: /\b(safe (?:account|wallet)|protect (?:your )?funds|transfer (?:to|into) .{0,30}account|verify (?:your )?(?:account|identity))\b/i },

  // package
  { scam_type: "package", category: "fake USPS / UPS / FedEx / DHL package problem", weight: 25,
    re: /\b(usps|ups|fedex|dhl)\b.{0,80}\b(deliver(?:ed|ing)?|package|parcel|shipment|redeliver|address (?:issue|problem)|held|customs)\b|\bpackage\b.{0,80}\b(customs|redeliver|small fee|verification|reschedule)\b/i },
  { scam_type: "package", category: "asks for small redelivery / customs fee", weight: 15,
    re: /\b(customs (?:fee|charge)|redelivery (?:fee|charge)|small (?:re-?)?shipment fee|confirm (?:your )?(?:address|details) (?:to|for) delivery)\b/i },
  { scam_type: "package", category: "fake redelivery / customs link domain", weight: 20,
    re: /\b[a-z0-9\-]*\b(?:usps|ups|fedex|dhl)\b[a-z0-9\-]*\.(?:top|xyz|click|support|help|online|delivery|track)\b/i },

  // romance
  { scam_type: "romance", category: "long-distance / military / oil-rig / doctor abroad", weight: 25,
    re: /\b(deployed (?:in|to)|on (?:a|an) (?:oil rig|ship|military base)|stranded|stuck in|customs (?:in|at) [A-Z])\b/i },
  { scam_type: "romance", category: "lovesick / soulmate language early on", weight: 15,
    re: /\b(my (?:dear(?:est)?|love|beautiful|queen|king|soul ?mate|everything|heart)|i (?:fell|am falling) (?:deeply )?in love|missing you (?:so much|already)|can'?t wait to (?:see|meet|hold) you)\b/i },
  { scam_type: "romance", category: "money / gift card ask from romantic partner", weight: 30,
    re: /\b(can you (?:help|send|lend|wire|transfer|gift)|need (?:a little|some) (?:help|money|favor)|i('?m| am) (?:stuck|in trouble|stranded) and need)\b/i },

  // job
  { scam_type: "job_scam", category: "unusually high pay / easy work / immediate start", weight: 20,
    re: /\b(\$\s?\d{2,4}\s?(?:\/|per|a|an) (?:day|hour|week|task)|easy (?:money|cash|work)|work[- ]from[- ]home (?:and earn|opportunity)|no experience (?:needed|required)|immediate (?:start|hiring))\b/i },
  { scam_type: "job_scam", category: "asks for upfront payment / training fee", weight: 25,
    re: /\b(training fee|startup (?:fee|cost)|equipment (?:fee|deposit)|send (?:a|us) (?:money|funds) (?:to|for)|pay (?:first|upfront) (?:a|the))\b/i },
  { scam_type: "job_scam", category: "asks for bank details or to receive + forward money", weight: 30,
    re: /\b(receive (?:payments?|funds?|transfers?) and (?:forward|send|wire)|deposit (?:into|to) your (?:bank|account)|provide (?:your )?(?:bank|account) (?:details|info))\b/i },

  // crypto
  { scam_type: "crypto_investment", category: "guaranteed / risk-free / huge returns", weight: 25,
    re: /\b(guaranteed (?:return|profit|earnings)|risk[- ]free (?:invest|trading)|(100|x|10x|20x) (?:return|lever|gain)|passive income of \$?\d{3,}|get (?:rich|wealthy) (?:with|using|through))\b/i },
  { scam_type: "crypto_investment", category: "fake celebrity endorsement or 'insider' pitch", weight: 20,
    re: /\b(elon (?:musk )?giveaway|crypto (?:airdrop|signal (?:group|channel))|forex (?:mentor|signal)|whale (?:wallet|alert)|insider (?:tip|info)|pump (?:and|&) dump)\b/i },
  { scam_type: "crypto_investment", category: "asks to send crypto / connect wallet to 'claim'", weight: 30,
    re: /\b(connect (?:your )?(?:wallet|metamask|trust wallet)|send (?:a|0\.\d+) (?:eth|btc|usdt) to (?:claim|verify|activate|unlock))\b/i },

  // lottery
  { scam_type: "lottery", category: "you won / claim prize / lucky winner", weight: 25,
    re: /\b(congratulations? (?:you|on winning)|you(?:'ve| have) (?:won|been selected)|claim (?:your )?(?:prize|reward|winnings?)|lucky (?:winner|draw))\b/i },
  { scam_type: "lottery", category: "lottery you never entered", weight: 15,
    re: /\b(microsoft (?:lotto|lottery|award)|amazon (?:lottery|award)|bmw (?:giveaway|lottery)|mega (?:millions|lotto) (?:winner|prize))\b/i },

  // universal
  { scam_type: "universal", category: "urgency / countdown / act now", weight: 10,
    re: /\b(within (?:the next )?(?:\d{1,3} (?:minutes?|hours?)|24 hours|48 hours)|act (?:now|immediately|fast|quickly)|don'?t (?:delay|wait)|time[- ]sensitive|expires? (?:today|in \d+ (?:min|hour|day)))\b/i },
  { scam_type: "universal", category: "secrecy / don't tell anyone", weight: 15,
    re: /\b(don'?t (?:tell|inform|notify) (?:anyone|your (?:bank|family|partner))|keep (?:this )?(?:between us|confidential|private)|(?:this )?must (?:remain|be) (?:confidential|a secret))\b/i },
  { scam_type: "universal", category: "payment in untraceable form", weight: 20,
    re: /\b(gift ?cards?|itunes cards?|google play cards?|steam cards?|vanilla (?:visa )?cards?|bitcoin|crypto|usdt|wire (?:transfer)?|western union|moneygram|zelle|venmo|cash ?app)\b/i },
  { scam_type: "universal", category: "click here / tap here / log in via link", weight: 10,
    re: /\b(click (?:here|below|the link)|tap (?:here|the link)|follow (?:this )?(?:link|url)|log ?in (?:here|via (?:this )?link)|verify (?:your )?account (?:now|here|via))\b/i },
  { scam_type: "universal", category: "shortened / lookalike / punycode link", weight: 15,
    re: /\b((?:bit\.ly|tinyurl\.com|t\.co|is\.gd|ow\.ly|rebrand\.ly|cutt\.ly|shorturl\.at|rb\.gy|lnkd\.in|tiny\.cc)\/\S+|(?:[a-z0-9-]+\.){1,3}(?:xyz|top|click|support|help|secure|login|verify|account|update)(?:\/\S*)?)\b/i },
];

const BRAND_DOMAINS = {
  paypal:      ["paypa1", "paypall", "paypai", "paypa.l"],
  amazon:      ["amaz0n", "amazom", "amazn", "amaz.on", "arnazon"],
  apple:       ["app1e", "appie", "app1e-id", "apple-id"],
  microsoft:   ["microsft", "micros0ft", "mircosoft", "micros oft", "msft-login"],
  google:      ["go0gle", "g00gle", "gogle", "goog1e"],
  fedex:       ["fedexx", "fed-ex", "fede-x"],
  ups:         ["ups-tracking", "ups-delivery"],
  usps:        ["uspss", "us-ps", "usps-track"],
  dhl:         ["dh1", "dhl-tracking"],
  chase:       ["chase-bank", "chaseonline-"],
  "wells fargo":["wellsfarg0", "wellfargo", "wels-fargo"],
  netflix:     ["netf1ix", "netfllx"],
  facebook:    ["faceb00k", "facebok", "facebook-login"],
  instagram:   ["1nstagram", "instagrarn"],
  linkedin:    ["1inkedin", "linkedln", "linked-in"],
};

const PHONE_RE  = /(?:(?<=\s)|(?<=\b))(\+?\d{1,3}[ \-]?\(?\d{2,4}\)?[ \-]?\d{3,4}[ \-]?\d{3,4})(?=\s|$|[.,;])/g;
const EMAIL_RE  = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;
const URL_RE    = /\b((?:https?:\/\/|www\.)[^\s<>"']+|[a-z0-9\-]+\.[a-z]{2,}(?:\/\S*)?)/gi;
const HANDLE_RE = /(?<![A-Za-z0-9._])@([A-Za-z0-9_]{3,30})\b/g;
const MONEY_RE  = /(?:[$€£]\s?\d[\d,.\s]*|\b(?:usd|eur|gbp)\s?\$?\s?\d[\d,.\s]*|\b\d[\d,.\s]*\s?(?:dollars?|usd|euros?|eur|gbp|pounds?))/gi;

const PRIORITY = [
  "phishing", "crypto_investment", "tech_support", "bank_impersonation",
  "government", "romance", "job_scam", "package", "lottery", "universal",
];

function extractEntities(text) {
  const uniq = (arr) => Array.from(new Set(arr)).slice(0, 20);
  const phones  = uniq(Array.from((text.match(PHONE_RE)  || []))
                         .map(s => s.trim()).filter(s => s.replace(/\D/g, "").length >= 7 && s.replace(/\D/g, "").length <= 15));
  const emails  = uniq(text.match(EMAIL_RE)  || []);
  const urls    = uniq((text.match(URL_RE)    || []).map(s => s.replace(/[.,;:!?)]$/, "")));
  const handles = uniq(text.match(HANDLE_RE) || []);
  const money   = uniq((text.match(MONEY_RE) || []).map(s => s.trim()));
  return { phones, emails, urls, handles, money };
}

function verdictFromScore(score) {
  if (score >= 75) return "scam";
  if (score >= 50) return "likely_scam";
  if (score >= 25) return "suspicious";
  return "clean";
}

function adviceFor(scamType) {
  const base = [
    "Never send money, gift cards, crypto, or wire transfers to someone you cannot meet in person.",
    "Never share full SSN, full card number, CVV, PIN, or one-time codes over phone/email/chat.",
    "Hang up and call the institution back on a number you look up yourself (back of card, official site).",
  ];
  const extra = {
    tech_support: [
      "Real Microsoft/Apple support will never cold-call you about a problem.",
      "Never install remote-access software at the request of an unsolicited caller.",
    ],
    government: [
      "The IRS, SSA, and FBI NEVER demand gift cards, crypto, or wire transfers.",
      "Real agencies send official correspondence by mail first. Threats of immediate arrest are always a scam.",
    ],
    bank_impersonation: [
      "Your bank already has your account info — they will not ask you to 'verify' the full number or PIN.",
      "If a 'fraud department' calls you, hang up and call the number on the back of your card.",
    ],
    package: [
      "Carriers charge redelivery/customs via the official site or app, never via a link in a text.",
    ],
    romance: [
      "Reverse-search their photos. Never send money to someone you have not met in person.",
      "Insist on a live video call early. Most scammers will refuse.",
    ],
    job_scam: [
      "Legitimate employers never charge upfront fees for training or equipment.",
      "Never receive and forward payments on behalf of a 'client' — that is money laundering.",
    ],
    crypto_investment: [
      "There is no such thing as guaranteed returns in crypto. Anyone promising them is committing fraud.",
      "Never connect your wallet to a site sent by a stranger.",
    ],
    lottery: [
      "You cannot win a lottery you did not enter. Real lotteries do not require you to pay to claim.",
    ],
    universal: ["Urgency + secrecy + untraceable payment = scam. Full stop."],
  };
  return base.concat(extra[scamType] || []);
}

function analyzeText(text) {
  if (!text || !text.trim()) {
    return {
      score: 0, verdict: "clean", scam_type: "unknown",
      signals: [], entities: { phones: [], emails: [], urls: [], handles: [], money: [] },
      advice: ["Nothing to analyze."],
    };
  }

  const lower = text.toLowerCase();
  const signals = [];
  const typeScore = {};

  for (const p of SCAM_PATTERNS) {
    const m = text.match(p.re);
    if (m) {
      signals.push({ scam_type: p.scam_type, category: p.category, weight: p.weight, snippet: m[0].slice(0, 120) });
      typeScore[p.scam_type] = (typeScore[p.scam_type] || 0) + p.weight;
    }
  }

  // brand-impersonation lookalike links
  const urls = Array.from(text.match(URL_RE) || []).map(s => s.replace(/[.,;:!?)]$/, ""));
  for (const [brand, typos] of Object.entries(BRAND_DOMAINS)) {
    if (lower.includes(brand)) {
      for (const u of urls) {
        const ul = u.toLowerCase();
        if (typos.some(t => ul.includes(t)) ||
            (ul.includes(brand) && !new RegExp(`\\b${brand}\\.(com|net|org|co|gov|io|ca|uk|de)\\b`).test(ul))) {
          signals.push({ scam_type: "phishing", category: `impersonating ${brand} via lookalike link`, weight: 30, snippet: u.slice(0, 120) });
          typeScore.phishing = (typeScore.phishing || 0) + 30;
        }
      }
    }
  }
  if ("phishing" in typeScore) {
    if (/\b(click (?:here|below|the link)|verify (?:your )?account|log ?in (?:here|via) (?:this )?link|suspended|locked|limited)\b/i.test(lower)) {
      signals.push({ scam_type: "phishing", category: "phishing link + account-suspension urgency", weight: 15, snippet: "phishing + urgency combo" });
      typeScore.phishing += 15;
    }
  }
  for (const u of urls) {
    const host = u.replace(/^https?:\/\//, "").split("/")[0].split("?")[0].toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      signals.push({ scam_type: "phishing", category: "raw IP address in link", weight: 20, snippet: u.slice(0, 120) });
      typeScore.phishing = (typeScore.phishing || 0) + 20;
    }
    if (host.includes("xn--")) {
      signals.push({ scam_type: "phishing", category: "punycode / IDN homograph link", weight: 20, snippet: u.slice(0, 120) });
      typeScore.phishing = (typeScore.phishing || 0) + 20;
    }
  }

  // scam_type tie-break
  let scamType = "unknown";
  if (Object.keys(typeScore).length > 0) {
    const max = Math.max(...Object.values(typeScore));
    const top = Object.keys(typeScore).filter(k => typeScore[k] >= max - 5);
    for (const t of PRIORITY) if (top.includes(t)) { scamType = t; break; }
  } else if (signals.some(s => s.scam_type === "universal")) {
    scamType = "universal";
  }

  // score with diminishing returns
  const raw = signals.reduce((a, s) => a + s.weight, 0);
  let score = Math.min(100, Math.round(100 * (1 - Math.pow(0.95, raw / 5))));
  if (Object.keys(typeScore).length >= 2) score = Math.min(100, score + 5);
  if (Object.keys(typeScore).length >= 3) score = Math.min(100, score + 5);

  const verdict = verdictFromScore(score);
  const entities = extractEntities(text);
  const advice = verdict === "clean"
    ? ["Nothing obvious triggered. Stay alert — no detector is perfect."]
    : adviceFor(scamType);

  return { score, verdict, scam_type: scamType, signals, entities, advice };
}

// Playbook questions — abbreviated subset for the popup
const PLAYBOOK = {
  universal: [
    { id: "uni-timezone",     q: "What time zone are you in right now?",
      w: "Scammers cluster in specific time zones. Their answer often contradicts their claimed identity." },
    { id: "uni-employee-id",  q: "What's your employee / agent / case number?",
      w: "Real agents have one. Scammers either make one up that won't match later, or dodge." },
    { id: "uni-conference",   q: "Hold on, let me conference in my buddy who works at [company] — your full name and direct number?",
      w: "Scammers vanish the second you threaten to bring in a third party." },
  ],
  tech_support: [
    { id: "tech-tier",   q: "Which support tier — 1, 2, or 3?",
      w: "Real support uses tiers; scammers copy lingo from one script and don't know which tier they're 'in'." },
    { id: "tech-badge",  q: "What's the badge / technician ID?",
      w: "Microsoft, Apple, Geek Squad all have real IDs. Scammers invent one." },
  ],
  government: [
    { id: "gov-office",  q: "Which field office is this case out of?",
      w: "Real IRS letters name a specific office. Scammers almost always say 'New York' or 'DC'." },
    { id: "gov-letter",  q: "What's the certified mail number on the notice?",
      w: "USPS Certified Mail has a real 20-digit number. Scammers have none." },
  ],
  bank_impersonation: [
    { id: "bank-last4",  q: "What's the last 4 of my account you see on file?",
      w: "Your real bank knows. A scammer who initiated the call usually does not." },
    { id: "bank-merchant", q: "What's the merchant name on the suspicious charge YOU flagged?",
      w: "Script-flip: they made up the charge. Asking them to recall it = total freeze." },
  ],
  package: [
    { id: "pkg-tracking", q: "What's the full tracking number on the label?",
      w: "Real ops have it. Scammers send a 'short link' instead." },
  ],
  romance: [
    { id: "rom-selfie",  q: "Send a selfie holding today's paper with the date visible.",
      w: "Gold standard. Stock-photo scammers cannot do this." },
    { id: "rom-video",   q: "Quick voice note — just say good morning. Or a 5-second video call?",
      w: "Most scammers will not risk exposing themselves." },
  ],
  job_scam: [
    { id: "job-ein",     q: "What's the company EIN?",
      w: "Employer Identification Number. Free to look up on the IRS site in 10 seconds." },
  ],
  crypto_investment: [
    { id: "crypto-finra", q: "What's your FINRA license number?",
      w: "Anyone selling securities in the US must have one. Free look-up at brokercheck.finra.org." },
  ],
  lottery: [
    { id: "lot-entry",   q: "When did I enter this drawing? Which ticket number?",
      w: "You never entered. They cannot produce a real ticket." },
  ],
  phishing: [
    { id: "phish-domain", q: "What's the company's official domain? I'll go there myself.",
      w: "If they can't tell you, it's a phishing link." },
  ],
};

function pickQuestions(scamType, n = 3) {
  const out = [];
  const seen = new Set();
  for (const q of (PLAYBOOK.universal || [])) {
    if (!seen.has(q.id)) { out.push(q); seen.add(q.id); }
  }
  for (const q of (PLAYBOOK[scamType] || [])) {
    if (!seen.has(q.id)) { out.push(q); seen.add(q.id); }
  }
  // Fisher-Yates shuffle then take n
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out.slice(0, n);
}

// expose for both content and popup use
if (typeof self !== "undefined" && self) self.scamShield = { analyzeText, pickQuestions };
if (typeof window !== "undefined") window.scamShield = { analyzeText, pickQuestions };
