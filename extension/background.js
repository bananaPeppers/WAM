/*
 * Service worker: receives raw signals from content.js, runs the local
 * Privacy Guard / Threat Analyzer (wam-local.js), and -- only for unclear
 * login pages, when the daily budget allows and the site isn't protected
 * webmail -- asks the backend for optional AI help. Verdict gets stored per
 * tab and shown on the toolbar badge.
 */
importScripts("wam-local.js");

var DEFAULT_SETTINGS = {
  enabled: true,
  backendUrl: "http://127.0.0.1:5000",
  pausedHosts: []
};
var DEFAULT_BUDGET_LIMIT = 5;

var BADGE = {
  danger: { text: "!", color: "#c0392b" },
  warning: { text: "!", color: "#e67e22" },
  unclear: { text: "?", color: "#e67e22" },
  "local-only": { text: "?", color: "#e67e22" },
  limited: { text: "~", color: "#7f8c8d" },
  safe: { text: "OK", color: "#27ae60" },
  paused: { text: "", color: "#7f8c8d" }
};

function getSettings() {
  return new Promise(function (resolve) {
    chrome.storage.local.get("wam_settings", function (data) {
      resolve(Object.assign({}, DEFAULT_SETTINGS, data.wam_settings || {}));
    });
  });
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

// Per-install daily budget. Returns true if a call is allowed (and counts it).
function spendBudget() {
  return new Promise(function (resolve) {
    chrome.storage.local.get("wam_budget", function (data) {
      var budget = data.wam_budget || { day: today(), count: 0, limit: DEFAULT_BUDGET_LIMIT };
      if (budget.day !== today()) {
        budget = { day: today(), count: 0, limit: budget.limit || DEFAULT_BUDGET_LIMIT };
      }
      if (budget.count >= (budget.limit || DEFAULT_BUDGET_LIMIT)) {
        resolve(false);
        return;
      }
      budget.count += 1;
      chrome.storage.local.set({ wam_budget: budget }, function () { resolve(true); });
    });
  });
}

function setBadge(tabId, level) {
  var style = BADGE[level] || BADGE.safe;
  try {
    chrome.action.setBadgeText({ tabId: tabId, text: style.text });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: style.color });
  } catch (e) { /* tab may be gone */ }
}

function storeVerdict(tabId, verdict) {
  var store = chrome.storage.session || chrome.storage.local;
  var record = {};
  record["wam_tab_" + tabId] = verdict;
  store.set(record);
}

function askBackend(backendUrl, summary) {
  return fetch(backendUrl.replace(/\/+$/, "") + "/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(summary)
  }).then(function (response) {
    if (!response.ok) throw new Error("backend status " + response.status);
    return response.json();
  });
}

async function handleScan(signals, tabId) {
  var settings = await getSettings();
  var hostname = signals.hostname || "";

  if (!settings.enabled || settings.pausedHosts.indexOf(hostname) !== -1) {
    var paused = { hostname: hostname, level: "paused", source: "paused",
      findings: [], note: "WAM is paused on this site.", ts: Date.now() };
    storeVerdict(tabId, paused);
    setBadge(tabId, "paused");
    return;
  }

  var summary = WamLocal.buildSafeSummary(signals);
  var local = WamLocal.analyzeLocal(summary);

  var verdict = {
    hostname: hostname,
    level: local.level,
    source: "local",
    findings: local.findings,
    explanation: null,
    note: null,
    ts: Date.now()
  };

  // Optional AI help for unclear, non-protected login pages.
  if (local.needsAi && !summary.protected_mode && settings.backendUrl) {
    var allowed = await spendBudget();
    if (!allowed) {
      verdict.source = "local-only";
      verdict.note = "AI check unavailable—daily limit reached (local checks only).";
    } else {
      try {
        var server = await askBackend(settings.backendUrl, summary);
        verdict.level = server.level || verdict.level;
        verdict.source = server.source || "ai";
        verdict.findings = server.findings && server.findings.length ? server.findings : verdict.findings;
        verdict.explanation = server.explanation || null;
        verdict.note = server.note || null;
      } catch (e) {
        verdict.source = "local-only";
        verdict.note = "AI check unavailable—local checks only.";
      }
    }
  }

  storeVerdict(tabId, verdict);
  setBadge(tabId, verdict.level);
}

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (message && message.type === "scan" && sender.tab) {
    handleScan(message.signals, sender.tab.id);
  }
  return false;
});
