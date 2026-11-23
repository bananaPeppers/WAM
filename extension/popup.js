/*
 * Popup: shows the current page's security overview and warning details,
 * and lets the user change settings or pause WAM on this site.
 */
(function () {
  "use strict";

  var DEFAULT_SETTINGS = {
    enabled: true,
    backendUrl: "http://127.0.0.1:5000",
    pausedHosts: []
  };

  var LEVEL_LABEL = {
    safe: "Looks safe",
    warning: "Be careful",
    danger: "Warning",
    unclear: "Needs a closer look",
    "local-only": "Checked locally only",
    limited: "Limited check",
    paused: "Paused on this site"
  };

  var els = {
    site: document.getElementById("site"),
    card: document.getElementById("statusCard"),
    pill: document.getElementById("statusPill"),
    source: document.getElementById("statusSource"),
    findings: document.getElementById("findings"),
    explanation: document.getElementById("explanation"),
    note: document.getElementById("note"),
    enabled: document.getElementById("enabled"),
    backendUrl: document.getElementById("backendUrl"),
    pauseBtn: document.getElementById("pauseBtn"),
    saveBtn: document.getElementById("saveBtn"),
    rescanBtn: document.getElementById("rescanBtn")
  };

  var activeTab = null;

  function getSettings() {
    return new Promise(function (resolve) {
      chrome.storage.local.get("wam_settings", function (data) {
        resolve(Object.assign({}, DEFAULT_SETTINGS, data.wam_settings || {}));
      });
    });
  }

  function getVerdict(tabId) {
    return new Promise(function (resolve) {
      var store = chrome.storage.session || chrome.storage.local;
      store.get("wam_tab_" + tabId, function (data) {
        resolve(data["wam_tab_" + tabId] || null);
      });
    });
  }

  function render(verdict, settings) {
    var host = (activeTab && activeTab.url) ? new URL(activeTab.url).hostname : "";
    els.site.textContent = host;

    var level = verdict ? verdict.level : "safe";
    els.card.className = "status status-" + level;
    els.pill.textContent = verdict ? (LEVEL_LABEL[level] || level) : "No scan yet";
    els.source.textContent = verdict ? ("Source: " + verdict.source) : "";

    els.findings.innerHTML = "";
    var findings = (verdict && verdict.findings) || [];
    if (!findings.length) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = verdict ? "No specific warnings." : "Open a page and WAM will check it.";
      els.findings.appendChild(li);
    } else {
      findings.forEach(function (f) {
        var li = document.createElement("li");
        li.className = f.level || "info";
        li.textContent = f.message;
        if (f.advice) {
          var span = document.createElement("span");
          span.className = "advice";
          span.textContent = f.advice;
          li.appendChild(span);
        }
        els.findings.appendChild(li);
      });
    }

    toggle(els.explanation, verdict && verdict.explanation, verdict && verdict.explanation);
    toggle(els.note, verdict && verdict.note, verdict && verdict.note);

    els.enabled.checked = settings.enabled;
    els.backendUrl.value = settings.backendUrl;
    var paused = settings.pausedHosts.indexOf(host) !== -1;
    els.pauseBtn.textContent = paused ? "Resume WAM on this site" : "Pause WAM on this site";
  }

  function toggle(el, show, text) {
    if (show) {
      el.textContent = text;
      el.classList.remove("hidden");
    } else {
      el.classList.add("hidden");
    }
  }

  function saveSettings(settings) {
    return new Promise(function (resolve) {
      chrome.storage.local.set({ wam_settings: settings }, resolve);
    });
  }

  async function refresh() {
    var settings = await getSettings();
    var verdict = activeTab ? await getVerdict(activeTab.id) : null;
    render(verdict, settings);
  }

  function currentHost() {
    try { return new URL(activeTab.url).hostname; } catch (e) { return ""; }
  }

  // --- Wire up controls ---
  els.saveBtn.addEventListener("click", async function () {
    var settings = await getSettings();
    settings.enabled = els.enabled.checked;
    settings.backendUrl = els.backendUrl.value.trim() || DEFAULT_SETTINGS.backendUrl;
    await saveSettings(settings);
    els.saveBtn.textContent = "Saved";
    setTimeout(function () { els.saveBtn.textContent = "Save"; }, 1200);
  });

  els.pauseBtn.addEventListener("click", async function () {
    var settings = await getSettings();
    var host = currentHost();
    var idx = settings.pausedHosts.indexOf(host);
    if (idx === -1) { settings.pausedHosts.push(host); }
    else { settings.pausedHosts.splice(idx, 1); }
    await saveSettings(settings);
    rescan();
  });

  els.rescanBtn.addEventListener("click", rescan);

  function rescan() {
    if (!activeTab) return;
    try {
      chrome.tabs.sendMessage(activeTab.id, { type: "rescan" }, function () {
        void chrome.runtime.lastError; // ignore if no content script
        setTimeout(refresh, 400);
      });
    } catch (e) { setTimeout(refresh, 400); }
  }

  // --- Init ---
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    activeTab = tabs[0] || null;
    refresh();
  });
})();
