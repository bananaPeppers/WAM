/*
 * Content script: reads only the STRUCTURE of the page -- password/form
 * presence, QR/download-link signals. Never reads the value of an input or
 * sends a link, referrer, query string, or full URL. Only booleans and
 * counts go to the background worker.
 */
(function () {
  "use strict";

  var QR_QUERY_KEYS = ["qr", "qrcode", "qr_code", "qrid", "qr_id", "scan_id"];
  var QR_TRACKING_KEYS = ["utm_medium", "utm_source"];
  var QR_TRACKING_VALUES = ["qr", "qrcode", "qr-code", "scan"];
  var QR_PATH_SEGMENTS = ["qr", "qrcode", "qr-code"];

  var RISKY_DOWNLOAD_EXTENSIONS = [
    ".apk", ".appx", ".bat", ".cmd", ".com", ".cpl", ".deb", ".dmg",
    ".exe", ".hta", ".iso", ".jar", ".js", ".jse", ".lnk", ".msi",
    ".msix", ".pkg", ".ps1", ".reg", ".rpm", ".scr", ".vbe", ".vbs",
    ".wsf"
  ];
  var ORDINARY_DOWNLOAD_EXTENSIONS = [
    ".7z", ".avi", ".csv", ".doc", ".docx", ".gif", ".gz", ".jpeg",
    ".jpg", ".json", ".mov", ".mp3", ".mp4", ".pdf", ".png", ".ppt",
    ".pptx", ".rar", ".svg", ".tar", ".tgz", ".txt", ".webm", ".webp",
    ".xls", ".xlsx", ".xml", ".zip"
  ];
  var DOWNLOAD_EXTENSIONS = RISKY_DOWNLOAD_EXTENSIONS.concat(
    ORDINARY_DOWNLOAD_EXTENSIONS
  );

  function sameOrigin(actionUrl) {
    try {
      var resolved = new URL(actionUrl, window.location.href);
      return resolved.origin === window.location.origin;
    } catch (e) {
      return false; // if we cannot tell, treat it as cross-origin (safer)
    }
  }

  function anyFormPostsCrossOrigin() {
    var forms = document.querySelectorAll("form[action]");
    for (var i = 0; i < forms.length; i++) {
      var action = forms[i].getAttribute("action");
      if (action && !sameOrigin(action)) {
        return true;
      }
    }
    return false;
  }

  function decodePath(url) {
    var path = url.pathname || "";
    for (var i = 0; i < 2; i++) {
      try {
        var decoded = decodeURIComponent(path);
        if (decoded === path) break;
        path = decoded;
      } catch (e) {
        break;
      }
    }
    return path.toLowerCase().replace(/[ .]+$/, "");
  }

  function hasExtension(path, extensions) {
    for (var i = 0; i < extensions.length; i++) {
      if (path.endsWith(extensions[i])) return true;
    }
    return false;
  }

  function resolveLink(link) {
    try {
      return new URL(link.getAttribute("href"), window.location.href);
    } catch (e) {
      return null;
    }
  }

  function looksLikeDownloadLink(link, resolved) {
    if (link.hasAttribute("download")) return true;
    if (["data:", "blob:", "file:"].indexOf(resolved.protocol) !== -1) {
      return true;
    }
    if (["http:", "https:"].indexOf(resolved.protocol) === -1) return false;
    return hasExtension(decodePath(resolved), DOWNLOAD_EXTENSIONS);
  }

  function isRiskyDownloadLink(link, resolved) {
    if (!looksLikeDownloadLink(link, resolved)) return false;
    if (["data:", "blob:", "file:", "javascript:"].indexOf(resolved.protocol) !== -1) {
      return true;
    }
    if (hasExtension(decodePath(resolved), RISKY_DOWNLOAD_EXTENSIONS)) return true;
    return window.location.protocol === "https:" && resolved.protocol === "http:";
  }

  function scanDownloadLinks() {
    var result = {
      has_download_link: false,
      has_risky_download_link: false,
      has_cross_origin_download_link: false
    };
    var links = document.querySelectorAll("a[href]");
    for (var i = 0; i < links.length; i++) {
      var resolved = resolveLink(links[i]);
      if (!resolved || !looksLikeDownloadLink(links[i], resolved)) continue;
      result.has_download_link = true;
      if (isRiskyDownloadLink(links[i], resolved)) {
        result.has_risky_download_link = true;
      }
      if (resolved.origin !== window.location.origin) {
        result.has_cross_origin_download_link = true;
      }
      if (
        result.has_download_link &&
        result.has_risky_download_link &&
        result.has_cross_origin_download_link
      ) {
        break;
      }
    }
    return result;
  }

  function hasQrLandingSignal() {
    // Browsers don't tell us a camera opened the URL, so just look for a
    // direct navigation (no referrer) plus an explicit QR marker.
    if (document.referrer) return false;
    var current;
    try {
      current = new URL(window.location.href);
    } catch (e) {
      return false;
    }
    if (["http:", "https:"].indexOf(current.protocol) === -1) return false;

    var found = false;
    current.searchParams.forEach(function (value, key) {
      var normalizedKey = key.toLowerCase();
      if (QR_QUERY_KEYS.indexOf(normalizedKey) !== -1) found = true;
      if (
        QR_TRACKING_KEYS.indexOf(normalizedKey) !== -1 &&
        QR_TRACKING_VALUES.indexOf(value.toLowerCase()) !== -1
      ) {
        found = true;
      }
    });
    if (found) return true;

    var path;
    try { path = decodeURIComponent(current.pathname); }
    catch (e) { path = current.pathname; }
    var segments = path.toLowerCase().split("/");
    for (var i = 0; i < segments.length; i++) {
      if (QR_PATH_SEGMENTS.indexOf(segments[i]) !== -1) return true;
    }
    return false;
  }

  function scanPage() {
    var hasPassword = !!document.querySelector('input[type="password"]');
    var downloads = scanDownloadLinks();
    return {
      event_type: hasPassword ? "login_form" : "page_load",
      is_https: window.location.protocol === "https:",
      has_password_field: hasPassword,
      form_posts_cross_origin: anyFormPostsCrossOrigin(),
      link_count: document.querySelectorAll("a[href]").length,
      has_qr_landing_signal: hasQrLandingSignal(),
      has_download_link: downloads.has_download_link,
      has_risky_download_link: downloads.has_risky_download_link,
      has_cross_origin_download_link: downloads.has_cross_origin_download_link,
      hostname: window.location.hostname
    };
  }

  function sendScan() {
    try {
      chrome.runtime.sendMessage({ type: "scan", signals: scanPage() });
    } catch (e) {
      /* extension context may be reloading; ignore */
    }
  }

  // Allow the popup to request a fresh scan.
  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message && message.type === "rescan") {
      sendScan();
      sendResponse({ ok: true });
    }
    return false;
  });

  // Scan once the page has settled.
  if (document.readyState === "complete") {
    sendScan();
  } else {
    window.addEventListener("load", sendScan, { once: true });
  }
})();
