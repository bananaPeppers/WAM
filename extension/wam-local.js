/*
 * Shared local logic (privacy guard + threat rules), kept dependency-free so
 * it can warn without any network call. Mirrors the backend's Python logic.
 * Loaded by both the background worker (importScripts) and the popup.
 *
 * Nothing in here reads a user's typed values -- just the non-personal
 * "raw signals" content.js collected.
 */
(function (root) {
  "use strict";

  // Exact protected webmail hosts (no look-alikes).
  var PROTECTED_EMAIL_HOSTS = [
    "mail.google.com",
    "outlook.live.com",
    "outlook.office.com"
  ];

  function isProtectedEmailHost(hostname) {
    if (!hostname) return false;
    return PROTECTED_EMAIL_HOSTS.indexOf(String(hostname).toLowerCase()) !== -1;
  }

  // Build the approved, non-personal summary. The hostname is used to decide
  // protected mode, then dropped (never forwarded).
  function buildSafeSummary(raw) {
    raw = raw || {};
    var protectedMode = isProtectedEmailHost(raw.hostname);
    return {
      event_type: String(raw.event_type || "other"),
      is_https: !!raw.is_https,
      has_password_field: !!raw.has_password_field,
      form_posts_cross_origin: !!raw.form_posts_cross_origin,
      link_count: parseInt(raw.link_count, 10) || 0,
      has_qr_landing_signal: !!raw.has_qr_landing_signal,
      has_download_link: !!raw.has_download_link,
      has_risky_download_link: !!raw.has_risky_download_link,
      has_cross_origin_download_link: !!raw.has_cross_origin_download_link,
      host_category: protectedMode ? "protected_email" : "normal",
      protected_mode: protectedMode
    };
  }

  var SEVERITY = { safe: 0, info: 1, warning: 2, danger: 3 };

  function overallLevel(findings) {
    if (!findings.length) return "safe";
    return findings
      .map(function (f) { return f.level; })
      .reduce(function (a, b) {
        return SEVERITY[b] > SEVERITY[a] ? b : a;
      });
  }

  function finding(code, level, message, advice) {
    return { code: code, level: level, message: message, advice: advice };
  }

  // Local threat rules. Returns { level, findings, needsAi }.
  function analyzeLocal(summary) {
    if (summary.protected_mode) {
      return {
        level: "limited",
        needsAi: false,
        findings: [finding(
          "protected_mode_active", "info",
          "Protected mode: email content not scanned.",
          "WAM checks only basic page safety on webmail sites."
        )]
      };
    }

    var findings = [];

    if (summary.has_password_field && !summary.is_https) {
      findings.push(finding(
        "insecure_password_field", "danger",
        "This page asks for a password over an insecure (HTTP) connection.",
        "Do not enter your password. Look for 'https' and a lock icon."
      ));
    }

    if (summary.has_password_field && summary.form_posts_cross_origin) {
      findings.push(finding(
        "cross_origin_login_form", "danger",
        "This login form sends your details to a different website.",
        "Check the real address of the site before signing in."
      ));
    } else if (summary.form_posts_cross_origin) {
      findings.push(finding(
        "cross_origin_form", "warning",
        "A form on this page submits to a different website.",
        "Make sure you trust where this form is sending information."
      ));
    }

    if (!summary.is_https && !summary.has_password_field) {
      findings.push(finding(
        "insecure_page", "warning",
        "This page is not using a secure (HTTPS) connection.",
        "Avoid entering personal information on insecure pages."
      ));
    }

    if (summary.has_risky_download_link) {
      findings.push(finding(
        "risky_download_link", "warning",
        "This page links to a download that could be unsafe (an app or script file).",
        "Only download and open files from sources you trust."
      ));
    }

    if (summary.has_qr_landing_signal && summary.has_password_field) {
      findings.push(finding(
        "qr_landing_login", "warning",
        "You may have reached this login page from a QR code.",
        "QR codes can hide the real address. Check the site name before signing in."
      ));
    } else if (summary.has_qr_landing_signal) {
      findings.push(finding(
        "qr_landing", "info",
        "This page may have been opened from a QR code.",
        "Check that the web address is the one you expected."
      ));
    }

    if (findings.length) {
      return { level: overallLevel(findings), findings: findings, needsAi: false };
    }

    if (summary.event_type === "login_form") {
      return {
        level: "unclear",
        needsAi: true,
        findings: [finding(
          "login_form_detected", "info",
          "A login form was detected and passed local checks.",
          "Confirm the website address matches the service you expect."
        )]
      };
    }

    return { level: "safe", findings: [], needsAi: false };
  }

  root.WamLocal = {
    PROTECTED_EMAIL_HOSTS: PROTECTED_EMAIL_HOSTS,
    isProtectedEmailHost: isProtectedEmailHost,
    buildSafeSummary: buildSafeSummary,
    analyzeLocal: analyzeLocal
  };
})(typeof self !== "undefined" ? self : this);
