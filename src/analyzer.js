/*
 * MailGuard analyzer: pure functions that score an email for phishing signs.
 * No network calls; everything runs locally in the add-in.
 * Works in the browser (window.MailGuard) and in Node (module.exports) for tests.
 */
(function (root) {
  "use strict";

  const RISKY_EXTENSIONS = [
    "exe", "scr", "bat", "cmd", "com", "pif", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "msi", "ps1", "jar", "lnk", "iso", "img", "vhd", "reg", "cpl",
    "docm", "xlsm", "pptm", "html", "htm", "svg", "one"
  ];
  const ARCHIVE_EXTENSIONS = ["zip", "rar", "7z", "gz", "tar", "cab"];

  const SUSPICIOUS_TLDS = [
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "rest", "cam", "monster", "support", "icu"
  ];

  const URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"
  ];

  const FREE_MAIL = [
    "gmail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
    "aol.com", "icloud.com", "proton.me", "protonmail.com", "gmx.com", "mail.com"
  ];

  // Brands often impersonated in display names.
  const BRANDS = {
    microsoft: ["microsoft.com", "office.com", "microsoftonline.com", "outlook.com", "live.com"],
    office365: ["microsoft.com", "office.com", "microsoftonline.com"],
    paypal: ["paypal.com"],
    apple: ["apple.com", "icloud.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.gr"],
    google: ["google.com", "gmail.com"],
    netflix: ["netflix.com"],
    dhl: ["dhl.com", "dhl.de"],
    fedex: ["fedex.com"],
    docusign: ["docusign.com", "docusign.net"],
    bank: []
  };

  const URGENCY_PATTERNS = [
    /verify your (account|identity|password)/i,
    /(account|mailbox) (will be )?(suspended|locked|disabled|closed|terminated)/i,
    /unusual (sign[- ]?in|login|activity)/i,
    /(update|confirm) your (payment|billing|banking) (details|information|info)/i,
    /password (expires|expired|will expire)/i,
    /within (24|48|72) hours/i,
    /(urgent|immediate) (action|attention|response)/i,
    /click (here|below) (to|and) (verify|confirm|restore|unlock|login|log in)/i,
    /gift ?cards?/i,
    /wire transfer|bank transfer|change of bank details/i,
    /you have (\d+ )?(pending|undelivered|held) (messages?|emails?|packages?)/i,
    /invoice (attached|overdue)|overdue invoice/i
  ];

  // ---------- helpers ----------

  function domainOf(email) {
    if (!email || typeof email !== "string") return "";
    const at = email.lastIndexOf("@");
    return at >= 0 ? email.slice(at + 1).trim().toLowerCase().replace(/>$/, "") : "";
  }

  // Rough "registrable domain": last two labels, or three for things like co.uk.
  function baseDomain(host) {
    if (!host) return "";
    host = host.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    const parts = host.split(".");
    if (parts.length <= 2) return host;
    const sld = parts[parts.length - 2];
    const twoLevelSuffix = ["co", "com", "org", "net", "gov", "ac", "edu"].includes(sld) &&
      parts[parts.length - 1].length === 2;
    return parts.slice(twoLevelSuffix ? -3 : -2).join(".");
  }

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch (e) {
      return "";
    }
  }

  function extOf(name) {
    const m = /\.([a-z0-9]+)$/i.exec(name || "");
    return m ? m[1].toLowerCase() : "";
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
  }

  // ---------- header checks ----------

  // Parses Authentication-Results headers for spf/dkim/dmarc verdicts.
  function parseAuthResults(headers) {
    const out = { spf: null, dkim: null, dmarc: null };
    if (!headers) return out;
    // Unfold continuation lines.
    const unfolded = headers.replace(/\r?\n[ \t]+/g, " ");
    const lines = unfolded.split(/\r?\n/).filter(function (l) {
      return /^(arc-)?authentication-results:/i.test(l);
    });
    // Prefer non-ARC (the receiving server's own verdict).
    lines.sort(function (a, b) {
      return (/^arc-/i.test(a) ? 1 : 0) - (/^arc-/i.test(b) ? 1 : 0);
    });
    lines.forEach(function (line) {
      ["spf", "dkim", "dmarc"].forEach(function (k) {
        if (out[k]) return;
        const m = new RegExp("\\b" + k + "=([a-z]+)", "i").exec(line);
        if (m) out[k] = m[1].toLowerCase();
      });
    });
    return out;
  }

  function headerValue(headers, name) {
    if (!headers) return "";
    const unfolded = headers.replace(/\r?\n[ \t]+/g, " ");
    const re = new RegExp("^" + name + ":\\s*(.*)$", "im");
    const m = re.exec(unfolded);
    return m ? m[1].trim() : "";
  }

  function extractEmail(value) {
    const m = /<([^>]+@[^>]+)>/.exec(value || "") || /([^\s<>"]+@[^\s<>"]+)/.exec(value || "");
    return m ? m[1].toLowerCase() : "";
  }

  // ---------- link extraction ----------

  // Returns [{href, text}] from an HTML body. Uses DOMParser when available.
  function extractLinks(html) {
    const links = [];
    if (!html) return links;
    if (typeof DOMParser !== "undefined") {
      const doc = new DOMParser().parseFromString(html, "text/html");
      doc.querySelectorAll("a[href]").forEach(function (a) {
        links.push({ href: a.getAttribute("href") || "", text: (a.textContent || "").trim() });
      });
      return links;
    }
    // Fallback for Node tests.
    const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = re.exec(html))) {
      links.push({ href: m[1], text: m[2].replace(/<[^>]+>/g, "").trim() });
    }
    return links;
  }

  function htmlToText(html) {
    if (!html) return "";
    if (typeof DOMParser !== "undefined") {
      return new DOMParser().parseFromString(html, "text/html").body.textContent || "";
    }
    return html.replace(/<[^>]+>/g, " ");
  }

  // ---------- main ----------

  /**
   * @param {object} msg
   *   fromName, fromEmail, senderEmail, replyTo (array of emails),
   *   subject, bodyHtml, bodyText, attachments [{name, size}], headers (raw string),
   *   userDomain (recipient's own domain, optional)
   * @returns {{score:number, level:string, findings:Array}}
   */
  function analyze(msg) {
    const findings = [];
    function add(severity, title, detail, weight) {
      findings.push({ severity: severity, title: title, detail: detail, weight: weight });
    }

    const fromEmail = (msg.fromEmail || "").toLowerCase();
    const fromDomain = domainOf(fromEmail);
    const fromBase = baseDomain(fromDomain);
    const fromName = (msg.fromName || "").trim();

    // 1. Authentication results
    const auth = parseAuthResults(msg.headers);
    if (msg.headers) {
      if (auth.dmarc === "fail") add("high", "DMARC failed", "The sender's domain did not authenticate this message. It may be spoofed.", 35);
      if (auth.spf && ["fail", "softfail"].includes(auth.spf)) add(auth.spf === "fail" ? "high" : "medium", "SPF " + auth.spf, "The sending server is not authorised to send for " + (fromDomain || "this domain") + ".", auth.spf === "fail" ? 20 : 10);
      if (auth.dkim === "fail") add("medium", "DKIM failed", "The message signature is invalid; it may have been altered.", 15);
      if (!auth.spf && !auth.dkim && !auth.dmarc) add("low", "No authentication results", "Your mail server did not record SPF/DKIM/DMARC results for this message.", 5);
      if (auth.spf === "pass" && auth.dkim === "pass" && auth.dmarc === "pass") add("ok", "SPF, DKIM and DMARC passed", "The sender's domain authenticated this message.", 0);

      const returnPath = extractEmail(headerValue(msg.headers, "Return-Path"));
      if (returnPath && fromBase && baseDomain(domainOf(returnPath)) !== fromBase && auth.dmarc !== "pass") {
        add("low", "Return-Path differs from sender", "Bounces go to " + domainOf(returnPath) + ", not " + fromDomain + ".", 5);
      }
    }

    // 2. Sender on behalf of someone else
    if (msg.senderEmail && fromEmail && baseDomain(domainOf(msg.senderEmail)) !== fromBase) {
      add("medium", "Sent on behalf of another address", "Actually sent by " + msg.senderEmail + " on behalf of " + fromEmail + ".", 10);
    }

    // 3. Display name tricks
    const nameEmail = extractEmail(fromName);
    if (nameEmail && nameEmail !== fromEmail) {
      add("high", "Display name contains a different address", "Shows \"" + nameEmail + "\" but the real address is " + fromEmail + ".", 30);
    }
    const lowerName = fromName.toLowerCase().replace(/\s+/g, "");
    Object.keys(BRANDS).forEach(function (brand) {
      if (brand === "bank") return;
      if (lowerName.includes(brand)) {
        const legit = BRANDS[brand].some(function (d) { return baseDomain(d) === fromBase; });
        if (!legit && fromDomain) {
          add("high", "Possible brand impersonation", "Name mentions \"" + brand + "\" but the address is from " + fromDomain + ".", 25);
        }
      }
    });
    if (FREE_MAIL.includes(fromBase) && /(support|security|billing|helpdesk|it ?dept|admin|service|team|bank)/i.test(fromName)) {
      add("medium", "Official-sounding name on a free email account", "\"" + fromName + "\" is using " + fromDomain + ".", 15);
    }
    if (/xn--/.test(fromDomain)) {
      add("high", "Look-alike (punycode) sender domain", fromDomain + " uses international characters that can mimic another domain.", 25);
    }

    // 4. Reply-To mismatch
    (msg.replyTo || []).forEach(function (rt) {
      const rtBase = baseDomain(domainOf(rt));
      if (rtBase && fromBase && rtBase !== fromBase) {
        add("medium", "Replies go to a different domain", "Reply-To is " + rt + " instead of " + fromDomain + ".", 15);
      }
    });

    // 5. Links
    const links = extractLinks(msg.bodyHtml);
    const seen = {};
    links.forEach(function (l) {
      const href = l.href.trim();
      if (/^(mailto|tel|cid|#)/i.test(href)) return;
      const host = hostOf(href);
      if (!host) return;
      const key = host;
      function once(id, fn) {
        if (seen[id + key]) return;
        seen[id + key] = true;
        fn();
      }
      // Visible text looks like a URL/domain different from the real target.
      const textHostMatch = /((?:[a-z0-9-]+\.)+[a-z]{2,})/i.exec(l.text);
      if (textHostMatch) {
        const shown = baseDomain(textHostMatch[1]);
        if (shown && shown !== baseDomain(host) && /\./.test(shown)) {
          once("mismatch" + shown, function () {
            add("high", "Link text hides the real destination", "Shows \"" + textHostMatch[1] + "\" but goes to " + host + ".", 25);
          });
        }
      }
      if (isIp(host)) once("ip", function () { add("high", "Link points to a raw IP address", href.slice(0, 80), 20); });
      if (URL_SHORTENERS.includes(baseDomain(host))) once("short", function () { add("low", "Shortened link", host + " hides the final destination.", 5); });
      const tld = host.split(".").pop();
      if (SUSPICIOUS_TLDS.includes(tld)) once("tld", function () { add("medium", "Link to a high-risk domain ending", host, 10); });
      if (/xn--/.test(host)) once("puny", function () { add("high", "Look-alike (punycode) link", host, 20); });
      if (/^http:\/\//i.test(href) && /login|signin|verify|account|password/i.test(href)) {
        once("http", function () { add("medium", "Unencrypted login link", host, 10); });
      }
      if (/@/.test(href.replace(/^https?:\/\//i, "").split("/")[0])) {
        once("at", function () { add("high", "Link uses a deceptive @ trick", href.slice(0, 80), 20); });
      }
    });

    // 6. Attachments
    (msg.attachments || []).forEach(function (a) {
      const ext = extOf(a.name);
      const parts = (a.name || "").toLowerCase().split(".");
      if (RISKY_EXTENSIONS.includes(ext)) {
        add("high", "Risky attachment type", a.name + " (." + ext + ") can run code or open phishing pages.", 25);
      } else if (ARCHIVE_EXTENSIONS.includes(ext)) {
        add("low", "Compressed attachment", a.name + " may hide its real contents.", 5);
      }
      if (parts.length > 2 && RISKY_EXTENSIONS.concat(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png"]).includes(parts[parts.length - 2]) && ext !== parts[parts.length - 2]) {
        add("high", "Double file extension", a.name + " disguises its real type.", 20);
      }
    });

    // 7. Pressure language
    const text = (msg.subject || "") + "\n" + (msg.bodyText || htmlToText(msg.bodyHtml));
    const hits = URGENCY_PATTERNS.filter(function (re) { return re.test(text); }).length;
    if (hits >= 2) add("medium", "Urgent or threatening language", hits + " pressure phrases found (e.g. account suspension, verify now).", 15);
    else if (hits === 1) add("low", "Some pressure language", "Contains a phrase common in phishing.", 5);

    // 8. External sender (informational)
    if (msg.userDomain && fromBase && baseDomain(msg.userDomain) !== fromBase) {
      add("info", "External sender", "This message is from outside " + msg.userDomain + ".", 0);
    }

    const score = Math.min(100, findings.reduce(function (s, f) { return s + f.weight; }, 0));
    const level = score >= 50 ? "danger" : score >= 20 ? "caution" : "safe";
    const order = { high: 0, medium: 1, low: 2, info: 3, ok: 4 };
    findings.sort(function (a, b) { return order[a.severity] - order[b.severity]; });
    return { score: score, level: level, findings: findings, auth: auth, linkCount: links.length };
  }

  const api = {
    analyze: analyze,
    parseAuthResults: parseAuthResults,
    extractLinks: extractLinks,
    baseDomain: baseDomain,
    domainOf: domainOf
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.MailGuard = api;
})(typeof self !== "undefined" ? self : this);
