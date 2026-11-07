/* global Office, MailGuard */
"use strict";

Office.onReady(function (info) {
  if (info.host !== Office.HostType.Outlook) {
    show("<p>MailGuard runs inside Outlook.</p>");
    return;
  }
  document.getElementById("rescan").addEventListener("click", scan);
  // Re-scan when the user selects another email while the pane is pinned.
  if (Office.context.requirements.isSetSupported("Mailbox", "1.5")) {
    Office.context.mailbox.addHandlerAsync(Office.EventType.ItemChanged, scan);
  }
  scan();
});

function show(html) {
  document.getElementById("result").innerHTML = html;
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

function getAsync(fn) {
  return new Promise(function (resolve) {
    try {
      fn(function (res) {
        resolve(res.status === Office.AsyncResultStatus.Succeeded ? res.value : "");
      });
    } catch (e) {
      resolve("");
    }
  });
}

async function scan() {
  const item = Office.context.mailbox.item;
  if (!item) {
    show('<p class="muted">Open an email to scan it.</p>');
    return;
  }
  show('<p class="muted">Scanning…</p>');

  const [bodyHtml, headers] = await Promise.all([
    getAsync(function (cb) { item.body.getAsync(Office.CoercionType.Html, cb); }),
    Office.context.requirements.isSetSupported("Mailbox", "1.8")
      ? getAsync(function (cb) { item.getAllInternetHeadersAsync(cb); })
      : Promise.resolve("")
  ]);

  const replyToHeader = (/^reply-to:\s*(.*)$/im.exec((headers || "").replace(/\r?\n[ \t]+/g, " ")) || [])[1] || "";
  const replyTo = (replyToHeader.match(/[^\s<>",;]+@[^\s<>",;]+/g) || []).map(function (s) { return s.toLowerCase(); });

  const from = item.from || {};
  const sender = item.sender || {};
  const userEmail = (Office.context.mailbox.userProfile && Office.context.mailbox.userProfile.emailAddress) || "";

  const result = MailGuard.analyze({
    fromName: from.displayName,
    fromEmail: from.emailAddress,
    senderEmail: sender.emailAddress !== from.emailAddress ? sender.emailAddress : "",
    replyTo: replyTo,
    subject: item.subject,
    bodyHtml: bodyHtml,
    attachments: (item.attachments || []).map(function (a) { return { name: a.name, size: a.size }; }),
    headers: headers,
    userDomain: MailGuard.domainOf(userEmail)
  });

  render(result, from);
}

function render(r, from) {
  const labels = {
    safe: ["No obvious red flags", "Still be careful with links and attachments you didn't expect."],
    caution: ["Be careful", "This email has some warning signs. Check the sender before you click or reply."],
    danger: ["Likely phishing", "Don't click links, open attachments or reply. Report it or delete it."]
  };
  const l = labels[r.level];
  const icons = { high: "⛔", medium: "⚠️", low: "•", info: "ℹ️", ok: "✅" };

  let html =
    '<div class="verdict ' + r.level + '">' +
    '<div class="score">' + r.score + '<span>/100</span></div>' +
    "<div><strong>" + l[0] + "</strong><p>" + l[1] + "</p></div></div>" +
    '<p class="from">From: <strong>' + esc(from.displayName) + "</strong> &lt;" + esc(from.emailAddress) + "&gt;</p>";

  if (r.findings.length) {
    html += '<ul class="findings">';
    r.findings.forEach(function (f) {
      html += '<li class="' + f.severity + '"><span class="ic">' + icons[f.severity] + "</span><div><strong>" +
        esc(f.title) + "</strong><small>" + esc(f.detail) + "</small></div></li>";
    });
    html += "</ul>";
  }
  html += '<p class="muted">Checked ' + r.linkCount + " link(s). Everything is analysed on your device; nothing is sent anywhere.</p>";
  show(html);
}
