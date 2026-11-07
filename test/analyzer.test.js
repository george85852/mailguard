// Run with: node --test test/*.test.js
const test = require("node:test");
const assert = require("node:assert");
const MG = require("../src/analyzer.js");

const goodHeaders =
  "Authentication-Results: mx.example.net;\r\n spf=pass smtp.mailfrom=paypal.com;\r\n dkim=pass header.d=paypal.com;\r\n dmarc=pass header.from=paypal.com\r\n" +
  "Return-Path: <bounce@paypal.com>\r\n";

test("legit email is safe", () => {
  const r = MG.analyze({
    fromName: "PayPal", fromEmail: "service@paypal.com", subject: "Your receipt",
    bodyHtml: '<p>Thanks.</p><a href="https://www.paypal.com/activity">View activity</a>',
    headers: goodHeaders, attachments: []
  });
  assert.strictEqual(r.level, "safe");
  assert.ok(r.findings.some((f) => f.severity === "ok"));
});

test("classic phishing is danger", () => {
  const r = MG.analyze({
    fromName: "PayPal Security", fromEmail: "alert@paypa1-secure.xyz",
    replyTo: ["collect@gmail.com"],
    subject: "Urgent action required: account suspended",
    bodyHtml: '<p>Unusual sign-in detected. Verify your account within 24 hours.</p>' +
      '<a href="http://192.168.4.20/login">https://www.paypal.com/signin</a>',
    headers: "Authentication-Results: mx; spf=fail; dkim=none; dmarc=fail\r\n",
    attachments: [{ name: "invoice.pdf.exe" }]
  });
  assert.strictEqual(r.level, "danger");
  const titles = r.findings.map((f) => f.title);
  ["DMARC failed", "Possible brand impersonation", "Replies go to a different domain",
   "Link text hides the real destination", "Link points to a raw IP address",
   "Risky attachment type", "Double file extension", "Urgent or threatening language"]
    .forEach((t) => assert.ok(titles.includes(t), "missing: " + t));
});

test("display name containing another address", () => {
  const r = MG.analyze({ fromName: "ceo@mycompany.com", fromEmail: "x@evil.top" });
  assert.ok(r.findings.some((f) => f.title === "Display name contains a different address"));
});

test("parseAuthResults prefers the receiver's own verdict over ARC", () => {
  const h = "ARC-Authentication-Results: i=1; spf=fail\r\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n";
  assert.deepStrictEqual(MG.parseAuthResults(h), { spf: "pass", dkim: "pass", dmarc: "pass" });
});

test("baseDomain handles subdomains and co.uk", () => {
  assert.strictEqual(MG.baseDomain("mail.accounts.google.com"), "google.com");
  assert.strictEqual(MG.baseDomain("www.amazon.co.uk"), "amazon.co.uk");
});
