# MailGuard

An Outlook add-in that checks the email you're reading for phishing warning signs and gives it a 0–100 risk score.

**What it checks**
- **Sender authentication:** SPF, DKIM and DMARC results from your mail server
- **Spoofed senders:** brand names on look-alike domains, a display name that contains a different address, official-sounding names on free email accounts, punycode look-alike domains
- **Reply-To / Return-Path** pointing to a different domain
- **Links:** text that shows one site but opens another, raw IP addresses, URL shorteners, high-risk domain endings, unencrypted login pages, the `user@host` trick
- **Attachments:** executable or script files, HTML attachments, double extensions (`invoice.pdf.exe`), archives
- **Pressure language:** "account suspended", "verify within 24 hours", gift cards, changed bank details

Everything runs inside Outlook on your device. MailGuard never sends your email anywhere.

## How it's hosted

Outlook add-ins load their files from a web address over HTTPS. This repo is served for free by **GitHub Pages** at
`https://george85852.github.io/mailguard/`, and `manifest.xml` points there.

### One-time: turn on GitHub Pages
1. Go to **github.com/george85852/mailguard → Settings → Pages**.
2. Under **Build and deployment**, set **Source** to *Deploy from a branch*.
3. Pick the branch that has this code (`main` once merged) and the **/ (root)** folder, then **Save**.
4. After a minute or two, open https://george85852.github.io/mailguard/src/taskpane.html. You should see the MailGuard page, saying "Loading…".

## Install in Outlook

Sideloading (installing your own add-in) needs a computer browser. The Outlook phone app can't install add-ins itself, but it picks up the ones on your account.

**Outlook on the web / new Outlook for Windows (personal Outlook.com or work account):**
1. Download `manifest.xml` from this repo (open it on GitHub → **Download raw file**).
2. In a browser, go to **https://aka.ms/olksideload**. This opens Outlook with the **Add-ins for Outlook** window.
3. Choose **My add-ins** → scroll to **Custom Addins** → **Add a custom add-in** → **Add from File…** → pick `manifest.xml` → **Install**.

**Classic Outlook for Windows / Mac:** add-ins installed on the web sync automatically. Otherwise use **File → Manage Add-ins** (Windows) or **Get Add-ins** (Mac), which take you to the same page.

**Use it:** open any email and click **Scan email** (MailGuard) in the toolbar. On the web it may sit under the **Apps** button or the **…** menu. Click it again on each email you want to check.

**Outlook on your phone (Android / iPhone):** nothing extra to install. Once the add-in is on your account (steps above), open the Outlook app, open an email, tap the **…** (More) button at the top of the message, then tap **MailGuard / Scan email**. It can take a few minutes, or a restart of the app, to appear the first time. Add-ins on mobile work with Outlook.com and Microsoft 365 accounts (not Gmail/other accounts added to the app). Some mobile versions don't let add-ins read email headers; MailGuard then skips the SPF/DKIM/DMARC check and says so.

> Work/school accounts: your IT admin may have disabled custom add-ins. If **Add a custom add-in** is missing, ask them, or they can deploy `manifest.xml` for you from the Microsoft 365 admin center.

## Updating
Push changes to the Pages branch. Outlook picks up the new HTML/JS automatically. Only reinstall the manifest if you change `manifest.xml` itself (also bump its `<Version>`).

## Development
```
node --test test/*.test.js     # analyzer unit tests (Node 18+)
```
- `src/analyzer.js`: all detection rules (pure JS, no dependencies)
- `src/taskpane.*`: the panel UI, which reads the open email through Office.js
- `manifest.xml`: tells Outlook where the add-in lives and adds the toolbar button

If you fork this or host it somewhere else, replace `https://george85852.github.io/mailguard` everywhere in `manifest.xml`.
