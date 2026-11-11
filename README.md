# ODTN CyberDefence – Incident Response Command Centre

An interactive incident-response simulator based on the **Operation Defend the North (ODTN) Ontario supply-chain cyberattack** scenario.

## Submission summary

**Scenario chosen:** ODTN Ontario kickoff. A hypothetical supply-chain cyberattack shortly before Christmas causes widespread payment-processing failures across retailers, pharmacies, transportation and government organisations. The exercise's five modules (technical evidence, system logs, customer complaints, conflicting information, internal communication) become the five rounds of the decision simulator. Lessons are also drawn from the Vancouver, Ottawa and Calgary ODTN sessions.

**Intended audience:** Cybersecurity students, junior SOC analysts and non-technical managers who need to experience a cross-sector cyber incident and practise the decisions it demands.

**Purpose:** To let users *do* incident response rather than read about it. They separate real indicators of compromise from noise, make trade-off decisions under pressure, plan a safe recovery, and leave with an after-action report and the key ODTN lessons.

**Tools and frameworks:** Plain HTML, CSS and JavaScript (no frameworks, libraries or third-party scripts). Built with AI assistance (Claude), with the generated code reviewed and tested against the security checklist below.

## Sections (6 views)

| # | View | Interaction |
|---|------|-------------|
| 01 | Executive dashboard | Role selection, live alert feed with fake alerts (pause/expand), sector impact, KPIs that react to your progress, mission checklist |
| 02 | Incident timeline | Expandable events with evidence and lessons, category filters |
| 03 | Investigation centre | Search/filter 18 log lines, flag IOCs, get a scored result with explanations |
| 04 | Decision simulator | 5 modules × 4 options, four live metrics, feedback on every choice |
| 05 | Recovery & lessons learned | Build the recovery sequence, 6-question quiz, generate a printable after-action report |
| i | About & security | Scenario, audience, purpose, security design, known limitations |

## Security design

- **No secrets:** there are no API keys, tokens or credentials anywhere in the code.
- **No backend or data collection:** nothing the user types leaves the browser. No cookies, no analytics, no network requests (`connect-src 'none'`).
- **Strict Content-Security-Policy:** only same-origin scripts and styles may load. Inline scripts, `eval`, plugins and framing are all blocked. The policy is sent as an HTTP header (`_headers` for Netlify, `vercel.json` for Vercel), with a `<meta>` fallback for hosts that can't send headers.
- **XSS-safe rendering:** no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` or `eval`. All dynamic text is set through `textContent`, and the `el()` helper refuses `on*` and `style` attributes.
- **Input validation:** the report name uses a Unicode allow-list regex with a 40-character limit. Log search is capped at 60 characters, rejects control characters, and uses plain substring matching (no user-supplied regex, so no ReDoS). The router only accepts view names from an allow-list.
- **Untrusted storage:** progress lives in `sessionStorage` and is re-validated field by field on load. Tampered values are discarded (tested).
- **Hardened headers:** HSTS, `nosniff`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and COOP/CORP.
- **Safe fictional indicators:** IPs come from the RFC 5737 documentation ranges and domains use `.example`.
- **No fake authentication:** roles are a selection, not a login. Adding passwords to a site with nothing to protect would only add attack surface.

**Known limitation:** scoring runs client-side, so users can alter their own score in DevTools. That's acceptable for a no-stakes training tool. A graded version would need server-side scoring.

## Run locally

Open `index.html` in a browser. No build step is needed.

## Deploy

**Netlify (recommended, applies `_headers`):** go to app.netlify.com → *Add new site* → *Deploy manually*, and drag this folder in.

**Vercel (applies `vercel.json`):** `npx vercel` in this folder, or import a GitHub repo containing it.

**Replit / GitHub Pages:** these work, but they ignore `_headers`/`vercel.json`. Only the `<meta>` CSP applies, which can't set `frame-ancestors`, HSTS or the other headers. Netlify or Vercel gives a stronger result for the security review.
