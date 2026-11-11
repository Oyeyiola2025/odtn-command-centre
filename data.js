/*
 * ODTN CyberDefence – scenario content.
 * All organisations, people, hostnames and IP addresses are FICTIONAL.
 * IPs use RFC 5737 documentation ranges and domains use the reserved
 * ".example" TLD so nothing here points at a real system.
 * This file contains no secrets, keys or credentials, and must never.
 */
'use strict';

const ODTN = Object.freeze({
  scenario: {
    title: 'Operation Defend the North – Ontario Supply-Chain Attack',
    org: 'Maple Ledger Payments',
    vendor: 'TillWorks Software',
    summary:
      'Four days before Christmas, a compromised software update from TillWorks Software – the point-of-sale ' +
      'middleware vendor used by Maple Ledger Payments – starts breaking card payments across Ontario. ' +
      'Retailers, pharmacies, transit fare gates and provincial service counters are failing transactions, ' +
      'customers are angry, and the vendor insists the problem is on your network.'
  },

  roles: [
    { id: 'ic', name: 'Incident Commander', objective: 'Coordinate the response, set priorities, and keep technical, legal, communications and executive teams moving in the same direction.' },
    { id: 'soc', name: 'SOC Analyst', objective: 'Separate real indicators of compromise from noise in the logs, scope the intrusion, and feed accurate evidence to decision-makers.' },
    { id: 'exec', name: 'Executive Advisor', objective: 'Protect critical services and public trust, meet legal and regulatory obligations, and make timely decisions with incomplete information.' }
  ],

  sectors: [
    { name: 'Retail', status: 'Degraded', level: 'warn', detail: '2,960 merchants reporting intermittent card declines during peak holiday shopping.' },
    { name: 'Pharmacies', status: 'Critical', level: 'crit', detail: '412 pharmacies cannot process prescription payments. Patients leaving without medication.' },
    { name: 'Transit', status: 'Degraded', level: 'warn', detail: 'Fare-gate card readers failing at 38 stations; gates set to open to avoid crowding.' },
    { name: 'Government services', status: 'Outage', level: 'crit', detail: 'Provincial service counters have switched to cash-only. Licence and permit renewals delayed.' }
  ],

  initialAlerts: [
    { sev: 'critical', src: 'Payment Gateway', msg: 'Transaction signature (MAC) failures at 61% – baseline is under 0.5%.', detail: 'Failures are concentrated on terminals running TillWorks agent v4.2.1.' },
    { sev: 'high', src: 'EDR', msg: 'tillagent.exe spawned encoded PowerShell on POS-PHX-0193.', detail: 'Payment middleware should never launch a script interpreter. Likely malicious code in the update.' },
    { sev: 'high', src: 'Firewall', msg: 'Periodic outbound HTTPS to tw-telemetry-cdn.example from 2,914 terminals.', detail: 'Connections every 300 seconds – a classic command-and-control "beacon" pattern.' },
    { sev: 'medium', src: 'Contact Centre', msg: 'Call volume is 9x normal. Average wait time 47 minutes.', detail: 'Top call reasons: "card declined", "is my data stolen?", "when will it be fixed?"' }
  ],

  alertPool: [
    { sev: 'medium', src: 'Social Media', msg: 'Trending post claims "all Ontario card data has been stolen".', detail: 'Unverified. No evidence of card-data exfiltration yet. Rumours spread faster than facts.' },
    { sev: 'high', src: 'Vendor Liaison', msg: 'TillWorks states the outage is "a network issue at the processor".', detail: 'Conflicts with your EDR and gateway evidence. Treat vendor statements as one input, not the answer.' },
    { sev: 'critical', src: 'Merchant Portal', msg: 'svc-tillworks API token used from unfamiliar IP 203.0.113.47.', detail: 'The vendor service account is reading your merchant terminal list. Possible attacker access to your environment.' },
    { sev: 'medium', src: 'Media Relations', msg: 'Reporter requesting comment within 30 minutes.', detail: 'Any statement must be accurate, coordinated with legal, and avoid speculation.' },
    { sev: 'high', src: 'EDR', msg: 'Unsigned DLL tw_sync.dll written to TillWorks cache folder on 1,180 hosts.', detail: 'Persistence mechanism – rolling back the agent alone may not remove it.' },
    { sev: 'low', src: 'WAF', msg: 'Blocked automated SQL-injection scan against public website.', detail: 'Internet background noise. Unrelated to this incident – but still logged and reviewed.' },
    { sev: 'critical', src: 'Executive Office', msg: 'Ransom demand e-mailed to TillWorks: 400 BTC to "restore payments".', detail: 'Paying does not guarantee recovery. Engage legal, insurers and law enforcement.' },
    { sev: 'medium', src: 'HR / Wellbeing', msg: 'SOC night shift has been on duty 19 hours straight.', detail: 'Fatigue causes mistakes. ODTN lessons learned: plan rotations and clear handovers.' }
  ],

  timeline: [
    { id: 't1', when: 'Dec 19 · 02:14', cat: 'technical', title: 'Attacker logs into vendor build server', body: 'A TillWorks developer account (dev.build02) signs in from 203.0.113.47 using a legacy login that skipped multi-factor authentication. The credentials were likely phished.', lesson: 'Vendor security is your security. Assess suppliers and require MFA on anything that can ship code to you.' },
    { id: 't2', when: 'Dec 19 · 23:40', cat: 'technical', title: 'Malicious update v4.2.1 is signed and published', body: 'The attacker uses the vendor\u2019s own code-signing process outside the normal release window. Because the update is properly signed, terminals trust it.', lesson: 'A valid signature proves who signed it – not that it is safe.' },
    { id: 't3', when: 'Dec 20 · 06:00', cat: 'technical', title: 'Auto-update reaches 61% of terminals', body: 'Maple Ledger\u2019s merchants have auto-update enabled. Within hours the update spreads across retail, pharmacy, transit and government terminals.', lesson: 'Staged roll-outs and canary groups limit the blast radius of a bad update.' },
    { id: 't4', when: 'Dec 21 · 08:12', cat: 'business', title: 'Pharmacies report payment failures', body: 'Morning opening reveals mass declines. Pharmacies are hit first because of early opening hours and prescription pick-ups.', lesson: 'Know your "crown jewels" and most critical customers before an incident.' },
    { id: 't5', when: 'Dec 21 · 09:30', cat: 'comms', title: 'Customer complaints flood in', body: 'Contact-centre volume jumps 9x. Social media fills with screenshots of declined cards and claims of a data breach.', lesson: 'Prepare holding statements and call-centre scripts in advance.' },
    { id: 't6', when: 'Dec 21 · 10:05', cat: 'technical', title: 'SOC detects beaconing', body: 'Firewall analytics show thousands of terminals contacting tw-telemetry-cdn.example every 300 seconds. EDR flags tillagent.exe running encoded PowerShell.', lesson: 'Detection is not enough – containment must follow quickly.' },
    { id: 't7', when: 'Dec 21 · 11:20', cat: 'comms', title: 'Vendor blames the processor', body: 'TillWorks publicly states the outage is "a network issue at the processor". Your evidence says otherwise.', lesson: 'Conflicting information is normal. Base decisions and statements on verified evidence.' },
    { id: 't8', when: 'Dec 21 · 13:00', cat: 'business', title: 'Government counters go cash-only', body: 'Provincial service counters suspend card payments. The incident is now a public-sector issue with political attention.', lesson: 'Cross-sector incidents need public-private coordination and information sharing.' },
    { id: 't9', when: 'Dec 21 · 15:00', cat: 'technical', title: 'Ransom demand received', body: 'An extortion e-mail to TillWorks demands 400 BTC to "restore payments". Attackers claim to hold merchant data.', lesson: 'Involve legal counsel, insurers and law enforcement early. Claims of data theft must be verified.' },
    { id: 't10', when: 'Dec 22 · 02:00', cat: 'comms', title: 'Responders hit fatigue limits', body: 'Key staff have been awake for 20+ hours. Handovers are informal and decisions are being revisited.', lesson: 'Human factors matter: rotations, psychological safety and clear handovers.' }
  ],

  logs: [
    { id: 'L01', ts: 'Dec 19 02:14:07', src: 'Vendor Build (shared)', msg: 'LOGIN OK user=dev.build02 src=203.0.113.47 method=legacy-basic mfa=not_enforced', ioc: true, why: 'Developer login from a never-before-seen IP using a legacy method that bypasses MFA. This is the initial access point.' },
    { id: 'L02', ts: 'Dec 19 03:00:00', src: 'Backup', msg: 'Nightly backup job merchant-db completed status=success size=412GB', ioc: false, why: 'Routine scheduled backup. Normal.' },
    { id: 'L03', ts: 'Dec 19 23:40:51', src: 'Vendor Build (shared)', msg: 'CODESIGN build=tillagent-4.2.1 signer=dev.build02 window=OUTSIDE_RELEASE ticket=none', ioc: true, why: 'Code signed outside the release window with no change ticket, by the same compromised account. This is how the malicious update got trusted.' },
    { id: 'L04', ts: 'Dec 20 05:58:12', src: 'Update Service', msg: 'Health check tillagent-4.2.0 channel=stable result=OK', ioc: false, why: 'Health check for the previous, legitimate version. Normal.' },
    { id: 'L05', ts: 'Dec 20 09:14:33', src: 'Firewall', msg: 'ALLOW tcp/443 pos-fleet -> api.mapleledger.example (gateway)', ioc: false, why: 'Terminals talking to your own payment gateway. Expected traffic.' },
    { id: 'L06', ts: 'Dec 21 07:51:02', src: 'EDR', msg: 'PROCESS tillagent.exe -> powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC... host=POS-PHX-0193', ioc: true, why: 'Payment middleware launching hidden (encoded) PowerShell is a strong sign of malicious code execution.' },
    { id: 'L07', ts: 'Dec 21 08:00:00', src: 'Firewall', msg: 'ALLOW tcp/443 2,914 hosts -> tw-telemetry-cdn.example (198.51.100.23) interval=300s', ioc: true, why: 'Thousands of terminals calling the same unknown domain on a fixed timer = command-and-control beaconing.' },
    { id: 'L08', ts: 'Dec 21 08:03:41', src: 'Payment Gateway', msg: 'DECLINE code=51 insufficient_funds card=****4421 merchant=M-20931', ioc: false, why: 'A normal decline for insufficient funds. Happens every day.' },
    { id: 'L09', ts: 'Dec 21 08:12:19', src: 'Payment Gateway', msg: 'ALERT mac_verification_failed rate=61.2% (baseline 0.4%) agent=4.2.1', ioc: true, why: 'Massive spike in transaction-signature failures tied specifically to version 4.2.1. This is the business impact of the malicious update.' },
    { id: 'L10', ts: 'Dec 21 08:20:05', src: 'Identity', msg: 'Password reset user=j.patel via helpdesk ticket INC-88412 verified=callback', ioc: false, why: 'Routine helpdesk reset with a verified call-back. Normal.' },
    { id: 'L11', ts: 'Dec 21 09:02:44', src: 'Merchant Portal', msg: 'API GET /v2/terminals?all=true token=svc-tillworks src=203.0.113.47', ioc: true, why: 'The vendor service account is used from the same attacker IP as L01 – the attacker has pivoted into your environment.' },
    { id: 'L12', ts: 'Dec 21 09:15:10', src: 'DNS', msg: 'QUERY os-updates.example A -> 192.0.2.10 host=WS-FIN-022', ioc: false, why: 'Operating-system update check from a workstation. Normal.' },
    { id: 'L13', ts: 'Dec 21 09:40:00', src: 'Monitoring', msg: 'WARN db-replica-2 cpu=91% (holiday peak volume)', ioc: false, why: 'High load from holiday shopping and retries. A symptom of the outage, not an indicator of compromise.' },
    { id: 'L14', ts: 'Dec 21 10:00:00', src: 'Vuln Scanner', msg: 'Scheduled internal scan started profile=weekly-pci', ioc: false, why: 'Your own scheduled vulnerability scan. Normal.' },
    { id: 'L15', ts: 'Dec 21 10:11:37', src: 'EDR', msg: 'FILE_CREATE C:\\ProgramData\\TillWorks\\cache\\tw_sync.dll signed=false hosts=1180', ioc: true, why: 'An unsigned DLL dropped across many hosts – a persistence mechanism. Rolling back the agent alone will not remove it.' },
    { id: 'L16', ts: 'Dec 21 10:30:22', src: 'VPN', msg: 'LOGIN OK user=oncall.netops src=known-device mfa=passed', ioc: false, why: 'Your on-call engineer connecting from a known device with MFA. Normal.' },
    { id: 'L17', ts: 'Dec 21 11:05:09', src: 'WAF', msg: 'BLOCK sqli-scan src=192.0.2.200 path=/search?q=1%27%20OR%201=1', ioc: false, why: 'Internet background noise that was blocked. Real, but not part of this incident – a distraction.' },
    { id: 'L18', ts: 'Dec 21 11:45:30', src: 'Backup', msg: 'Restore test merchant-db snapshot=Dec18 result=PASS', ioc: false, why: 'Good news: you have a clean backup from before the compromise.' }
  ],

  // Metrics: containment, continuity (critical services), trust (public), compliance (legal/regulatory)
  modules: [
    {
      id: 'm1', tag: 'Module 1 · Technical evidence',
      situation: 'EDR and firewall data show terminals running TillWorks v4.2.1 are executing hidden scripts and beaconing to tw-telemetry-cdn.example. Payments are failing province-wide. What is your first move?',
      options: [
        { text: 'Block the beacon domain at the perimeter, suspend the vendor auto-update channel, and preserve forensic images of a sample of affected terminals.', fx: { containment: 20, continuity: 5, trust: 5, compliance: 10 }, best: true, feedback: 'Strong. You cut off attacker control and stopped further spread while keeping evidence for investigation, insurers and law enforcement.' },
        { text: 'Shut down ALL payment processing across Ontario immediately until the investigation is finished.', fx: { containment: 15, continuity: -25, trust: -10, compliance: 0 }, feedback: 'Contains the threat but causes maximum disruption to pharmacies and government services days before Christmas. Containment should be targeted.' },
        { text: 'Wait for TillWorks to confirm the problem before taking any action.', fx: { containment: -20, continuity: -10, trust: -5, compliance: -5 }, feedback: 'The attacker keeps control while you wait. Your own evidence is enough to act – detection without containment is the core ODTN lesson.' },
        { text: 'Push a remote rollback to every terminal right now and wipe the cache folders.', fx: { containment: 5, continuity: 5, trust: 0, compliance: -15 }, feedback: 'Fast, but you destroy evidence and the unsigned DLL persistence may survive. Scope the compromise before recovery.' }
      ]
    },
    {
      id: 'm2', tag: 'Module 2 · System logs',
      situation: 'Logs show the svc-tillworks API token – a vendor service account with access to your merchant portal – being used from the same IP that compromised the vendor\u2019s build server.',
      options: [
        { text: 'Disable the vendor service account, revoke its API tokens, require MFA for all third-party access, and hunt for lateral movement.', fx: { containment: 20, continuity: 0, trust: 5, compliance: 10 }, best: true, feedback: 'Correct. Third-party access is a common pivot point. Revoke, rebuild with least privilege, and check what else the attacker touched.' },
        { text: 'Delete the account and clear the portal logs so the attacker cannot use them.', fx: { containment: 5, continuity: 0, trust: -10, compliance: -25 }, feedback: 'Deleting logs destroys evidence and may breach legal and regulatory obligations. Never destroy logs during an incident.' },
        { text: 'Leave the account active for 24 hours to watch what the attacker does.', fx: { containment: -15, continuity: -5, trust: 0, compliance: -5 }, feedback: 'Monitoring an attacker can have value for mature teams, but during an active outage it gives them time to cause more harm.' },
        { text: 'Ask TillWorks to rotate the credential on their side when they have time.', fx: { containment: -10, continuity: 0, trust: 0, compliance: -5 }, feedback: 'The credential gives access to YOUR environment – you own that risk. Act directly.' }
      ]
    },
    {
      id: 'm3', tag: 'Module 3 · Customer complaints',
      situation: 'Pharmacies cannot process prescriptions, the contact centre has a 47-minute wait, and your largest retail client is threatening to leave unless they are restored first.',
      options: [
        { text: 'Activate business-continuity fallbacks prioritising pharmacies and government counters, and give the contact centre an approved holding script.', fx: { containment: 0, continuity: 20, trust: 15, compliance: 5 }, best: true, feedback: 'Excellent. Recovery priorities should be driven by critical services and public safety – not by who pays most. Scripts keep messages consistent.' },
        { text: 'Restore the largest retail client first – they generate the most revenue.', fx: { containment: 0, continuity: -10, trust: -10, compliance: -5 }, feedback: 'Letting one client dictate priorities was a specific ODTN lesson. Patients without medication is a higher-impact harm.' },
        { text: 'Tell callers it is a "minor technical glitch" that will be fixed soon.', fx: { containment: 0, continuity: 0, trust: -20, compliance: -5 }, feedback: 'Minimising a cyber incident damages trust badly once the truth emerges.' },
        { text: 'Stop answering calls until the investigation is complete.', fx: { containment: 0, continuity: -10, trust: -20, compliance: 0 }, feedback: 'Silence fuels rumours. Customers need to know what is happening and what to do.' }
      ]
    },
    {
      id: 'm4', tag: 'Module 4 · Conflicting information',
      situation: 'The vendor says it is your network. Social media claims all card data was stolen. A reporter wants comment in 30 minutes. You have NOT confirmed any data theft.',
      options: [
        { text: 'Issue a short, evidence-based statement: what you know, what you don\u2019t yet, what customers should do, and when the next update is. Coordinate with legal and the vendor.', fx: { containment: 0, continuity: 5, trust: 20, compliance: 10 }, best: true, feedback: 'This is the model. Transparent, accurate and coordinated – without speculation. Commit to a regular update cadence.' },
        { text: 'Confirm a data breach to the reporter so you look transparent.', fx: { containment: 0, continuity: 0, trust: -10, compliance: -15 }, feedback: 'Premature. Confirming unverified facts can cause panic, legal exposure and later corrections that erode trust.' },
        { text: 'Firmly deny that any data was or could have been taken.', fx: { containment: 0, continuity: 0, trust: -15, compliance: -10 }, feedback: 'You don\u2019t know that yet. Categorical denials that turn out wrong are very damaging.' },
        { text: 'Publicly blame TillWorks for the whole incident.', fx: { containment: -5, continuity: -5, trust: -5, compliance: -5 }, feedback: 'Public blame breaks the partnership you need for recovery. Shared responsibility, coordinated messaging.' }
      ]
    },
    {
      id: 'm5', tag: 'Module 5 · Internal communication & governance',
      situation: 'It is hour 20. Staff are exhausted, executives want constant updates, the ransom deadline is approaching, and nobody is sure who has final authority.',
      options: [
        { text: 'Formally appoint an incident commander, set a fixed briefing cadence, start shift rotations with written handovers, engage legal/privacy on notification duties, and share indicators with the Canadian Centre for Cyber Security.', fx: { containment: 10, continuity: 10, trust: 10, compliance: 20 }, best: true, feedback: 'This reflects every major ODTN lesson: clear authority, human factors, legal obligations and cross-sector information sharing.' },
        { text: 'Have the CEO personally run every decision to show leadership.', fx: { containment: -5, continuity: -5, trust: 0, compliance: 0 }, feedback: 'Executives set direction and approve major decisions; an incident commander runs the response. Bottlenecks slow everything down.' },
        { text: 'Keep the current team working until it\u2019s over – changing people now loses context.', fx: { containment: -10, continuity: -5, trust: 0, compliance: -5 }, feedback: 'Exhausted responders make mistakes. Rotations with clear handovers preserve context and people.' },
        { text: 'Quietly pay the ransom to make the problem go away before Christmas.', fx: { containment: -5, continuity: 0, trust: -15, compliance: -20 }, feedback: 'Payment gives no guarantee of recovery, may break sanctions and legal rules, and funds future attacks. Decisions like this need legal, insurer and law-enforcement input.' }
      ]
    }
  ],

  recoverySteps: [
    { id: 'r1', text: 'Confirm containment and full scope of compromise (including persistence like tw_sync.dll)' },
    { id: 'r2', text: 'Obtain a verified clean release (v4.2.2) re-signed with a NEW code-signing certificate' },
    { id: 'r3', text: 'Rebuild affected terminals from a known-good image' },
    { id: 'r4', text: 'Restore critical services first: pharmacies and government counters' },
    { id: 'r5', text: 'Phase in retail and transit with enhanced monitoring' },
    { id: 'r6', text: 'Complete regulatory and affected-party notifications as advised by legal' },
    { id: 'r7', text: 'Hold a blameless post-incident review and update plans, vendor contracts and playbooks' }
  ],
  // The order the steps are displayed in (deliberately shuffled)
  recoveryDisplayOrder: ['r4', 'r7', 'r2', 'r6', 'r1', 'r5', 'r3'],

  quiz: [
    { q: 'In the ODTN Ontario exercise, which of these was part of the five exercise modules?', options: ['Penetration testing of the vendor', 'Conflicting information and internal communication challenges', 'Hardware procurement', 'Cryptocurrency tracing'], answer: 1, explain: 'The five modules used technical evidence, system logs, customer complaints, conflicting information and internal communication challenges.' },
    { q: 'According to the ODTN lessons on proactive defence, detecting a threat is insufficient without…', options: ['A press release', 'Rapid containment and scoping of lateral movement', 'Buying new firewalls', 'Waiting for vendor confirmation'], answer: 1, explain: 'Organisations must contain quickly and investigate the full scope of compromise before recovery.' },
    { q: 'Why should a single large client not dictate recovery priorities?', options: ['They may not pay on time', 'Priorities should follow critical services, safety and legal/service obligations', 'Large clients have their own IT teams', 'It is illegal to talk to clients during an incident'], answer: 1, explain: 'ODTN participants advised against letting individual clients dictate recovery – critical services and obligations come first.' },
    { q: 'Which is a recommended third-party (vendor) security practice from ODTN?', options: ['Give vendors permanent admin access for convenience', 'Assess vendors, monitor supplier access continuously, and terminate access securely', 'Trust any signed update automatically', 'Let vendors manage your incident response'], answer: 1, explain: 'Vendor assessments, continuous monitoring of supplier access, strong contracts and secure termination were all recommended.' },
    { q: 'Which human-factors practice did ODTN lessons-learned sessions emphasise?', options: ['Keep the same team on until the incident ends', 'Staff rotations, clear handovers and psychological safety', 'Only executives should be informed', 'Avoid post-incident reviews'], answer: 1, explain: 'Effective response depends on the wellbeing of the people managing the incident.' },
    { q: 'Which Ontario law was highlighted at the ODTN kickoff as a framework for public-sector cybersecurity?', options: ['Strengthening Cybersecurity and Building Trust in the Public Sector Act, 2024', 'Ontario Digital Payments Act, 2019', 'Cyber Defence of the North Act, 2023', 'Retail Security Standards Act, 2021'], answer: 0, explain: 'The Act establishes cybersecurity requirements for applicable public-sector organisations.' }
  ],

  lessons: [
    'Cybersecurity is a shared responsibility – public and private sectors must collaborate and share information.',
    'Detection without rapid containment leaves the attacker in control.',
    'Appoint an incident commander and make decision authority clear before you need it.',
    'Your vendors\u2019 security is part of your security: assess, monitor and contractually protect supplier access.',
    'Prioritise recovery by critical services and public safety, not by who shouts loudest.',
    'Communicate early, accurately and regularly – say what you know, what you don\u2019t, and when you\u2019ll update.',
    'People are your most important control: plan rotations, handovers and post-incident support.',
    'Identify your "crown jewels" and test business-continuity and recovery plans before an incident.'
  ]
});
