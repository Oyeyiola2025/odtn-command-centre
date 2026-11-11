/*
 * ODTN CyberDefence – Incident Response Command Centre
 *
 * Security notes for reviewers:
 *  - No innerHTML / outerHTML / insertAdjacentHTML / document.write / eval anywhere.
 *    All dynamic text goes through textContent via the el() helper.
 *  - No network requests. No secrets. No third-party code.
 *  - sessionStorage is treated as untrusted input and re-validated on every load.
 *  - User input (search, name) is length-limited and validated with allow-lists.
 */
'use strict';

(function () {
  // ---------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);

  /** Safe element builder. Text is always set with textContent. */
  function el(tag, opts, children) {
    const node = document.createElement(tag);
    const o = opts || {};
    if (o.className) node.className = o.className;
    if (o.text !== undefined && o.text !== null) node.textContent = String(o.text);
    if (o.attrs) {
      Object.keys(o.attrs).forEach((k) => {
        // Never allow event-handler attributes or style attributes through this helper.
        if (/^on/i.test(k) || k.toLowerCase() === 'style') throw new Error('Blocked attribute: ' + k);
        node.setAttribute(k, String(o.attrs[k]));
      });
    }
    if (o.on) Object.keys(o.on).forEach((ev) => node.addEventListener(ev, o.on[ev]));
    (children || []).forEach((c) => { if (c) node.append(c); });
    return node;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, n));

  const D = ODTN;
  const VIEWS = ['dashboard', 'timeline', 'investigate', 'decisions', 'recovery', 'about'];
  const METRICS = [
    { key: 'containment', label: 'Containment' },
    { key: 'continuity', label: 'Critical services' },
    { key: 'trust', label: 'Public trust' },
    { key: 'compliance', label: 'Legal & compliance' }
  ];
  const TIMELINE_IDS = D.timeline.map((t) => t.id);
  const LOG_IDS = D.logs.map((l) => l.id);
  const STEP_IDS = D.recoverySteps.map((s) => s.id);
  const IOC_TOTAL = D.logs.filter((l) => l.ioc).length;

  // ---------------------------------------------------------------- state
  const STORAGE_KEY = 'odtn-cc-v1';

  function freshState() {
    return { role: null, viewed: [], flags: [], invSubmitted: false, decisions: [], plan: [], seqChecked: false, quiz: {}, quizSubmitted: false, reported: false };
  }

  /** Keep only allowed, unique string ids. */
  function idList(value, allowed, max) {
    if (!Array.isArray(value)) return [];
    const out = [];
    value.forEach((v) => {
      if (typeof v === 'string' && allowed.indexOf(v) !== -1 && out.indexOf(v) === -1 && out.length < max) out.push(v);
    });
    return out;
  }

  /** Storage can be edited by the user: validate every field, discard anything unexpected. */
  function loadState() {
    const s = freshState();
    let raw = null;
    try { raw = window.sessionStorage.getItem(STORAGE_KEY); } catch (e) { return s; }
    if (typeof raw !== 'string' || raw.length > 8000) return s;
    let p;
    try { p = JSON.parse(raw); } catch (e) { return s; }
    if (!p || typeof p !== 'object' || Array.isArray(p)) return s;

    if (D.roles.some((r) => r.id === p.role)) s.role = p.role;
    s.viewed = idList(p.viewed, TIMELINE_IDS, TIMELINE_IDS.length);
    s.flags = idList(p.flags, LOG_IDS, LOG_IDS.length);
    s.invSubmitted = p.invSubmitted === true;

    if (Array.isArray(p.decisions) && p.decisions.length <= D.modules.length &&
        p.decisions.every((d, i) => Number.isInteger(d) && d >= 0 && d < D.modules[i].options.length)) {
      s.decisions = p.decisions.slice();
    }

    s.plan = idList(p.plan, STEP_IDS, STEP_IDS.length);
    s.seqChecked = p.seqChecked === true && s.plan.length === STEP_IDS.length;

    if (p.quiz && typeof p.quiz === 'object' && !Array.isArray(p.quiz)) {
      D.quiz.forEach((q, i) => {
        const a = p.quiz[String(i)];
        if (Number.isInteger(a) && a >= 0 && a < q.options.length) s.quiz[String(i)] = a;
      });
    }
    s.quizSubmitted = p.quizSubmitted === true && Object.keys(s.quiz).length === D.quiz.length;
    s.reported = p.reported === true;
    return s;
  }

  let state = loadState();

  function save() {
    try { window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (e) { /* storage unavailable: progress just won't persist */ }
    updateDashboard();
  }

  // ---------------------------------------------------------------- scoring
  function metricValues() {
    const m = { containment: 50, continuity: 50, trust: 50, compliance: 50 };
    state.decisions.forEach((choice, i) => {
      const fx = D.modules[i].options[choice].fx;
      METRICS.forEach(({ key }) => { m[key] = clamp(m[key] + (fx[key] || 0), 0, 100); });
    });
    return m;
  }

  function invResult() {
    let found = 0; let fp = 0;
    D.logs.forEach((l) => {
      const flagged = state.flags.indexOf(l.id) !== -1;
      if (flagged && l.ioc) found++;
      if (flagged && !l.ioc) fp++;
    });
    return { found, fp, missed: IOC_TOTAL - found, pct: Math.max(0, (found - fp) / IOC_TOTAL) * 100 };
  }

  function seqCorrectCount() {
    return state.plan.reduce((n, id, i) => n + (STEP_IDS[i] === id ? 1 : 0), 0);
  }

  function quizCorrectCount() {
    return D.quiz.reduce((n, q, i) => n + (state.quiz[String(i)] === q.answer ? 1 : 0), 0);
  }

  function overallScore() {
    const parts = [];
    if (state.invSubmitted) parts.push([invResult().pct, 30]);
    if (state.decisions.length === D.modules.length) {
      const m = metricValues();
      parts.push([METRICS.reduce((a, { key }) => a + m[key], 0) / METRICS.length, 40]);
    }
    if (state.seqChecked) parts.push([seqCorrectCount() / STEP_IDS.length * 100, 15]);
    if (state.quizSubmitted) parts.push([quizCorrectCount() / D.quiz.length * 100, 15]);
    if (!parts.length) return null;
    const w = parts.reduce((a, p) => a + p[1], 0);
    return Math.round(parts.reduce((a, p) => a + p[0] * p[1], 0) / w);
  }

  // ---------------------------------------------------------------- router
  let currentView = null;

  function route() {
    const h = window.location.hash;
    // Non-route anchors (e.g. the skip link "#main") must not change the view.
    if (h && h.indexOf('#/') !== 0 && currentView) return;
    const name = h.indexOf('#/') === 0 ? h.slice(2) : '';
    const view = VIEWS.indexOf(name) !== -1 ? name : 'dashboard'; // allow-list only
    showView(view);
  }

  function showView(view) {
    const changed = currentView !== null && currentView !== view;
    currentView = view;
    document.querySelectorAll('.view').forEach((v) => { v.hidden = v.getAttribute('data-view') !== view; });
    document.querySelectorAll('[data-nav]').forEach((a) => {
      if (a.getAttribute('data-nav') === view) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    if (changed) {
      window.scrollTo(0, 0);
      const h1 = document.querySelector('#view-' + view + ' h1');
      if (h1) { h1.setAttribute('tabindex', '-1'); h1.focus({ preventScroll: true }); }
    }
  }

  // ---------------------------------------------------------------- sim clock
  const SIM_START = { day: 21, minutes: 10 * 60 + 15 }; // Dec 21 10:15
  const pageStart = Date.now();

  function simTime() {
    const elapsed = Math.floor((Date.now() - pageStart) / 1000); // 1 real second = 1 simulated minute
    const total = SIM_START.minutes + elapsed;
    const day = SIM_START.day + Math.floor(total / 1440);
    const mins = total % 1440;
    const hh = String(Math.floor(mins / 60)).padStart(2, '0');
    const mm = String(mins % 60).padStart(2, '0');
    return { label: 'Dec ' + day + ' ' + hh + ':' + mm, short: hh + ':' + mm };
  }

  function tickClock() { $('sim-clock').textContent = simTime().label; }

  // ---------------------------------------------------------------- dashboard
  function initDashboard() {
    $('scenario-summary').textContent = D.scenario.summary;

    const picker = $('role-picker');
    D.roles.forEach((r) => {
      picker.append(el('button', {
        className: 'role-btn', text: r.name,
        attrs: { type: 'button', role: 'radio', 'aria-checked': 'false', 'data-role': r.id },
        on: { click: () => { state.role = r.id; save(); renderRole(); } }
      }));
    });
    renderRole();

    const sectors = $('sectors');
    D.sectors.forEach((s) => {
      sectors.append(el('div', { className: 'sector lvl-' + s.level }, [
        el('div', { className: 'sector-head' }, [
          el('span', { className: 'sector-name', text: s.name }),
          el('span', { className: 'pill pill-' + s.level, text: s.status })
        ]),
        el('p', { className: 'sector-detail', text: s.detail })
      ]));
    });

    const initialTimes = ['08:12', '07:51', '10:05', '09:30'];
    D.initialAlerts
      .map((a, i) => Object.assign({}, a, { time: initialTimes[i] || '08:00' }))
      .sort((a, b) => (a.time < b.time ? -1 : 1))
      .forEach((a) => addAlert(a, false));

    $('feed-toggle').addEventListener('click', () => {
      feedPaused = !feedPaused;
      const b = $('feed-toggle');
      b.setAttribute('aria-pressed', String(feedPaused));
      b.textContent = feedPaused ? 'Resume feed' : 'Pause feed';
    });

    updateDashboard();
  }

  function renderRole() {
    document.querySelectorAll('.role-btn').forEach((b) => {
      b.setAttribute('aria-checked', String(b.getAttribute('data-role') === state.role));
    });
    const role = D.roles.find((r) => r.id === state.role);
    $('role-objective').textContent = role ? 'Objective: ' + role.objective : 'Pick a role to receive your objective.';
  }

  let feedPaused = false;
  let poolIndex = 0;

  function addAlert(a, isNew) {
    const feed = $('alert-feed');
    const detail = el('p', { className: 'alert-detail', text: a.detail, attrs: { hidden: '' } });
    const btn = el('button', {
      className: 'alert-btn',
      attrs: { type: 'button', 'aria-expanded': 'false' },
      on: { click: () => {
        const open = btn.getAttribute('aria-expanded') === 'true';
        btn.setAttribute('aria-expanded', String(!open));
        detail.hidden = open;
      } }
    }, [
      el('span', { className: 'alert-sev sev-' + a.sev, text: a.sev.toUpperCase() }),
      el('span', { className: 'alert-time', text: a.time }),
      el('span', { className: 'alert-src', text: a.src }),
      el('span', { className: 'alert-msg', text: a.msg })
    ]);
    const li = el('li', { className: 'alert' + (isNew ? ' is-new' : '') }, [btn, detail]);
    feed.prepend(li);
  }

  function feedTick() {
    if (feedPaused || document.hidden) return;
    if (poolIndex >= D.alertPool.length) { window.clearInterval(feedTimer); return; }
    const a = Object.assign({}, D.alertPool[poolIndex++], { time: simTime().short });
    addAlert(a, true);
    if (currentView !== 'dashboard' && (a.sev === 'critical' || a.sev === 'high')) toast(a);
  }

  function toast(a) {
    const box = $('toasts');
    while (box.children.length >= 3) box.removeChild(box.firstChild);
    const t = el('button', {
      className: 'toast sev-border-' + a.sev,
      attrs: { type: 'button' },
      on: { click: () => { t.remove(); window.location.hash = '#/dashboard'; } }
    }, [
      el('span', { className: 'alert-sev sev-' + a.sev, text: a.sev.toUpperCase() }),
      el('span', { text: a.src + ': ' + a.msg })
    ]);
    box.append(t);
    window.setTimeout(() => t.remove(), 7000);
  }

  function updateDashboard() {
    // Transaction success recovers as the user makes decisions.
    const contSum = state.decisions.reduce((a, c, i) => a + D.modules[i].options[c].fx.continuity, 0);
    const success = state.decisions.length ? clamp(Math.round(38 + state.decisions.length * 9 + contSum * 0.6), 5, 97) : 38;
    $('kpi-success').textContent = success + '%';

    let stage = 'Detection'; let note = 'Investigate the logs to progress';
    if (state.invSubmitted) { stage = 'Investigation'; note = 'Make response decisions'; }
    if (state.decisions.length >= 2) { stage = 'Containment'; note = 'Complete all five modules'; }
    if (state.decisions.length === D.modules.length) { stage = 'Recovery'; note = 'Plan a safe restoration'; }
    if (state.seqChecked && state.quizSubmitted) { stage = 'Lessons learned'; note = 'Generate your report'; }
    $('kpi-stage').textContent = stage;
    $('kpi-stage-note').textContent = note;

    const score = overallScore();
    $('kpi-score').textContent = score === null ? '–' : score + '/100';

    const steps = [
      { done: !!state.role, text: 'Choose your role', href: '#/dashboard' },
      { done: state.viewed.length >= 5, text: 'Review at least 5 timeline events (' + state.viewed.length + '/' + TIMELINE_IDS.length + ')', href: '#/timeline' },
      { done: state.invSubmitted, text: 'Identify indicators of compromise', href: '#/investigate' },
      { done: state.decisions.length === D.modules.length, text: 'Make all five response decisions (' + state.decisions.length + '/5)', href: '#/decisions' },
      { done: state.seqChecked, text: 'Build the recovery sequence', href: '#/recovery' },
      { done: state.quizSubmitted, text: 'Complete the lessons-learned quiz', href: '#/recovery' },
      { done: state.reported, text: 'Generate your after-action report', href: '#/recovery' }
    ];
    const list = $('mission');
    clear(list);
    steps.forEach((s) => {
      list.append(el('li', { className: s.done ? 'done' : '' }, [
        el('span', { className: 'tick', text: s.done ? '✓' : '', attrs: { 'aria-hidden': 'true' } }),
        el('a', { text: s.text, attrs: { href: s.href } }),
        el('span', { className: 'sr-only', text: s.done ? ' (done)' : ' (to do)' })
      ]));
    });
  }

  // ---------------------------------------------------------------- timeline
  let timelineFilter = 'all';

  function initTimeline() {
    const list = $('timeline');
    D.timeline.forEach((t) => {
      const panelId = 'tl-panel-' + t.id;
      const panel = el('div', { className: 'tl-panel', attrs: { id: panelId, hidden: '' } }, [
        el('p', { text: t.body }),
        el('p', { className: 'tl-lesson' }, [el('strong', { text: 'Lesson: ' }), document.createTextNode(t.lesson)])
      ]);
      const btn = el('button', {
        className: 'tl-btn',
        attrs: { type: 'button', 'aria-expanded': 'false', 'aria-controls': panelId },
        on: { click: () => {
          const open = btn.getAttribute('aria-expanded') === 'true';
          btn.setAttribute('aria-expanded', String(!open));
          panel.hidden = open;
          if (!open && state.viewed.indexOf(t.id) === -1) {
            state.viewed.push(t.id);
            li.classList.add('viewed');
            save();
            renderTimelineProgress();
          }
        } }
      }, [
        el('span', { className: 'tl-when', text: t.when }),
        el('span', { className: 'tl-cat cat-' + t.cat, text: t.cat === 'comms' ? 'Comms' : t.cat === 'business' ? 'Business' : 'Technical' }),
        el('span', { className: 'tl-title', text: t.title })
      ]);
      const li = el('li', { className: 'tl-item' + (state.viewed.indexOf(t.id) !== -1 ? ' viewed' : ''), attrs: { 'data-cat': t.cat } }, [
        el('span', { className: 'tl-dot', attrs: { 'aria-hidden': 'true' } }), btn, panel
      ]);
      list.append(li);
    });

    $('timeline-filters').addEventListener('click', (e) => {
      const b = e.target.closest('button[data-filter]');
      if (!b) return;
      const f = b.getAttribute('data-filter');
      if (['all', 'technical', 'business', 'comms'].indexOf(f) === -1) return;
      timelineFilter = f;
      document.querySelectorAll('#timeline-filters .chip').forEach((c) => c.setAttribute('aria-pressed', String(c === b)));
      document.querySelectorAll('#timeline .tl-item').forEach((item) => {
        item.hidden = f !== 'all' && item.getAttribute('data-cat') !== f;
      });
    });
    renderTimelineProgress();
  }

  function renderTimelineProgress() {
    $('timeline-progress').textContent = state.viewed.length + ' of ' + TIMELINE_IDS.length + ' events reviewed';
  }

  // ---------------------------------------------------------------- investigation
  const MAX_SEARCH = 60;

  function initInvestigation() {
    const sel = $('log-source');
    Array.from(new Set(D.logs.map((l) => l.src))).sort().forEach((src) => {
      sel.append(el('option', { text: src, attrs: { value: src } }));
    });

    $('log-search').addEventListener('input', renderLogs);
    sel.addEventListener('change', renderLogs);
    $('inv-submit').addEventListener('click', () => {
      if (!state.flags.length) {
        showResult('Flag at least one log line before submitting.');
        return;
      }
      state.invSubmitted = true; save(); renderLogs(); renderInvResult();
      $('inv-result').focus();
    });
    $('inv-reset').addEventListener('click', () => {
      state.flags = []; state.invSubmitted = false; save();
      $('inv-result').hidden = true;
      renderLogs();
    });
    renderLogs();
    if (state.invSubmitted) renderInvResult();
  }

  /** Validate the search term: length-limited, no control characters. Plain substring matching only. */
  function readSearch() {
    const input = $('log-search');
    const err = $('log-search-error');
    let v = input.value;
    if (v.length > MAX_SEARCH) { v = v.slice(0, MAX_SEARCH); input.value = v; }
    // eslint-disable-next-line no-control-regex
    if (/[\u0000-\u001F\u007F]/.test(v)) {
      err.textContent = 'Search contains characters that are not allowed.';
      err.hidden = false;
      return null;
    }
    err.hidden = true;
    return v.trim().toLowerCase();
  }

  function renderLogs() {
    const term = readSearch();
    const src = $('log-source').value;
    const validSrc = src === '' || D.logs.some((l) => l.src === src);
    const body = $('log-body');
    clear(body);
    let shown = 0;

    D.logs.forEach((l) => {
      if (term === null || !validSrc) return;
      if (src && l.src !== src) return;
      if (term && (l.ts + ' ' + l.src + ' ' + l.msg).toLowerCase().indexOf(term) === -1) return;
      shown++;

      const flagged = state.flags.indexOf(l.id) !== -1;
      const cb = el('input', {
        attrs: { type: 'checkbox', 'aria-label': 'Flag ' + l.id + ' as an indicator of compromise' },
        on: { change: () => {
          const idx = state.flags.indexOf(l.id);
          if (cb.checked && idx === -1) state.flags.push(l.id);
          if (!cb.checked && idx !== -1) state.flags.splice(idx, 1);
          save(); updateFlagCount();
          tr.classList.toggle('flagged', cb.checked);
        } }
      });
      cb.checked = flagged;
      cb.disabled = state.invSubmitted;

      const eventCell = el('td', { className: 'log-msg' }, [el('code', { text: l.msg })]);
      let rowClass = flagged ? 'flagged' : '';
      if (state.invSubmitted) {
        let verdict; let cls;
        if (l.ioc && flagged) { verdict = '✓ Correct – IOC'; cls = 'v-good'; }
        else if (l.ioc && !flagged) { verdict = '✗ Missed IOC'; cls = 'v-miss'; }
        else if (!l.ioc && flagged) { verdict = '✗ False positive'; cls = 'v-bad'; }
        else { verdict = '✓ Correctly ignored'; cls = 'v-ok'; }
        rowClass += ' ' + cls;
        eventCell.append(el('p', { className: 'log-why' }, [el('strong', { text: verdict + ': ' }), document.createTextNode(l.why)]));
      }

      const tr = el('tr', { className: rowClass.trim() }, [
        el('td', { className: 'log-flag' }, [cb]),
        el('td', { className: 'log-ts', text: l.ts }),
        el('td', { className: 'log-src', text: l.src }),
        eventCell
      ]);
      body.append(tr);
    });

    if (!shown) body.append(el('tr', {}, [el('td', { text: 'No log lines match.', attrs: { colspan: '4' }, className: 'empty' })]));
    $('log-count').textContent = shown + ' of ' + D.logs.length + ' lines shown';
    updateFlagCount();
  }

  function updateFlagCount() {
    $('flag-count').textContent = state.flags.length + (state.flags.length === 1 ? ' line' : ' lines') + ' flagged';
  }

  function showResult(msg) {
    const box = $('inv-result');
    clear(box);
    box.append(el('p', { text: msg }));
    box.hidden = false;
  }

  function renderInvResult() {
    const r = invResult();
    const box = $('inv-result');
    clear(box);
    box.append(
      el('h2', { className: 'panel-title', text: 'Investigation results' }),
      el('div', { className: 'result-stats' }, [
        stat(r.found + '/' + IOC_TOTAL, 'IOCs found'),
        stat(String(r.fp), 'False positives'),
        stat(String(r.missed), 'Missed'),
        stat(Math.round(r.pct) + '%', 'Accuracy score')
      ]),
      el('p', { text: r.found === IOC_TOTAL && r.fp === 0
        ? 'Perfect triage. You traced the full attack chain: vendor account takeover → malicious signed update → code execution → beaconing → persistence → pivot into your merchant portal.'
        : 'Explanations are now shown under each log line. Notice how the attacker IP 203.0.113.47 links the vendor compromise (L01) to access in your own environment (L11) – correlating evidence across sources is what reveals the full story.' }),
      el('a', { className: 'btn btn-primary', text: 'Continue to decisions →', attrs: { href: '#/decisions' } })
    );
    box.hidden = false;
  }

  function stat(value, label) {
    return el('div', { className: 'stat' }, [el('span', { className: 'stat-value', text: value }), el('span', { className: 'stat-label', text: label })]);
  }

  // ---------------------------------------------------------------- decisions
  let awaitingNext = false;

  function initDecisions() {
    $('dec-next').addEventListener('click', () => { awaitingNext = false; renderDecision(); $('module-situation').focus(); });
    $('dec-restart').addEventListener('click', () => { state.decisions = []; awaitingNext = false; save(); renderDecision(); });
    $('module-situation').setAttribute('tabindex', '-1');
    renderDecision();
  }

  function renderMeters() {
    const m = metricValues();
    const box = $('meters');
    clear(box);
    METRICS.forEach(({ key, label }) => {
      const v = m[key];
      const fill = el('span', { className: 'meter-fill ' + (v >= 65 ? 'm-good' : v >= 40 ? 'm-mid' : 'm-bad') });
      fill.style.setProperty('width', v + '%'); // CSSOM, permitted by CSP
      box.append(el('div', { className: 'meter' }, [
        el('div', { className: 'meter-head' }, [el('span', { text: label }), el('span', { className: 'meter-val', text: String(v) })]),
        el('div', { className: 'meter-track', attrs: { role: 'meter', 'aria-label': label, 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(v) } }, [fill])
      ]));
    });
  }

  function renderStepper(active) {
    const s = $('stepper');
    clear(s);
    D.modules.forEach((mod, i) => {
      let cls = 'step-dot';
      if (i < state.decisions.length) cls += D.modules[i].options[state.decisions[i]].best ? ' s-best' : ' s-done';
      if (i === active) cls += ' s-active';
      s.append(el('span', { className: cls, text: String(i + 1) }));
    });
  }

  function renderDecision() {
    renderMeters();
    const done = state.decisions.length;
    const optsBox = $('module-options');
    const fb = $('module-feedback');
    clear(optsBox);
    clear(fb);
    fb.hidden = true;
    $('dec-next').hidden = true;

    if (done === D.modules.length && !awaitingNext) {
      renderStepper(-1);
      renderDecisionSummary();
      return;
    }

    const idx = awaitingNext ? done - 1 : done;
    const mod = D.modules[idx];
    renderStepper(idx);
    $('module-tag').textContent = mod.tag + '  (' + (idx + 1) + ' of ' + D.modules.length + ')';
    $('module-situation').textContent = mod.situation;

    mod.options.forEach((opt, oi) => {
      const chosen = awaitingNext && state.decisions[idx] === oi;
      let cls = 'option';
      if (awaitingNext && opt.best) cls += ' is-best';
      if (chosen) cls += ' is-chosen';
      const b = el('button', {
        className: cls,
        attrs: { type: 'button' },
        on: { click: () => choose(idx, oi) }
      }, [el('span', { className: 'option-key', text: String.fromCharCode(65 + oi) }), el('span', { text: opt.text })]);
      b.disabled = awaitingNext;
      optsBox.append(b);
    });

    if (awaitingNext) {
      const opt = mod.options[state.decisions[idx]];
      const deltas = el('div', { className: 'deltas' });
      METRICS.forEach(({ key, label }) => {
        const d = opt.fx[key] || 0;
        if (!d) return;
        deltas.append(el('span', { className: 'delta ' + (d > 0 ? 'up' : 'down'), text: label + ' ' + (d > 0 ? '+' : '') + d }));
      });
      fb.append(
        el('p', { className: 'fb-title ' + (opt.best ? 'good' : 'warn'), text: opt.best ? 'Best practice' : 'Consider the trade-offs' }),
        el('p', { text: opt.feedback }),
        deltas
      );
      fb.hidden = false;
      const next = $('dec-next');
      next.textContent = idx === D.modules.length - 1 ? 'See results' : 'Next module';
      next.hidden = false;
    }
  }

  function choose(idx, optionIndex) {
    if (awaitingNext || idx !== state.decisions.length) return;
    if (!Number.isInteger(optionIndex) || optionIndex < 0 || optionIndex >= D.modules[idx].options.length) return;
    state.decisions.push(optionIndex);
    awaitingNext = true;
    save();
    renderDecision();
    $('module-feedback').focus();
  }

  function renderDecisionSummary() {
    const best = state.decisions.filter((c, i) => D.modules[i].options[c].best).length;
    $('module-tag').textContent = 'Simulation complete';
    $('module-situation').textContent = 'You chose the best-practice response in ' + best + ' of ' + D.modules.length + ' modules.';
    const box = $('module-options');
    const list = el('ol', { className: 'summary-list' });
    state.decisions.forEach((c, i) => {
      const mod = D.modules[i];
      const opt = mod.options[c];
      const li = el('li', { className: opt.best ? 'good' : 'warn' }, [
        el('strong', { text: mod.tag }),
        el('p', { text: 'You chose: ' + opt.text })
      ]);
      if (!opt.best) li.append(el('p', { className: 'muted', text: 'Best practice: ' + mod.options.find((o) => o.best).text }));
      list.append(li);
    });
    box.append(list, el('a', { className: 'btn btn-primary', text: 'Continue to recovery →', attrs: { href: '#/recovery' } }));
  }

  // ---------------------------------------------------------------- recovery
  function initRecovery() {
    $('seq-reset').addEventListener('click', () => { state.plan = []; state.seqChecked = false; save(); renderSequence(); });
    $('seq-check').addEventListener('click', () => {
      if (state.plan.length !== STEP_IDS.length) {
        $('seq-result').textContent = 'Add all ' + STEP_IDS.length + ' steps to your plan first.';
        return;
      }
      state.seqChecked = true; save(); renderSequence();
    });
    renderSequence();

    initQuiz();

    const lessons = $('lessons');
    D.lessons.forEach((l) => lessons.append(el('li', { text: l })));

    $('report-form').addEventListener('submit', (e) => {
      e.preventDefault();
      generateReport();
    });
  }

  function stepText(id) { return D.recoverySteps.find((s) => s.id === id).text; }

  function renderSequence() {
    const pool = $('step-pool');
    const plan = $('step-plan');
    clear(pool); clear(plan);

    D.recoveryDisplayOrder.forEach((id) => {
      if (state.plan.indexOf(id) !== -1) return;
      pool.append(el('button', {
        className: 'step-btn', text: stepText(id),
        attrs: { type: 'button' },
        on: { click: () => {
          if (state.plan.indexOf(id) === -1 && STEP_IDS.indexOf(id) !== -1) { state.plan.push(id); state.seqChecked = false; save(); renderSequence(); }
        } }
      }));
    });
    if (!pool.children.length) pool.append(el('p', { className: 'muted', text: 'All steps placed.' }));

    state.plan.forEach((id, i) => {
      let cls = 'plan-item';
      let mark = '';
      if (state.seqChecked) {
        const ok = STEP_IDS[i] === id;
        cls += ok ? ' ok' : ' wrong';
        mark = ok ? '✓ ' : '✗ ';
      }
      plan.append(el('li', { className: cls }, [
        el('span', { text: mark + stepText(id) }),
        el('button', {
          className: 'btn-x', text: '×',
          attrs: { type: 'button', 'aria-label': 'Remove step: ' + stepText(id) },
          on: { click: () => { state.plan.splice(state.plan.indexOf(id), 1); state.seqChecked = false; save(); renderSequence(); } }
        })
      ]));
    });
    if (!state.plan.length) plan.append(el('li', { className: 'muted empty-plan', text: 'Select steps on the left to build your plan.' }));

    const r = $('seq-result');
    if (state.seqChecked) {
      const n = seqCorrectCount();
      r.textContent = n === STEP_IDS.length
        ? 'Perfect sequence! Contain, verify, rebuild, restore critical services first, then notify and learn.'
        : n + ' of ' + STEP_IDS.length + ' steps in the right position. Remember: never restore before you have confirmed containment and have a verified clean build.';
    } else {
      r.textContent = state.plan.length + ' of ' + STEP_IDS.length + ' steps placed';
    }
  }

  function initQuiz() {
    const box = $('quiz');
    D.quiz.forEach((q, qi) => {
      const fs = el('fieldset', { className: 'q', attrs: { 'data-q': String(qi) } }, [
        el('legend', { text: (qi + 1) + '. ' + q.q })
      ]);
      q.options.forEach((opt, oi) => {
        const input = el('input', { attrs: { type: 'radio', name: 'q' + qi, value: String(oi) } });
        input.checked = state.quiz[String(qi)] === oi;
        input.addEventListener('change', () => {
          if (state.quizSubmitted) return;
          state.quiz[String(qi)] = oi; save();
        });
        fs.append(el('label', { className: 'q-opt' }, [input, el('span', { text: opt })]));
      });
      fs.append(el('p', { className: 'q-explain', attrs: { hidden: '' } }));
      box.append(fs);
    });

    $('quiz-submit').addEventListener('click', () => {
      if (Object.keys(state.quiz).length !== D.quiz.length) {
        $('quiz-result').textContent = 'Answer all ' + D.quiz.length + ' questions first.';
        return;
      }
      state.quizSubmitted = true; save(); renderQuizResults();
    });
    if (state.quizSubmitted) renderQuizResults();
  }

  function renderQuizResults() {
    document.querySelectorAll('#quiz fieldset.q').forEach((fs) => {
      const qi = Number(fs.getAttribute('data-q'));
      const q = D.quiz[qi];
      const correct = state.quiz[String(qi)] === q.answer;
      fs.classList.add(correct ? 'q-right' : 'q-wrong');
      fs.querySelectorAll('input').forEach((i) => { i.disabled = true; });
      const ex = fs.querySelector('.q-explain');
      ex.textContent = (correct ? '✓ Correct. ' : '✗ Answer: ' + q.options[q.answer] + '. ') + q.explain;
      ex.hidden = false;
    });
    $('quiz-submit').disabled = true;
    $('quiz-result').textContent = 'You scored ' + quizCorrectCount() + ' of ' + D.quiz.length + '.';
  }

  // Allow-list: a letter first, then letters, spaces, apostrophes, hyphens, full stops. Max 40.
  const NAME_RE = /^[\p{L}][\p{L} .'’-]{0,39}$/u;

  function generateReport() {
    const input = $('report-name');
    const err = $('report-name-error');
    const raw = input.value.normalize('NFC').trim().replace(/\s+/g, ' ');
    if (raw && !NAME_RE.test(raw)) {
      err.textContent = 'Please use letters, spaces, apostrophes, hyphens or full stops only (max 40 characters).';
      err.hidden = false;
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      return;
    }
    err.hidden = true;
    input.removeAttribute('aria-invalid');
    const name = raw || 'Anonymous responder';

    const report = $('report');
    clear(report);
    const role = D.roles.find((r) => r.id === state.role);
    const score = overallScore();

    report.append(
      el('header', { className: 'report-head' }, [
        el('p', { className: 'eyebrow', text: 'After-action report · ' + simTime().label }),
        el('h3', { text: D.scenario.title }),
        el('p', { text: 'Prepared by: ' + name + (role ? ' · Role: ' + role.name : '') }),
        el('p', { className: 'report-score', text: score === null ? 'Readiness score: not enough exercises completed' : 'Overall readiness score: ' + score + '/100' })
      ])
    );

    const sec = (title, lines) => el('section', {}, [el('h4', { text: title }), el('ul', {}, lines.map((t) => el('li', { text: t })))]);

    if (state.invSubmitted) {
      const r = invResult();
      report.append(sec('Investigation', [
        r.found + ' of ' + IOC_TOTAL + ' indicators of compromise identified',
        r.fp + ' false positive(s), ' + r.missed + ' missed'
      ]));
    } else report.append(sec('Investigation', ['Not completed']));

    if (state.decisions.length) {
      const m = metricValues();
      report.append(sec('Response decisions', state.decisions.map((c, i) =>
        D.modules[i].tag + ': ' + (D.modules[i].options[c].best ? 'best practice' : 'sub-optimal')
      ).concat(METRICS.map(({ key, label }) => label + ' – final score ' + m[key]))));
    } else report.append(sec('Response decisions', ['Not completed']));

    report.append(sec('Recovery & knowledge', [
      state.seqChecked ? 'Recovery sequence: ' + seqCorrectCount() + '/' + STEP_IDS.length + ' steps correctly placed' : 'Recovery sequence: not completed',
      state.quizSubmitted ? 'Quiz: ' + quizCorrectCount() + '/' + D.quiz.length + ' correct' : 'Quiz: not completed'
    ]));

    report.append(sec('Recommended focus areas', recommendations()));
    report.append(el('button', { className: 'btn btn-ghost no-print', text: 'Print / save as PDF', attrs: { type: 'button' }, on: { click: () => window.print() } }));

    report.hidden = false;
    report.focus();
    state.reported = true;
    save();
  }

  function recommendations() {
    const recs = [];
    if (state.invSubmitted) {
      const r = invResult();
      if (r.missed) recs.push('Practise correlating evidence across log sources – shared indicators (like an attacker IP) reveal the full attack chain.');
      if (r.fp) recs.push('Reduce false positives: distinguish incident symptoms and background noise from true indicators of compromise.');
    }
    if (state.decisions.length === D.modules.length) {
      const m = metricValues();
      const advice = {
        containment: 'Act decisively on your own evidence: targeted containment beats waiting for confirmation.',
        continuity: 'Pre-plan business-continuity fallbacks and rank critical services before an incident.',
        trust: 'Prepare holding statements and commit to a regular, evidence-based update cadence.',
        compliance: 'Preserve evidence and engage legal, privacy and regulators early.'
      };
      METRICS.filter(({ key }) => m[key] < 65).forEach(({ key }) => recs.push(advice[key]));
    }
    if (state.seqChecked && seqCorrectCount() < STEP_IDS.length) recs.push('Review staged recovery: confirm containment and verify clean builds before restoring any service.');
    if (!recs.length) recs.push('Excellent work. Next step: run this scenario as a live tabletop exercise with your own team.');
    return recs;
  }

  // ---------------------------------------------------------------- boot
  initDashboard();
  initTimeline();
  initInvestigation();
  initDecisions();
  initRecovery();
  window.addEventListener('hashchange', route);
  route();
  tickClock();
  window.setInterval(tickClock, 1000);
  const feedTimer = window.setInterval(feedTick, 9000);
})();
