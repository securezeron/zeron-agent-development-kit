/* ═══════════════════════════════════════════════════════════
   DomainShield Agent – Dashboard Application Logic
   ═══════════════════════════════════════════════════════════ */

'use strict';

// ══════════════════════════════════════════════════════════
// 1. SAMPLE DATA  (simulates agent output for the UI demo)
// ══════════════════════════════════════════════════════════

const SAMPLE_EMAILS = [
  {
    uid: 'msg-001',
    from_raw: '"Alice Johnson" <alice@company.com>',
    from_domain: 'company.com',
    display_name: 'Alice Johnson',
    subject: 'Q1 Financial Report – Final Draft',
    date: '2026-04-12 09:14',
    risk_level: 'SAFE',
    action: 'ALLOW',
    reasons: [],
    flags: {},
    spf_pass: true, dkim_pass: true, dmarc_pass: true,
    in_whitelist: true,
    body_preview: 'Hi team, please find attached the final Q1 report for review before the board meeting.',
  },
  {
    uid: 'msg-002',
    from_raw: '"IT Security Team" <noreply@evil-company.net>',
    from_domain: 'evil-company.net',
    display_name: 'IT Security Team',
    subject: '🚨 URGENT: Your account will be suspended – verify now',
    date: '2026-04-12 09:31',
    risk_level: 'HIGH_RISK',
    action: 'BLOCK',
    reasons: [
      "Display name 'IT Security Team' resembles 'company' but sent from 'evil-company.net'",
      "SPF check failed",
      "DKIM check failed",
      "Sender domain 'evil-company.net' is not in the approved whitelist",
    ],
    flags: { display_name_spoof: true },
    spf_pass: false, dkim_pass: false, dmarc_pass: false,
    in_whitelist: false,
    body_preview: 'Your account has been flagged for suspicious activity. Click here immediately to verify your identity or your access will be revoked within 24 hours.',
  },
  {
    uid: 'msg-003',
    from_raw: '"Trusted Partner" <billing@trustedpartner.com>',
    from_domain: 'trustedpartner.com',
    display_name: 'Trusted Partner',
    subject: 'Invoice #INV-2026-0412 – Payment Confirmation',
    date: '2026-04-12 10:02',
    risk_level: 'SAFE',
    action: 'ALLOW',
    reasons: [],
    flags: {},
    spf_pass: true, dkim_pass: true, dmarc_pass: true,
    in_whitelist: true,
    body_preview: 'Please find your payment confirmation for invoice INV-2026-0412 attached. Thank you for your continued partnership.',
  },
  {
    uid: 'msg-004',
    from_raw: '"Newsletter" <newsletter@external-vendor.io>',
    from_domain: 'external-vendor.io',
    display_name: 'Newsletter',
    subject: 'April Product Updates & Announcements',
    date: '2026-04-12 11:17',
    risk_level: 'MEDIUM_RISK',
    action: 'WARN',
    reasons: ["Sender domain 'external-vendor.io' is not in the approved whitelist"],
    flags: {},
    spf_pass: true, dkim_pass: true, dmarc_pass: true,
    in_whitelist: false,
    body_preview: 'Check out what is new in our April release: enhanced reporting, API improvements, and new integrations.',
  },
  {
    uid: 'msg-005',
    from_raw: '"Microsoft Support" <support@micros0ft-help.com>',
    from_domain: 'micros0ft-help.com',
    display_name: 'Microsoft Support',
    subject: 'Your Microsoft 365 subscription is expiring',
    date: '2026-04-12 11:45',
    risk_level: 'HIGH_RISK',
    action: 'BLOCK',
    reasons: [
      "Display name 'Microsoft Support' resembles known brand 'microsoft' but sent from 'micros0ft-help.com'",
      "DMARC check failed",
      "Sender domain 'micros0ft-help.com' is not in the approved whitelist",
    ],
    flags: { display_name_spoof: true },
    spf_pass: false, dkim_pass: false, dmarc_pass: false,
    in_whitelist: false,
    body_preview: 'Your subscription will expire in 3 days. To avoid service interruption, renew immediately at the link below.',
  },
  {
    uid: 'msg-006',
    from_raw: '"Bob Smith" <bob@company.com>',
    from_domain: 'company.com',
    display_name: 'Bob Smith',
    subject: 'Team lunch next Friday?',
    date: '2026-04-12 12:03',
    risk_level: 'SAFE',
    action: 'ALLOW',
    reasons: [],
    flags: {},
    spf_pass: true, dkim_pass: true, dmarc_pass: true,
    in_whitelist: true,
    body_preview: 'Hey everyone, are we still on for the team lunch next Friday at noon? Please RSVP by Thursday.',
  },
  {
    uid: 'msg-007',
    from_raw: '"CEO" <ceo@company.com>',
    from_domain: 'company.com',
    display_name: 'CEO',
    subject: 'Wire Transfer – Urgent Request',
    date: '2026-04-12 13:22',
    risk_level: 'HIGH_RISK',
    action: 'BLOCK',
    reasons: [
      "SPF check failed",
      "DKIM check failed",
      "DMARC check failed",
      "Whitelisted domain 'company.com' with authentication failures — possible internal spoofing",
    ],
    flags: {},
    spf_pass: false, dkim_pass: false, dmarc_pass: false,
    in_whitelist: true,
    body_preview: 'I need you to process a wire transfer of $45,000 immediately to a new vendor. This is time-sensitive. Do not discuss with anyone else.',
  },
  {
    uid: 'msg-008',
    from_raw: '"Phish" <admin@mail.evil.company.com>',
    from_domain: 'mail.evil.company.com',
    display_name: 'Company Admin',
    subject: 'Password Reset Required – Action Needed',
    date: '2026-04-12 14:05',
    risk_level: 'HIGH_RISK',
    action: 'BLOCK',
    reasons: [
      "Sender uses unauthorized subdomain of whitelisted domain (mail.evil.company.com of company.com)",
      "SPF check failed",
      "Sender domain 'mail.evil.company.com' is not in the approved whitelist",
    ],
    flags: { subdomain_spoof: true },
    spf_pass: false, dkim_pass: false, dmarc_pass: false,
    in_whitelist: false,
    body_preview: 'Your account password must be reset immediately due to a security policy update. Follow the link below to complete the process.',
  },
];

const WHITELIST = ['company.com', 'trustedpartner.com'];

// ══════════════════════════════════════════════════════════
// 2. STATE
// ══════════════════════════════════════════════════════════

let state = {
  emails: window.LIVE_EMAILS ? window.LIVE_EMAILS : [...SAMPLE_EMAILS],
  whitelist: window.LIVE_WHITELIST ? window.LIVE_WHITELIST : [...WHITELIST],
  strictMode: window.LIVE_STRICT_MODE !== undefined ? window.LIVE_STRICT_MODE : true,
  alertThreshold: 'medium_and_above',
  showBlocked: true,
  activeFilter: 'all',
  searchQuery: '',
  currentView: 'inbox',
  scanning: false,
};

// ══════════════════════════════════════════════════════════
// 3. INIT
// ══════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  updateStats();
  renderEmailList();
  renderBlockedList();
  renderWhitelist();
  renderLogs();
  renderAnalytics();
  updateBadges();
  
  // Auto-sync config from the CLI if server is running
  setInterval(() => {
    if (window.location.protocol !== 'file:') {
      fetch('/api/whitelist')
        .then(r => r.json())
        .then(data => {
          if (data.domains && JSON.stringify(data.domains) !== JSON.stringify(state.whitelist)) {
            state.whitelist = data.domains;
            renderWhitelist();
          }
        }).catch(()=>{});
    }
  }, 2000);
});

// ══════════════════════════════════════════════════════════
// 4. VIEW NAVIGATION
// ══════════════════════════════════════════════════════════

const VIEW_META = {
  inbox:     { title: 'Inbox Monitor',     sub: 'Zero-trust email visibility' },
  blocked:   { title: 'Blocked / Flagged', sub: 'Emails intercepted by DomainShield policy' },
  policy:    { title: 'Policy Manager',    sub: 'Whitelist domains & agent configuration' },
  logs:      { title: 'Audit Logs',        sub: 'Complete email processing history' },
  analytics: { title: 'Analytics',         sub: 'Detection signals & risk distribution' },
};

function showView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  document.getElementById(`view-${name}`).classList.remove('hidden');
  document.getElementById(`nav-${name}`)?.classList.add('active');

  const meta = VIEW_META[name] || {};
  document.getElementById('page-title').textContent = meta.title || name;
  document.getElementById('page-sub').textContent   = meta.sub   || '';
  state.currentView = name;
}

// ══════════════════════════════════════════════════════════
// 5. STATS
// ══════════════════════════════════════════════════════════

function updateStats() {
  const total  = state.emails.length;
  const safe   = state.emails.filter(e => e.risk_level === 'SAFE').length;
  const medium = state.emails.filter(e => e.risk_level === 'MEDIUM_RISK').length;
  const high   = state.emails.filter(e => e.risk_level === 'HIGH_RISK').length;

  animateCount('stat-total-val',  total);
  animateCount('stat-safe-val',   safe);
  animateCount('stat-medium-val', medium);
  animateCount('stat-high-val',   high);
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const duration = 600;
  const startTime = performance.now();
  const step = (now) => {
    const t = Math.min((now - startTime) / duration, 1);
    el.textContent = Math.round(start + (target - start) * easeOut(t));
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function updateBadges() {
  const safe = state.emails.filter(e => e.risk_level === 'SAFE').length;
  const bad  = state.emails.filter(e => e.risk_level !== 'SAFE').length;
  document.getElementById('badge-inbox').textContent   = safe;
  document.getElementById('badge-blocked').textContent = bad;
}

// ══════════════════════════════════════════════════════════
// 6. EMAIL LIST RENDERING
// ══════════════════════════════════════════════════════════

function getFilteredEmails() {
  return state.emails.filter(email => {
    if (!state.showBlocked && email.risk_level !== 'SAFE') return false;
    if (state.activeFilter !== 'all' && email.risk_level !== state.activeFilter) return false;
    if (state.searchQuery) {
      const q = state.searchQuery.toLowerCase();
      return (
        email.from_raw.toLowerCase().includes(q) ||
        email.subject.toLowerCase().includes(q) ||
        email.from_domain.toLowerCase().includes(q)
      );
    }
    return true;
  });
}

function renderEmailList() {
  const list = document.getElementById('email-list');
  const emails = getFilteredEmails();
  list.innerHTML = emails.length ? emails.map(emailRowHTML).join('') : emptyStateHTML();
}

function renderBlockedList() {
  const list = document.getElementById('blocked-list');
  const emails = state.emails.filter(e => e.risk_level !== 'SAFE');
  list.innerHTML = emails.length ? emails.map(emailRowHTML).join('') : emptyStateHTML('No blocked emails yet 🎉');
}

function emailRowHTML(email) {
  const initials = email.display_name
    ? email.display_name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase()
    : email.from_domain[0].toUpperCase();

  const avatarClass = {
    SAFE: 'avatar-safe', MEDIUM_RISK: 'avatar-warn', HIGH_RISK: 'avatar-danger',
  }[email.risk_level] || 'avatar-safe';

  const bannerHTML = email.risk_level !== 'SAFE'
    ? `<div class="warning-banner">
        ${email.risk_level === 'HIGH_RISK' ? '🔴' : '⚠️'}
        <span>${email.reasons[0] || 'Flagged by DomainShield policy'}</span>
       </div>`
    : '';

  return `
    <div class="email-row ${email.risk_level}" onclick="openEmailDetail('${email.uid}')">
      <div class="email-avatar ${avatarClass}">${initials}</div>
      <div class="email-body">
        <div class="email-from">${escHtml(email.display_name || email.from_domain)}</div>
        <div class="email-subject">${escHtml(email.subject)}</div>
        <div class="email-domain">${escHtml(email.from_domain)}</div>
        ${bannerHTML}
      </div>
      <div class="email-meta">
        <span class="email-date">${email.date}</span>
        <span class="risk-badge risk-${email.risk_level}">${riskLabel(email.risk_level)}</span>
        <span style="font-size:11px;color:var(--${actionColor(email.action)})">${email.action}</span>
      </div>
    </div>`;
}

function emptyStateHTML(msg = 'No emails match your filters') {
  return `<div class="empty-state"><div class="empty-icon">📭</div><p>${msg}</p></div>`;
}

function riskLabel(level) {
  return { SAFE: '✅ Safe', MEDIUM_RISK: '⚠️ Medium', HIGH_RISK: '🔴 High Risk' }[level] || level;
}

function actionColor(action) {
  return { ALLOW: 'safe', WARN: 'warn', BLOCK: 'danger' }[action] || 'text3';
}

// ══════════════════════════════════════════════════════════
// 7. EMAIL DETAIL MODAL
// ══════════════════════════════════════════════════════════

function openEmailDetail(uid) {
  const email = state.emails.find(e => e.uid === uid);
  if (!email) return;

  const authSummary = [
    email.spf_pass  ? '✅ SPF'  : '❌ SPF',
    email.dkim_pass ? '✅ DKIM' : '❌ DKIM',
    email.dmarc_pass? '✅ DMARC': '❌ DMARC',
  ].join('  &nbsp;  ');

  const reasonsHTML = email.reasons.length
    ? email.reasons.map(r => `<div class="modal-reason">⚠️ <span>${escHtml(r)}</span></div>`).join('')
    : '<div class="modal-reason">✅ <span>No issues detected</span></div>';

  const flagsHTML = Object.keys(email.flags).length
    ? Object.entries(email.flags)
        .filter(([,v]) => v)
        .map(([k]) => `<span class="risk-badge risk-HIGH_RISK">${k.replace(/_/g,' ')}</span>`)
        .join(' ')
    : '<span style="color:var(--safe);font-size:13px">None</span>';

  document.getElementById('modal-content').innerHTML = `
    <div class="modal-title">
      <span class="risk-badge risk-${email.risk_level}" style="margin-right:8px">${riskLabel(email.risk_level)}</span>
      Email Detail
    </div>

    <div class="modal-section">
      <div class="modal-section-label">From</div>
      <div class="modal-value">${escHtml(email.from_raw)}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Subject</div>
      <div class="modal-value">${escHtml(email.subject)}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Sender Domain</div>
      <div class="modal-value">${escHtml(email.from_domain)}
        &nbsp;${email.in_whitelist
          ? '<span style="color:var(--safe);font-size:11px">✅ Whitelisted</span>'
          : '<span style="color:var(--danger);font-size:11px">🚫 Not whitelisted</span>'}
      </div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Authentication</div>
      <div class="modal-value">${authSummary}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Active Flags</div>
      <div style="padding: 6px 0">${flagsHTML}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Flagging Reasons</div>
      <div class="modal-reasons">${reasonsHTML}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Body Preview</div>
      <div class="modal-value" style="font-family:inherit;font-size:13px;color:var(--text2)">${escHtml(email.body_preview || '—')}</div>
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Action</div>
      <div style="font-size:14px;font-weight:700;color:var(--${actionColor(email.action)})">${email.action}</div>
    </div>
  `;

  document.getElementById('modal-backdrop').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('modal-backdrop').classList.add('hidden');
}

// ══════════════════════════════════════════════════════════
// 8. FILTERS & SEARCH
// ══════════════════════════════════════════════════════════

function setFilter(filter, chip) {
  state.activeFilter = filter;
  document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
  chip.classList.add('active');
  renderEmailList();
}

function filterEmails() {
  state.searchQuery = document.getElementById('search-box').value;
  renderEmailList();
}

function toggleShowBlocked() {
  state.showBlocked = !state.showBlocked;
  const btn = document.getElementById('toggle-blocked-btn');
  btn.textContent = state.showBlocked ? '👁 Hide Suspicious' : '👁 Show Suspicious';
  renderEmailList();
}

// ══════════════════════════════════════════════════════════
// 9. SCAN SIMULATION
// ══════════════════════════════════════════════════════════

const NEW_EMAILS = [
  {
    uid: `msg-new-${Date.now()}`,
    from_raw: '"Marketing" <info@promo-deals.xyz>',
    from_domain: 'promo-deals.xyz',
    display_name: 'Marketing',
    subject: 'You have been selected for a special offer!',
    date: new Date().toISOString().slice(0,16).replace('T',' '),
    risk_level: 'MEDIUM_RISK',
    action: 'WARN',
    reasons: ["Sender domain 'promo-deals.xyz' is not in the approved whitelist"],
    flags: {},
    spf_pass: true, dkim_pass: false, dmarc_pass: false,
    in_whitelist: false,
    body_preview: 'Congratulations! You have been selected to receive an exclusive deal. Limited time offer...',
  },
];

function runScan() {
  if (state.scanning) return;
  state.scanning = true;

  const btn = document.querySelector('.btn-primary');
  btn.textContent = '⟳ Scanning…';
  btn.classList.add('scanning');

  setTimeout(() => {
    // Add new email
    const email = { ...NEW_EMAILS[0], uid: `msg-new-${Date.now()}`, date: new Date().toISOString().slice(0,16).replace('T',' ') };
    state.emails.unshift(email);

    btn.textContent = '⚡ Scan Now';
    btn.classList.remove('scanning');
    state.scanning = false;

    updateStats();
    renderEmailList();
    renderBlockedList();
    renderLogs();
    renderAnalytics();
    updateBadges();

    toast(`Scan complete — ${state.emails.length} emails processed, ${state.emails.filter(e=>e.risk_level!=='SAFE').length} flagged.`, 'warning');
  }, 2000);
}

// ══════════════════════════════════════════════════════════
// 10. POLICY MANAGEMENT
// ══════════════════════════════════════════════════════════

function renderWhitelist() {
  const list = document.getElementById('whitelist-list');
  document.getElementById('wl-count').textContent = `${state.whitelist.length} domains`;
  list.innerHTML = state.whitelist.map(d => `
    <div class="whitelist-tag">
      <span>✅ ${escHtml(d)}</span>
      <button class="tag-remove" onclick="removeDomain('${d}')" title="Remove">✕</button>
    </div>
  `).join('');
}

function addDomain() {
  const input = document.getElementById('new-domain-input');
  const domains = input.value.split(',').map(d => d.trim().toLowerCase()).filter(d => d);
  if (!domains.length) return;
  
  const toAdd = domains.filter(d => !state.whitelist.includes(d));
  const toRemove = domains.filter(d => state.whitelist.includes(d));

  if (window.location.protocol === 'file:') {
    if (toAdd.length) toast(`✅ Added temporarily. Save via CLI!`, 'warning');
    if (toRemove.length) toast(`🚫 Removed temporarily. Save via CLI!`, 'warning');
  } else {
    if (toAdd.length) {
      fetch('/api/whitelist/add', { method: 'POST', body: JSON.stringify({domain: toAdd.join(',')}), headers: {'Content-Type': 'application/json'} }).catch(()=>{});
      toast(`✅ Added permanently!`, 'success');
    }
    if (toRemove.length) {
      fetch('/api/whitelist/remove', { method: 'POST', body: JSON.stringify({domain: toRemove.join(',')}), headers: {'Content-Type': 'application/json'} }).catch(()=>{});
      toast(`🚫 Removed permanently!`, 'warning');
    }
  }

  toAdd.forEach(d => { if (!state.whitelist.includes(d)) state.whitelist.push(d); });
  toRemove.forEach(d => { state.whitelist = state.whitelist.filter(existing => existing !== d); });

  input.value = '';
  renderWhitelist();

  // Visually Re-classify emails immediately 
  state.emails = state.emails.map(e => {
    if (toAdd.includes(e.from_domain)) return { ...e, risk_level: 'SAFE', action: 'ALLOW', reasons: [], in_whitelist: true };
    if (toRemove.includes(e.from_domain)) return { ...e, risk_level: 'MEDIUM_RISK', action: 'WARN', reasons: ['Sender domain is not in the approved whitelist'], in_whitelist: false };
    return e;
  });
  
  updateStats(); renderEmailList(); renderBlockedList(); updateBadges(); renderAnalytics();
}

function removeDomain(domain) {
  state.whitelist = state.whitelist.filter(d => d !== domain);
  renderWhitelist();
  if (window.location.protocol === 'file:') {
    toast(`🚫 '${domain}' removed temporarily. Run easy_start.py menu to save permanently!`, 'warning');
  } else {
    fetch('/api/whitelist/remove', { method: 'POST', body: JSON.stringify({domain}), headers: {'Content-Type': 'application/json'} }).catch(()=>{});
    toast(`🚫 '${domain}' permanently removed!`, 'success');
  }
  
  // Visually Re-classify emails immediately
  state.emails = state.emails.map(e => {
    if (e.from_domain === domain) return { ...e, risk_level: 'MEDIUM_RISK', action: 'WARN', reasons: ['Sender domain is not in the approved whitelist'], in_whitelist: false };
    return e;
  });
  
  updateStats(); renderEmailList(); renderBlockedList(); updateBadges(); renderAnalytics();
}

function toggleStrictMode(checkbox) {
  state.strictMode = checkbox.checked;
  document.getElementById('policy-strict').checked = checkbox.checked;
  toast(`Strict mode ${checkbox.checked ? 'enabled 🔒' : 'disabled ⚠️'}`, checkbox.checked ? 'success' : 'warning');

  // Update actions
  state.emails = state.emails.map(e =>
    e.risk_level !== 'SAFE'
      ? { ...e, action: checkbox.checked ? 'BLOCK' : 'WARN' }
      : e
  );
  renderEmailList(); renderBlockedList();
}

function updateSetting(key, value) {
  if (key === 'strict_mode') {
    state.strictMode = value;
    document.getElementById('strict-mode-toggle').checked = value;
    toggleStrictMode({ checked: value });
  } else if (key === 'alert_threshold') {
    state.alertThreshold = value;
    toast(`Alert threshold set to: ${value}`, 'success');
  }
}

// ══════════════════════════════════════════════════════════
// 11. AUDIT LOG
// ══════════════════════════════════════════════════════════

function renderLogs() {
  const tbody = document.getElementById('log-body');
  tbody.innerHTML = state.emails.map(e => `
    <tr>
      <td class="mono">${e.date}</td>
      <td class="mono" style="color:var(--text3)">${e.uid}</td>
      <td>${escHtml(e.display_name || e.from_domain)}</td>
      <td class="mono">${escHtml(e.from_domain)}</td>
      <td>${escHtml(e.subject.slice(0, 50))}${e.subject.length > 50 ? '…' : ''}</td>
      <td><span class="risk-badge risk-${e.risk_level}">${riskLabel(e.risk_level)}</span></td>
      <td style="color:var(--${actionColor(e.action)});font-weight:700">${e.action}</td>
      <td style="color:var(--text3);font-size:11px">${e.reasons[0] ? escHtml(e.reasons[0].slice(0,60)) + '…' : '—'}</td>
    </tr>
  `).join('');
}

function exportCSV() {
  const headers = ['Timestamp','UID','From Domain','Subject','Risk Level','Action','Reasons'];
  const rows = state.emails.map(e => [
    e.date, e.uid, e.from_domain,
    `"${e.subject.replace(/"/g,'""')}"`,
    e.risk_level, e.action,
    `"${e.reasons.join(' | ').replace(/"/g,'""')}"`,
  ]);
  const csv = [headers, ...rows].map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), {
    href: url, download: `domainshield_audit_${new Date().toISOString().slice(0,10)}.csv`
  });
  a.click();
  URL.revokeObjectURL(url);
  toast('✅ Audit log exported as CSV', 'success');
}

// ══════════════════════════════════════════════════════════
// 12. ANALYTICS
// ══════════════════════════════════════════════════════════

function renderAnalytics() {
  renderDonut();
  renderBarList();
  renderSignalGrid();
}

function renderDonut() {
  const total  = state.emails.length || 1;
  const counts = {
    SAFE:        state.emails.filter(e => e.risk_level === 'SAFE').length,
    MEDIUM_RISK: state.emails.filter(e => e.risk_level === 'MEDIUM_RISK').length,
    HIGH_RISK:   state.emails.filter(e => e.risk_level === 'HIGH_RISK').length,
  };
  const colors = { SAFE: '#10b981', MEDIUM_RISK: '#f59e0b', HIGH_RISK: '#ef4444' };
  const labels = { SAFE: 'Safe', MEDIUM_RISK: 'Medium Risk', HIGH_RISK: 'High Risk' };

  const r = 42, cx = 60, cy = 60;
  const circumference = 2 * Math.PI * r;
  let offset = 0;
  let segments = '';

  for (const [key, count] of Object.entries(counts)) {
    const pct = count / total;
    const dash = pct * circumference;
    segments += `<circle
      cx="${cx}" cy="${cy}" r="${r}"
      fill="none"
      stroke="${colors[key]}"
      stroke-width="18"
      stroke-dasharray="${dash} ${circumference - dash}"
      stroke-dashoffset="${-offset}"
      transform="rotate(-90 ${cx} ${cy})"
      opacity="${count === 0 ? 0 : 1}"
    />`;
    offset += dash;
  }

  const pct = Math.round((counts.SAFE / total) * 100);
  segments += `<text x="${cx}" y="${cy}" text-anchor="middle" dominant-baseline="middle"
    fill="white" font-size="13" font-weight="800" font-family="Inter,sans-serif">${pct}%</text>
    <text x="${cx}" y="${cy + 14}" text-anchor="middle" dominant-baseline="middle"
    fill="#8b90a4" font-size="8" font-family="Inter,sans-serif">safe</text>`;

  document.getElementById('donut-svg').innerHTML = segments;

  document.getElementById('donut-legend').innerHTML = Object.entries(counts).map(([key, count]) => `
    <div class="legend-item">
      <div class="legend-dot" style="background:${colors[key]}"></div>
      <span style="color:var(--text2)">${labels[key]}</span>
      <span style="margin-left:auto;font-weight:700">${count}</span>
    </div>
  `).join('');
}

function renderBarList() {
  const blocked = state.emails.filter(e => e.risk_level !== 'SAFE');
  const domainCounts = {};
  blocked.forEach(e => { domainCounts[e.from_domain] = (domainCounts[e.from_domain] || 0) + 1; });
  const sorted = Object.entries(domainCounts).sort((a,b) => b[1]-a[1]).slice(0, 5);
  const maxVal = sorted[0]?.[1] || 1;

  document.getElementById('bar-list').innerHTML = sorted.length
    ? sorted.map(([domain, count]) => `
        <div class="bar-item">
          <div class="bar-label">
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px">${escHtml(domain)}</span>
            <span style="color:var(--danger)">${count}</span>
          </div>
          <div class="bar-track">
            <div class="bar-fill" style="width:${(count/maxVal*100).toFixed(1)}%"></div>
          </div>
        </div>
      `).join('')
    : '<p style="color:var(--text3);font-size:13px">No blocked domains yet.</p>';
}

function renderSignalGrid() {
  const signals = [
    { icon: '🚫', label: 'Whitelist Misses',    count: state.emails.filter(e => !e.in_whitelist).length,             color: 'var(--danger)' },
    { icon: '🎭', label: 'Display Name Spoof',  count: state.emails.filter(e => e.flags?.display_name_spoof).length, color: 'var(--warn)' },
    { icon: '🌐', label: 'Subdomain Spoof',      count: state.emails.filter(e => e.flags?.subdomain_spoof).length,   color: 'var(--warn)' },
    { icon: '🔐', label: 'Auth Failures',        count: state.emails.filter(e => !e.spf_pass || !e.dkim_pass || !e.dmarc_pass).length, color: 'var(--danger)' },
    { icon: '✅', label: 'SPF Pass',             count: state.emails.filter(e => e.spf_pass).length,                 color: 'var(--safe)' },
    { icon: '✅', label: 'DKIM Pass',            count: state.emails.filter(e => e.dkim_pass).length,                color: 'var(--safe)' },
    { icon: '✅', label: 'DMARC Pass',           count: state.emails.filter(e => e.dmarc_pass).length,               color: 'var(--safe)' },
    { icon: '📋', label: 'Total Scanned',        count: state.emails.length,                                          color: 'var(--accent2)' },
  ];

  document.getElementById('signal-grid').innerHTML = signals.map(s => `
    <div class="signal-card">
      <div class="signal-icon">${s.icon}</div>
      <div class="signal-count" style="color:${s.color}">${s.count}</div>
      <div class="signal-name">${s.label}</div>
    </div>
  `).join('');
}

// ══════════════════════════════════════════════════════════
// 13. TOAST
// ══════════════════════════════════════════════════════════

function toast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 300); }, 3500);
}

// ══════════════════════════════════════════════════════════
// 14. UTILS
// ══════════════════════════════════════════════════════════

function escHtml(str) {
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}
