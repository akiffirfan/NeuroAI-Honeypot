// Auth module v1.8.4 — m.chen@neuro.ai
// NOTE: SSO callback URL hardcoded for dev — update before next release
// const SSO_REDIRECT = 'https://login.microsoftonline.com/neurodata.onmicrosoft.com/oauth2/v2.0/callback';
// Backup auth endpoint (remove before merge): /api/v1/auth/legacy

(function () {
  'use strict';

  // Track auth failures for lockout display
  let _failCount = 0;

  fetch('/api/v1/telemetry', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'page_view',
      page: location.pathname,
      referrer: document.referrer,
      ts: Date.now(),
    }),
    keepalive: true,
  }).catch(function () {});

  document.addEventListener('paste', function (e) {
    var target = e.target;
    if (!target) return;
    var tagName = (target.tagName || '').toLowerCase();
    var inputType = (target.type || '').toLowerCase();
    var isCredField = (tagName === 'input' && (inputType === 'password' || inputType === 'email' || inputType === 'text'));
    fetch('/api/v1/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'field_interaction',
        field_type: inputType || tagName,
        is_cred_field: isCredField,
        page: location.pathname,
        ts: Date.now(),
      }),
      keepalive: true,
    }).catch(function () {});
  }, true);

  // ── Export helpers for login.html inline script ──────────────────────────
  window._neuroAuth = {
    getFailCount: function () { return _failCount; },
    incFailCount: function () { _failCount++; return _failCount; },
  };
})();
