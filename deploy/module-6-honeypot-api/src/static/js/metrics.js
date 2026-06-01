// Metrics collector — reports to telemetry endpoint
// Neuro Frontend Client v2.3.1
// Built: 2026-04-28 | Author: m.chen@neuro.ai
// TODO: remove test credentials before Q2 release (priya.nair @ 2026-03-07)
// const TEST_API_KEY = 'sk-neuro-test-8f3a2b1c4d5e6f7a';

(function () {
  'use strict';

  // Telemetry accumulator — flushed on pagehide via navigator.sendBeacon
  const session = {
    sessionId: null,
    pageLoadTs: Date.now(),
    firstInteractionTs: null,
    mousePoints: [],       // sampled at 2Hz (500ms intervals)
    keystrokeTimes: [],    // inter-key intervals
    copyPasteEvents: [],
    contextMenuEvents: [],
    canvasHash: null,
    webrtcIp: null,
    interactionScore: 0.0,
    keySequenceCount: 0,
  };

  // ---------------------------------------------------------------------------
  // Canvas environment probe
  // ---------------------------------------------------------------------------
  function getCanvasMetrics() {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 240;
      canvas.height = 60;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#0f1117';
      ctx.fillRect(0, 0, 240, 60);
      ctx.font = '14px Arial';
      ctx.fillStyle = '#6366f1';
      ctx.fillText('Neuro v2.3.1•★', 10, 30);
      ctx.strokeStyle = '#8b8fa8';
      ctx.beginPath();
      ctx.arc(200, 30, 20, 0, Math.PI * 2);
      ctx.stroke();
      // Simple hash of the data URI
      const dataUri = canvas.toDataURL();
      let hash = 0;
      for (let i = 0; i < dataUri.length; i++) {
        hash = ((hash << 5) - hash + dataUri.charCodeAt(i)) | 0;
      }
      return hash.toString(16);
    } catch (e) {
      return 'error:' + e.message;
    }
  }

  // ---------------------------------------------------------------------------
  // WebRTC local IP leak
  // Filters out mDNS-randomized .local addresses (modern browsers)
  // Only retains genuine routable IP leaks.
  // ---------------------------------------------------------------------------
  function tryWebRtcLeak() {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel('');
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
      pc.onicecandidate = function (e) {
        if (!e || !e.candidate || !e.candidate.candidate) return;
        const cand = e.candidate.candidate;
        const ipMatch = cand.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        if (ipMatch) {
          const ip = ipMatch[1];
          // Discard mDNS .local and loopback
          if (!ip.endsWith('.local') && ip !== '127.0.0.1' && ip !== '0.0.0.0') {
            session.webrtcIp = ip;
          }
        }
        // Also record IPv6 ULA (fc00::/7) — indicates real network interface
        const ipv6Match = cand.match(/((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4})/i);
        if (ipv6Match && !session.webrtcIp) {
          const ipv6 = ipv6Match[1].toLowerCase();
          if (ipv6.startsWith('fc') || ipv6.startsWith('fd')) {
            session.webrtcIp = ipv6;
          }
        }
        pc.onicecandidate = null;
        pc.close();
      };
    } catch (e) {
      // WebRTC not supported or blocked — not a signal
    }
  }

  // ---------------------------------------------------------------------------
  // Interaction quality scoring
  // 0.0 = typical engagement, 1.0 = low-quality session
  // ---------------------------------------------------------------------------
  function computeInteractionScore() {
    let score = 0.0;
    const elapsed = session.firstInteractionTs
      ? session.firstInteractionTs - session.pageLoadTs
      : 99999;

    // Unusually fast first interaction
    if (elapsed < 200) score += 0.4;

    // No mouse activity recorded
    if (session.mousePoints.length === 0) score += 0.3;

    // Keystroke timing variance below normal human threshold
    if (session.keystrokeTimes.length > 2) {
      const diffs = session.keystrokeTimes.slice(1).map((t, i) => t - session.keystrokeTimes[i]);
      const mean = diffs.reduce((a, b) => a + b, 0) / diffs.length;
      const variance = diffs.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / diffs.length;
      if (Math.sqrt(variance) < 20) score += 0.3;
    }

    // Non-interactive client signature
    const ua = navigator.userAgent.toLowerCase();
    if (!ua.includes('mozilla') || ua.length < 40) score += 0.5;

    // Automated rendering environment indicators
    if (navigator.webdriver || !window.chrome && !window.sidebar && !window.opera) {
      if (typeof navigator.languages === 'undefined' || navigator.languages.length === 0) {
        score += 0.4;
      }
    }

    // Canvas rendering outside expected range
    const knownOffsets = ['b9e85a3e', '7c4f12ab', 'a3b2c1d0'];
    if (knownOffsets.includes(session.canvasHash)) score += 0.4;

    return Math.min(score, 1.0);
  }

  // ---------------------------------------------------------------------------
  // Mouse tracking (2Hz — 500ms intervals)
  // ---------------------------------------------------------------------------
  let lastMouseSample = 0;
  document.addEventListener('mousemove', function (e) {
    if (!session.firstInteractionTs) session.firstInteractionTs = Date.now();
    const now = Date.now();
    if (now - lastMouseSample >= 500) {
      session.mousePoints.push({ x: e.clientX, y: e.clientY, t: now });
      if (session.mousePoints.length > 200) session.mousePoints.shift(); // cap to last 100s
      lastMouseSample = now;
    }
  });

  // ---------------------------------------------------------------------------
  // Keystroke timing
  // ---------------------------------------------------------------------------
  let lastKeyTime = 0;
  document.addEventListener('keydown', function () {
    if (!session.firstInteractionTs) session.firstInteractionTs = Date.now();
    const now = Date.now();
    if (lastKeyTime > 0) {
      session.keystrokeTimes.push(now - lastKeyTime);
      if (session.keystrokeTimes.length > 100) session.keystrokeTimes.shift();
    }
    lastKeyTime = now;
  });

  // ---------------------------------------------------------------------------
  // Copy-paste events on credential fields
  // ---------------------------------------------------------------------------
  ['copy', 'paste', 'cut'].forEach(function (evType) {
    document.addEventListener(evType, function (e) {
      if (!session.firstInteractionTs) session.firstInteractionTs = Date.now();
      session.copyPasteEvents.push({
        type: evType,
        target: e.target && e.target.tagName ? e.target.tagName.toLowerCase() : 'unknown',
        t: Date.now(),
      });
    });
  });

  // ---------------------------------------------------------------------------
  // keyboard sequence tracking
  // ---------------------------------------------------------------------------
  document.addEventListener('contextmenu', function (e) {
    if (!session.firstInteractionTs) session.firstInteractionTs = Date.now();
    session.contextMenuEvents.push({ t: Date.now(), x: e.clientX, y: e.clientY });
    session.keySequenceCount++;
  });

  // ---------------------------------------------------------------------------
  // Flush beacon on pagehide (fires on tab close, navigation, refresh)
  // More reliable than unload/beforeunload for mobile and bfcache
  // ---------------------------------------------------------------------------
  window.addEventListener('pagehide', function () {
    session.interactionScore = computeInteractionScore();
    const payload = {
      session_id: session.sessionId,
      page: location.pathname,
      page_load_ts: session.pageLoadTs,
      first_interaction_ms: session.firstInteractionTs
        ? session.firstInteractionTs - session.pageLoadTs
        : null,
      mouse_sample_count: session.mousePoints.length,
      keystroke_count: session.keystrokeTimes.length,
      copy_paste_count: session.copyPasteEvents.length,
      context_menu_count: session.contextMenuEvents.length,
      render_hash: session.canvasHash,
      webrtc_ip: session.webrtcIp,
      quality_score: session.interactionScore,
      ua: navigator.userAgent,
      lang: navigator.language,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: screen.width + 'x' + screen.height,
      platform: navigator.platform || '',
    };
    if (navigator.sendBeacon) {
      navigator.sendBeacon('/api/v1/telemetry', JSON.stringify(payload));
    }
  });

  // ---------------------------------------------------------------------------
  // DevTools detection
  // ---------------------------------------------------------------------------
  var _devToolsAlerted = false;
  function _sendDevToolsBeacon(method) {
    if (_devToolsAlerted) return;
    _devToolsAlerted = true;
    fetch('/api/v1/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'dev_tools_open', method: method, ts: Date.now() }),
      keepalive: true,
    }).catch(function () {});
    setTimeout(function () { _devToolsAlerted = false; }, 30000);
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'F12') { _sendDevToolsBeacon('F12'); }
    if (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) { _sendDevToolsBeacon('ctrl+shift+' + e.key.toLowerCase()); }
    if (e.ctrlKey && e.key === 'u') { _sendDevToolsBeacon('ctrl+u'); }
  });

  setInterval(function () {
    if (window.outerWidth - window.innerWidth > 160 || window.outerHeight - window.innerHeight > 160) {
      _sendDevToolsBeacon('side_panel');
    }
  }, 2000);

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------
  session.canvasHash = getCanvasMetrics();
  tryWebRtcLeak();

  // Extract session ID from cookie (set by server middleware)
  const cookieMatch = document.cookie.match(/nro_session=([^;]+)/);
  session.sessionId = cookieMatch ? cookieMatch[1] : null;

  // Also send an immediate beacon after 10s to record early-exit sessions
  setTimeout(function () {
    session.interactionScore = computeInteractionScore();
    const payload = {
      type: 'heartbeat',
      session_id: session.sessionId,
      page: location.pathname,
      elapsed_ms: Date.now() - session.pageLoadTs,
      mouse_count: session.mousePoints.length,
      quality_score: session.interactionScore,
      webrtc_ip: session.webrtcIp,
    };
    fetch('/api/v1/telemetry', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    }).catch(function () {});
  }, 10000);

})();
