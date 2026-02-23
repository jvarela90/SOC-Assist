/* =====================================================
   SOC Assist — Main JavaScript
   ===================================================== */

// ── Auto-dismiss alerts after 5 seconds ─────────────────
document.addEventListener('DOMContentLoaded', function () {
  const alerts = document.querySelectorAll('.alert-dismissible');
  alerts.forEach(function (alert) {
    setTimeout(function () {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 5000);
  });
});

// ═══════════════════════════════════════════════════════
//  Shared TI Widget — used in form.html and admin.html
// ═══════════════════════════════════════════════════════

window.TIWidget = (function () {

  function verdictBadge(v) {
    const map = {
      'MALICIOSO':      'bg-danger',
      'SOSPECHOSO':     'bg-warning text-dark',
      'LIMPIO':         'bg-success',
      'BLOQUEADO':      'bg-secondary',
      'SIN_RESULTADOS': 'bg-secondary',
      'ERROR':          'bg-danger',
    };
    return `<span class="badge ${map[v] || 'bg-secondary'}">${v}</span>`;
  }

  function renderTiResult(data) {
    if (data.error) {
      return `<div class="alert alert-danger py-2 small">${data.error}</div>`;
    }
    if (data.blocked) {
      return `<div class="alert alert-secondary py-2 small">
        <i class="bi bi-shield-slash me-1"></i><strong>IP Bloqueada:</strong> ${data.block_reason}
      </div>`;
    }

    let html = `<div class="mb-1 d-flex align-items-center gap-2 flex-wrap">
      <strong class="small">${data.indicator}</strong>
      ${verdictBadge(data.summary_verdict)}
    </div>`;

    for (const r of (data.results || [])) {
      html += `<div class="border border-secondary rounded p-2 mb-1" style="font-size:0.73rem;">
        <div class="d-flex justify-content-between align-items-start">
          <strong>${r.source}</strong>${verdictBadge(r.verdict)}
        </div>`;
      if (r.source === 'VirusTotal') {
        html += `<div>Detecciones: <span class="text-danger fw-bold">${r.malicious_votes}</span>/${r.total_engines} motores</div>`;
        if (r.country) html += `<div class="text-muted">${r.country} | ${r.as_owner || 'N/A'}</div>`;
      } else if (r.source === 'AbuseIPDB') {
        html += `<div>Abuso: <span class="text-warning fw-bold">${r.abuse_score}%</span> (${r.total_reports} reportes)</div>`;
        html += `<div class="text-muted">${r.country} | ${r.isp}</div>`;
        if (r.is_tor) html += `<span class="badge bg-danger" style="font-size:0.6rem;">TOR</span>`;
      } else if (r.source === 'IBM X-Force') {
        html += `<div>Risk: <span class="text-warning fw-bold">${r.risk_score}/10</span></div>`;
        if (r.categories && r.categories.length > 0)
          html += `<div class="text-muted">${r.categories.join(', ')}</div>`;
      }
      if (r.raw_url)
        html += `<a href="${r.raw_url}" target="_blank" class="small text-info">Ver fuente ↗</a>`;
      html += `</div>`;
    }

    for (const e of (data.errors || [])) {
      html += `<div class="text-muted small border-start border-secondary ps-2 mb-1">
        <strong>${e.source}:</strong> ${e.error}
      </div>`;
    }

    if (!data.results.length && !data.errors.length) {
      html += `<div class="text-muted small">Sin resultados (claves no configuradas).</div>`;
    }
    return html;
  }

  function renderMacResult(data) {
    if (data.error) {
      return `<div class="alert alert-warning py-2 small">${data.error}</div>`;
    }
    return `<div class="border border-secondary rounded p-2" style="font-size:0.78rem;">
      <div class="d-flex align-items-center gap-2 mb-1 flex-wrap">
        <i class="bi ${data.icon || 'bi-question-circle'} text-info"></i>
        <strong>${data.vendor}</strong>
        <span class="badge bg-dark border border-secondary">${data.category}</span>
        ${data.found
          ? '<span class="badge bg-success">Encontrado</span>'
          : '<span class="badge bg-secondary">No encontrado</span>'}
      </div>
      <div class="text-muted">OUI: <code>${data.oui}</code></div>
    </div>`;
  }

  async function lookupTI(indicatorInputId, typeSelectId, resultElId, loadingElId) {
    const indicator = document.getElementById(indicatorInputId)?.value.trim();
    const type      = document.getElementById(typeSelectId)?.value || 'auto';
    const resultEl  = document.getElementById(resultElId);
    const loadingEl = document.getElementById(loadingElId);
    if (!indicator || !resultEl) return;

    resultEl.style.display = 'none';
    if (loadingEl) loadingEl.style.display = 'block';

    try {
      const resp = await fetch('/api/ti/lookup', {
        method:  'POST',
        headers: {'Content-Type': 'application/json'},
        body:    JSON.stringify({indicator, type}),
      });
      const data = await resp.json();
      resultEl.innerHTML = renderTiResult(data);
    } catch (e) {
      resultEl.innerHTML = `<div class="alert alert-danger py-1 small">Error: ${e.message}</div>`;
    } finally {
      if (loadingEl) loadingEl.style.display = 'none';
      resultEl.style.display = 'block';
    }
  }

  async function lookupMAC(macInputId, resultElId) {
    const mac      = document.getElementById(macInputId)?.value.trim();
    const resultEl = document.getElementById(resultElId);
    if (!mac || !resultEl) return;

    try {
      const resp = await fetch(`/api/mac/lookup?mac=${encodeURIComponent(mac)}`);
      const data = await resp.json();
      resultEl.innerHTML = renderMacResult(data);
      resultEl.style.display = 'block';
    } catch (e) {
      resultEl.innerHTML = `<div class="alert alert-danger py-1 small">Error: ${e.message}</div>`;
      resultEl.style.display = 'block';
    }
  }

  return { verdictBadge, renderTiResult, renderMacResult, lookupTI, lookupMAC };
})();
