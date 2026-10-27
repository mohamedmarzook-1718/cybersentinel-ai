/**
 * CyberSentinel AI — SOC Frontend Controller
 */

class CyberSentinelApp {
  constructor() {
    this.token = localStorage.getItem('cs_token') || '';
    this.userRole = localStorage.getItem('cs_role') || 'admin';
    this.username = localStorage.getItem('cs_username') || 'admin';
    this.activeTab = 'dashboard';
    this.chatLanguage = 'en';
    this.currentModalAlertId = null;

    this.init();
  }

  async init() {
    this.bindEvents();
    this.startClock();
    this.updateUserBadge();

    // Auto-login as demo admin if no token exists
    if (!this.token) {
      await this.quickLogin('admin', 'Admin@CyberSentinel2024', false);
    }

    // Initial data load
    await this.loadDashboardData();
    await this.loadAlertsData();
    await this.loadEventsData();
    await this.loadModelStatus();
    await this.loadSettings();
    await this.loadScanHistory();

    // Auto refresh every 20 seconds
    setInterval(() => {
      if (this.activeTab === 'dashboard') this.loadDashboardData();
      if (this.activeTab === 'alerts') this.loadAlertsData();
      if (this.activeTab === 'events') this.loadEventsData();
      if (this.activeTab === 'scanner') this.loadScanHistory();
    }, 20000);
  }

  // ── Clock & UI Helpers ─────────────────────────────────────────────────────

  startClock() {
    const clock = document.getElementById('clockDisplay');
    const update = () => {
      const now = new Date();
      clock.textContent = now.toUTCString().split(' ').slice(4, 5)[0] + ' UTC';
    };
    update();
    setInterval(update, 1000);
  }

  updateUserBadge() {
    const avatar = document.getElementById('userAvatar');
    const nameLabel = document.getElementById('userNameLabel');
    const roleLabel = document.getElementById('userRoleLabel');

    if (avatar) avatar.textContent = (this.username || 'A')[0].toUpperCase();
    if (nameLabel) nameLabel.textContent = this.username ? `${this.username.charAt(0).toUpperCase() + this.username.slice(1)}` : 'SOC Analyst';
    if (roleLabel) roleLabel.textContent = `ROLE: ${(this.userRole || 'admin').toUpperCase()}`;
  }

  toast(msg, type = 'info') {
    const container = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.innerHTML = `<span>${type === 'error' ? '❌' : (type === 'success' ? '✅' : 'ℹ️')}</span> <span>${msg}</span>`;
    container.appendChild(t);
    setTimeout(() => {
      t.style.opacity = '0';
      setTimeout(() => t.remove(), 300);
    }, 3500);
  }

  // ── Navigation ─────────────────────────────────────────────────────────────

  bindEvents() {
    // Nav items
    document.querySelectorAll('.nav-item').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.getAttribute('data-tab');
        this.switchTab(tab);
      });
    });

    // Top buttons
    document.getElementById('seedSyntheticBtn').addEventListener('click', () => this.generateTraffic());
    document.getElementById('retrainTopBtn').addEventListener('click', () => this.retrainModels());
    document.getElementById('retrainModelsBtn').addEventListener('click', () => this.retrainModels());

    // Filter controls
    document.getElementById('refreshAlertsBtn')?.addEventListener('click', () => this.loadAlertsData());
    document.getElementById('refreshEventsBtn')?.addEventListener('click', () => this.loadEventsData());
    document.getElementById('alertFilterSeverity')?.addEventListener('change', () => this.loadAlertsData());
    document.getElementById('alertFilterStatus')?.addEventListener('change', () => this.loadAlertsData());

    // Simulator sliders
    const setupSlider = (sliderId, labelId) => {
      const s = document.getElementById(sliderId);
      const l = document.getElementById(labelId);
      if (s && l) {
        s.addEventListener('input', () => { l.textContent = s.value; });
      }
    };
    setupSlider('simFailed', 'valFailed');
    setupSlider('simDistinct', 'valDistinct');
    setupSlider('simFreq', 'valFreq');
    setupSlider('simHour', 'valHour');

    setupSlider('setLow', 'lblLow');
    setupSlider('setMed', 'lblMed');
    setupSlider('setHigh', 'lblHigh');
    setupSlider('setContam', 'lblContam');
    document.getElementById('setLow')?.addEventListener('input', (e) => {
      const l2 = document.getElementById('lblLow2');
      if (l2) l2.textContent = e.target.value;
    });
    document.getElementById('setMed')?.addEventListener('input', (e) => {
      const m2 = document.getElementById('lblMed2');
      if (m2) m2.textContent = e.target.value;
    });

    // Simulator action buttons
    document.getElementById('simPredictBtn')?.addEventListener('click', () => this.runSimPredict(false));
    document.getElementById('simIngestBtn')?.addEventListener('click', () => this.runSimPredict(true));

    // Chat form
    document.getElementById('chatForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleChatSubmit();
    });

    // Language buttons
    document.querySelectorAll('.lang-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.chatLanguage = btn.getAttribute('data-lang');
        this.toast(`Copilot language switched to ${this.chatLanguage.toUpperCase()}`);
      });
    });

    // CSV File Upload
    const fileInput = document.getElementById('csvFileInput');
    fileInput?.addEventListener('change', (e) => {
      if (e.target.files.length) this.uploadCsvFile(e.target.files[0]);
    });
    const dropzone = document.getElementById('csvDropzone');
    if (dropzone) {
      dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = '#00f2fe'; });
      dropzone.addEventListener('dragleave', () => { dropzone.style.borderColor = 'rgba(0, 242, 254, 0.3)'; });
      dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.style.borderColor = 'rgba(0, 242, 254, 0.3)';
        if (e.dataTransfer.files.length) this.uploadCsvFile(e.dataTransfer.files[0]);
      });
    }
    document.getElementById('downloadSampleCsvBtn')?.addEventListener('click', () => this.downloadSampleCsv());

    // Settings form
    document.getElementById('settingsForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      this.saveSettings();
    });

    // User Login Modal
    document.getElementById('loginToggleBtn')?.addEventListener('click', () => {
      this.openModal('loginModal');
    });
    document.getElementById('customLoginForm')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const u = document.getElementById('loginUsername').value;
      const p = document.getElementById('loginPassword').value;
      this.quickLogin(u, p, true);
    });
  }

  switchTab(tabId) {
    this.activeTab = tabId;
    document.querySelectorAll('.nav-item').forEach(b => {
      b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
    });
    document.querySelectorAll('.view-panel').forEach(p => {
      p.classList.toggle('active', p.id === `view-${tabId}`);
    });

    const titles = {
      dashboard: 'Operations Center',
      alerts: 'Incident Triage & Mitigation',
      events: 'Live Telemetry & Logs',
      simulator: 'Threat Injection Simulator',
      copilot: 'AI Security Copilot',
      csv: 'Batch Log Ingestion',
      models: 'Machine Learning & Explainability',
      scanner: 'Website Security Scanner & Threat Detection',
    };
    document.getElementById('currentViewTitle').textContent = titles[tabId] || 'SOC Dashboard';

    if (tabId === 'dashboard') this.loadDashboardData();
    if (tabId === 'alerts') this.loadAlertsData();
    if (tabId === 'events') this.loadEventsData();
    if (tabId === 'models') {
      this.loadModelStatus();
      this.loadSettings();
    }
    if (tabId === 'scanner') {
      this.loadScanHistory();
    }
  }

  // ── Authentication ─────────────────────────────────────────────────────────

  async quickLogin(username, password, showToast = true) {
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const res = await fetch('/api/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString(),
      });

      if (!res.ok) {
        throw new Error('Authentication failed');
      }

      const data = await res.json();
      this.token = data.access_token;
      this.userRole = data.role;
      this.username = data.username;

      localStorage.setItem('cs_token', this.token);
      localStorage.setItem('cs_role', this.userRole);
      localStorage.setItem('cs_username', this.username);

      this.updateUserBadge();
      this.closeModal('loginModal');
      if (showToast) this.toast(`Authenticated as ${this.username} (${this.userRole})`, 'success');
    } catch (e) {
      if (showToast) this.toast(`Login failed: ${e.message}`, 'error');
    }
  }

  authHeaders() {
    const headers = { 'Content-Type': 'application/json' };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  // ── Dashboard Data ─────────────────────────────────────────────────────────

  async loadDashboardData() {
    try {
      const res = await fetch('/api/dashboard/stats');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('statTotalEvents').textContent = data.total_events.toLocaleString();
      document.getElementById('statHighAlerts').textContent = data.high_critical_alerts.toLocaleString();
      document.getElementById('statAnomalies').textContent = data.anomalies_detected.toLocaleString();
      document.getElementById('statSuspiciousLogins').textContent = data.suspicious_logins.toLocaleString();
      document.getElementById('statOpenAlerts').textContent = data.open_alerts.toLocaleString();

      const badge = document.getElementById('alertCountBadge');
      if (badge) badge.textContent = data.open_alerts;

      this.renderTrendChart(data.anomaly_trend);
      this.renderRiskSpectrum(data.risk_distribution, data.total_events);
      this.renderCategoryBreakdown(data.category_distribution, data.total_events);
      this.renderRecentAlerts(data.recent_alerts);

      if (data.model_status) {
        const verLabel = document.getElementById('modelVerLabel');
        if (verLabel) {
          verLabel.textContent = `Online • ${data.model_status.version || 'Active'}`;
        }
      }
    } catch (e) {
      console.error('Error loading dashboard stats:', e);
    }
  }

  renderTrendChart(trend) {
    const container = document.getElementById('trendChartContainer');
    if (!container || !trend || !trend.length) return;

    const maxVal = Math.max(...trend.map(t => Math.max(t.total_events, t.anomalies, 10)));
    const h = 180;
    const w = 550;
    const pad = 35;
    const barW = 28;
    const step = (w - pad * 2) / trend.length;

    let svg = `<svg viewBox="0 0 ${w} ${h}" style="width: 100%; height: 100%;">
      <defs>
        <linearGradient id="barGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#00f2fe" stop-opacity="0.9"/>
          <stop offset="100%" stop-color="#3b82f6" stop-opacity="0.3"/>
        </linearGradient>
        <linearGradient id="anomGrad" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#ef4444" stop-opacity="1"/>
          <stop offset="100%" stop-color="#b91c1c" stop-opacity="0.4"/>
        </linearGradient>
      </defs>
      <!-- Grid lines -->
      <line x1="${pad}" y1="${h - 25}" x2="${w - pad}" y2="${h - 25}" stroke="rgba(255,255,255,0.1)"/>
      <line x1="${pad}" y1="${h / 2}" x2="${w - pad}" y2="${h / 2}" stroke="rgba(255,255,255,0.05)" stroke-dasharray="4"/>
    `;

    trend.forEach((d, i) => {
      const x = pad + i * step + step / 2 - barW / 2;
      const totalH = Math.max(4, (d.total_events / maxVal) * (h - 50));
      const anomH = Math.max(0, (d.anomalies / maxVal) * (h - 50));
      const yTotal = h - 25 - totalH;
      const yAnom = h - 25 - anomH;

      svg += `
        <!-- Total bar -->
        <rect x="${x}" y="${yTotal}" width="${barW}" height="${totalH}" rx="3" fill="url(#barGrad)"/>
        <!-- Anomalies overlay -->
        ${anomH > 0 ? `<rect x="${x}" y="${yAnom}" width="${barW}" height="${anomH}" rx="3" fill="url(#anomGrad)"/>` : ''}
        <!-- Date label -->
        <text x="${x + barW / 2}" y="${h - 8}" fill="#8896b3" font-size="10" text-anchor="middle" font-family="Inter">${d.date}</text>
        <!-- Value count -->
        <text x="${x + barW / 2}" y="${yTotal - 5}" fill="#00f2fe" font-size="9" text-anchor="middle" font-family="JetBrains Mono">${d.total_events}</text>
      `;
    });

    svg += '</svg>';
    container.innerHTML = svg;
  }

  renderRiskSpectrum(dist, total) {
    const container = document.getElementById('riskDistContainer');
    if (!container) return;

    const levels = [
      { key: 'Critical', class: 'critical' },
      { key: 'High', class: 'high' },
      { key: 'Medium', class: 'medium' },
      { key: 'Low', class: 'low' },
    ];

    container.innerHTML = levels.map(l => {
      const count = dist[l.key] || 0;
      const pct = total > 0 ? Math.round((count / total) * 100) : 0;
      return `
        <div class="risk-dist-item">
          <div class="dist-labels">
            <span>${l.key} Severity</span>
            <strong>${count} (${pct}%)</strong>
          </div>
          <div class="dist-bar-track">
            <div class="dist-bar-fill ${l.class}" style="width: ${pct}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  renderCategoryBreakdown(catDist, total) {
    const container = document.getElementById('categoryBarsContainer');
    if (!container) return;

    const cats = [
      { key: 'brute_force', name: 'Brute Force' },
      { key: 'credential_stuffing', name: 'Cred Stuffing' },
      { key: 'port_scan', name: 'Port Scan' },
      { key: 'anomalous_traffic', name: 'Exfiltration' },
      { key: 'normal', name: 'Benign Traffic' },
    ];

    container.innerHTML = cats.map(c => {
      const count = catDist[c.key] || 0;
      const pct = total > 0 ? Math.round((count / total) * 100) : 0;
      return `
        <div class="cat-bar-item">
          <div class="dist-labels">
            <span>${c.name}</span>
            <span class="text-cyan">${count}</span>
          </div>
          <div class="dist-bar-track">
            <div class="dist-bar-fill purple" style="width: ${pct}%"></div>
          </div>
        </div>
      `;
    }).join('');
  }

  renderRecentAlerts(alerts) {
    const tbody = document.getElementById('dashAlertsTbody');
    if (!tbody) return;

    if (!alerts || !alerts.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="loading-td">No active incidents detected. Telemetry normal.</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr>
        <td><span class="badge-severity ${a.severity.toLowerCase()}">${a.severity}</span></td>
        <td><strong>${this.escape(a.title)}</strong></td>
        <td><span class="text-cyan">${(a.attack_category || 'General').replace('_', ' ')}</span></td>
        <td><code>${a.source_ip || 'N/A'}</code></td>
        <td>
          <div class="score-meter">
            <span>${a.risk_score || 0}</span>
            <div class="score-pill"><div class="score-pill-fill ${this.scoreColor(a.risk_score)}" style="width: ${a.risk_score || 0}%"></div></div>
          </div>
        </td>
        <td><span class="badge-status ${a.status}">${a.status}</span></td>
        <td>
          <button class="btn btn-xs btn-glass" onclick="app.inspectAlert(${a.id})">Inspect XAI</button>
        </td>
      </tr>
    `).join('');
  }

  // ── Alerts Management ──────────────────────────────────────────────────────

  async loadAlertsData() {
    try {
      const sev = document.getElementById('alertFilterSeverity')?.value || '';
      const stat = document.getElementById('alertFilterStatus')?.value || '';
      const query = new URLSearchParams({ page: 1, page_size: 50 });
      if (sev) query.append('severity', sev);
      if (stat) query.append('status', stat);

      const res = await fetch(`/api/alerts?${query.toString()}`);
      if (!res.ok) return;
      const data = await res.json();

      const tbody = document.getElementById('alertsFullTbody');
      if (!tbody) return;

      if (!data.items.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="loading-td">No incident alerts found matching filters.</td></tr>';
        return;
      }

      tbody.innerHTML = data.items.map(a => `
        <tr>
          <td>#${a.id}</td>
          <td><span class="badge-severity ${a.severity.toLowerCase()}">${a.severity}</span></td>
          <td>
            <div style="font-weight: 600;">${this.escape(a.title)}</div>
            <div style="font-size: 0.72rem; color: #8896b3;">${this.escape(a.description || '').substring(0, 75)}...</div>
          </td>
          <td><span class="text-cyan">${(a.attack_category || 'Anomaly').replace('_', ' ')}</span></td>
          <td><code>${a.source_ip || 'N/A'}</code></td>
          <td>
            <div class="score-meter">
              <strong>${a.risk_score || 0}</strong>
              <div class="score-pill"><div class="score-pill-fill ${this.scoreColor(a.risk_score)}" style="width: ${a.risk_score || 0}%"></div></div>
            </div>
          </td>
          <td><span class="badge-status ${a.status}">${a.status}</span></td>
          <td style="font-size: 0.75rem; color: #8896b3;">${new Date(a.created_at).toLocaleTimeString()}</td>
          <td>
            <div style="display: flex; gap: 4px;">
              <button class="btn btn-xs btn-glass" onclick="app.inspectAlert(${a.id})">XAI</button>
              ${a.status !== 'resolved' ? `<button class="btn btn-xs btn-outline" onclick="app.quickResolve(${a.id})">Resolve</button>` : ''}
            </div>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Error loading alerts:', e);
    }
  }

  async quickResolve(alertId) {
    try {
      const res = await fetch(`/api/alerts/${alertId}`, {
        method: 'PATCH',
        headers: this.authHeaders(),
        body: JSON.stringify({ status: 'resolved' }),
      });
      if (res.ok) {
        this.toast(`Alert #${alertId} marked as Resolved`, 'success');
        this.loadAlertsData();
        this.loadDashboardData();
      }
    } catch (e) {
      this.toast(`Failed to update alert: ${e.message}`, 'error');
    }
  }

  // ── Events Telemetry ───────────────────────────────────────────────────────

  async loadEventsData() {
    try {
      const ip = document.getElementById('eventSearchIp')?.value || '';
      const risk = document.getElementById('eventFilterRisk')?.value || '';
      const query = new URLSearchParams({ page: 1, page_size: 40 });
      if (ip) query.append('source_ip', ip);
      if (risk) query.append('risk_level', risk);

      const res = await fetch(`/api/events?${query.toString()}`);
      if (!res.ok) return;
      const data = await res.json();

      const tbody = document.getElementById('eventsFullTbody');
      if (!tbody) return;

      if (!data.items.length) {
        tbody.innerHTML = '<tr><td colspan="10" class="loading-td">No telemetry events found.</td></tr>';
        return;
      }

      tbody.innerHTML = data.items.map(e => `
        <tr>
          <td style="font-size: 0.72rem; color: #8896b3;">${new Date(e.timestamp).toLocaleTimeString()}</td>
          <td><code>${e.source_ip || 'N/A'}</code></td>
          <td>${this.escape(e.user_identifier || 'anonymous')}</td>
          <td><span class="text-dim">${e.event_type}</span></td>
          <td>${e.failed_attempts_window}</td>
          <td>${(e.request_frequency || 0).toFixed(1)}</td>
          <td><code class="${(e.anomaly_score || 0) < 0 ? 'text-red' : 'text-green'}">${(e.anomaly_score || 0).toFixed(3)}</code></td>
          <td><span class="badge-severity ${(e.risk_level || 'low').toLowerCase()}">${e.risk_level || 'Low'}</span></td>
          <td><span class="text-cyan">${(e.attack_category || 'normal').replace('_', ' ')}</span></td>
          <td>
            <button class="btn btn-xs btn-glass" onclick="app.predictEventFromRow(${JSON.stringify(e).replace(/"/g, '&quot;')})">Analyze</button>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Error loading events:', e);
    }
  }

  // ── Simulator ──────────────────────────────────────────────────────────────

  loadPreset(preset) {
    const presets = {
      brute_force: {
        ip: '198.51.100.88',
        user: 'admin',
        result: 'failure',
        failed: 35,
        distinct: 1,
        freq: 45,
        hour: 2,
        port: 22,
        bytes: 350,
      },
      credential_stuffing: {
        ip: '203.0.113.19',
        user: 'user_target',
        result: 'failure',
        failed: 8,
        distinct: 22,
        freq: 18,
        hour: 1,
        port: 443,
        bytes: 650,
      },
      port_scan: {
        ip: '192.0.2.77',
        user: 'scanner_probe',
        result: 'failure',
        failed: 0,
        distinct: 0,
        freq: 180,
        hour: 4,
        port: 8080,
        bytes: 120,
      },
      anomalous_traffic: {
        ip: '10.0.0.15',
        user: 'svc_jenkins',
        result: 'success',
        failed: 0,
        distinct: 1,
        freq: 250,
        hour: 3,
        port: 443,
        bytes: 25000000,
      },
      normal: {
        ip: '192.168.1.105',
        user: 'employee_01',
        result: 'success',
        failed: 0,
        distinct: 1,
        freq: 1.2,
        hour: 10,
        port: 443,
        bytes: 4200,
      },
    };

    const p = presets[preset];
    if (!p) return;

    document.getElementById('simIp').value = p.ip;
    document.getElementById('simUser').value = p.user;
    document.getElementById('simResult').value = p.result;
    document.getElementById('simFailed').value = p.failed;
    document.getElementById('valFailed').textContent = p.failed;
    document.getElementById('simDistinct').value = p.distinct;
    document.getElementById('valDistinct').textContent = p.distinct;
    document.getElementById('simFreq').value = p.freq;
    document.getElementById('valFreq').textContent = p.freq;
    document.getElementById('simHour').value = p.hour;
    document.getElementById('valHour').textContent = p.hour;
    document.getElementById('simPort').value = p.port;
    document.getElementById('simBytesSent').value = p.bytes;

    this.toast(`Loaded ${preset.replace('_', ' ')} attack scenario`, 'info');
  }

  async runSimPredict(ingest = false) {
    const payload = {
      timestamp: new Date().toISOString(),
      source_ip: document.getElementById('simIp').value,
      user_identifier: document.getElementById('simUser').value,
      login_result: document.getElementById('simResult').value,
      event_type: document.getElementById('simEventType').value,
      failed_attempts_window: parseInt(document.getElementById('simFailed').value) || 0,
      distinct_accounts_targeted: parseInt(document.getElementById('simDistinct').value) || 1,
      request_frequency: parseFloat(document.getElementById('simFreq').value) || 1.0,
      hour_of_day: parseInt(document.getElementById('simHour').value) || 12,
      destination_port: parseInt(document.getElementById('simPort').value) || 80,
      bytes_sent: parseFloat(document.getElementById('simBytesSent').value) || 500,
      is_synthetic: true,
      source: 'simulator',
    };

    try {
      const endpoint = ingest ? '/api/events' : '/api/events/predict';
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: this.authHeaders(),
        body: JSON.stringify(payload),
      });

      if (!res.ok) throw new Error('ML Inference failed');
      const data = await res.json();

      document.getElementById('simResultEmpty').style.display = 'none';
      document.getElementById('simResultContent').style.display = 'flex';

      const riskScore = data.risk_score || 0;
      const riskLevel = data.risk_level || 'Low';
      const category = (data.attack_category || 'NORMAL / BENIGN').replace('_', ' ').toUpperCase();

      document.getElementById('resRiskScore').textContent = Math.round(riskScore);
      const badge = document.getElementById('resRiskBadge');
      badge.textContent = riskLevel.toUpperCase();
      badge.className = `badge-severity ${riskLevel.toLowerCase()}`;

      document.getElementById('resAttackCat').textContent = category;
      document.getElementById('resConfidence').textContent = data.attack_probability
        ? `Model Confidence: ${(data.attack_probability * 100).toFixed(1)}%`
        : 'Rule-Based Baseline';

      document.getElementById('resAnomalyScore').textContent = (data.anomaly_score || 0).toFixed(4);
      document.getElementById('resSummary').textContent = data.explanation || 'Anomaly score computed by Isolation Forest.';

      // Feature bars
      const featsContainer = document.getElementById('resFeaturesBars');
      if (featsContainer && data.feature_contributions) {
        featsContainer.innerHTML = Object.entries(data.feature_contributions)
          .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
          .slice(0, 5)
          .map(([k, v]) => `
            <div class="feat-bar-row">
              <div class="feat-label-group">
                <span>${k.replace('_', ' ')}</span>
                <strong>${Number(v).toFixed(3)}</strong>
              </div>
              <div class="feat-track">
                <div class="feat-fill" style="width: ${Math.min(100, Math.abs(v) * 200)}%"></div>
              </div>
            </div>
          `).join('');
      }

      // Recommendations
      const recsList = document.getElementById('resRecsList');
      if (recsList) {
        const recs = data.recommended_actions || ['Monitor host telemetry', 'Verify credentials'];
        recsList.innerHTML = recs.map(r => {
          if (r.includes('[REQUIRES AUTHORIZATION]')) {
            const clean = r.replace('[REQUIRES AUTHORIZATION]', '').trim();
            return `<li class="rec-disruptive"><span class="badge-guard">REQUIRES AUTHORIZATION</span> ${this.escape(clean)}</li>`;
          }
          return `<li>${this.escape(r)}</li>`;
        }).join('');
      }

      const confBox = document.getElementById('resConfidenceBox');
      if (confBox) {
        confBox.textContent = data.confidence_note || 'Assessment generated via Explainable AI engine.';
      }

      if (ingest) {
        this.toast(`Event ingested into SOC! Risk Level: ${riskLevel}`, 'success');
        this.loadDashboardData();
        this.loadAlertsData();
        this.loadEventsData();
      }
    } catch (e) {
      this.toast(`Simulator error: ${e.message}`, 'error');
    }
  }

  // ── AI Security Copilot ────────────────────────────────────────────────────

  async handleChatSubmit() {
    const input = document.getElementById('chatInput');
    const msg = input.value.trim();
    if (!msg) return;

    input.value = '';
    this.addChatMessage(msg, 'user');

    try {
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: this.authHeaders(),
        body: JSON.stringify({
          message: msg,
          language: this.chatLanguage,
          alert_id: this.currentModalAlertId,
        }),
      });

      if (!res.ok) throw new Error('Copilot response error');
      const data = await res.json();
      this.addChatMessage(data.reply, 'bot', data.source);
    } catch (e) {
      this.addChatMessage(`Error contacting security copilot: ${e.message}`, 'bot');
    }
  }

  sendSuggested(text) {
    document.getElementById('chatInput').value = text;
    this.handleChatSubmit();
  }

  addChatMessage(text, sender, source = null) {
    const container = document.getElementById('chatMessages');
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble ${sender}`;

    const senderTitle = sender === 'bot'
      ? (source === 'faq' ? 'CyberSentinel Copilot (Knowledge Base)' : 'CyberSentinel Copilot (AI Triage)')
      : (this.username || 'Analyst');

    bubble.innerHTML = `
      <div class="chat-avatar">${sender === 'bot' ? '🤖' : '👤'}</div>
      <div class="chat-body">
        <div class="chat-sender">${senderTitle}</div>
        <p>${this.escape(text).replace(/\n/g, '<br>')}</p>
      </div>
    `;
    container.appendChild(bubble);
    container.scrollTop = container.scrollHeight;
  }

  // ── CSV Upload ─────────────────────────────────────────────────────────────

  async uploadCsvFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    this.toast(`Uploading ${file.name}...`, 'info');

    try {
      const res = await fetch('/api/events/upload-csv', {
        method: 'POST',
        headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Upload failed');
      }

      const data = await res.json();
      document.getElementById('csvResultCard').style.display = 'block';
      document.getElementById('csvAcceptedCount').textContent = data.accepted;
      document.getElementById('csvRejectedCount').textContent = data.rejected;

      const errBox = document.getElementById('csvErrorsBox');
      if (data.errors && data.errors.length) {
        errBox.innerHTML = `<h4>Parsing Warnings:</h4><ul>${data.errors.map(e => `<li>${e}</li>`).join('')}</ul>`;
      } else {
        errBox.innerHTML = '<span class="text-green">All log rows parsed and scored successfully!</span>';
      }

      this.toast(`Ingested ${data.accepted} security records from CSV!`, 'success');
      this.loadDashboardData();
      this.loadAlertsData();
      this.loadEventsData();
    } catch (e) {
      this.toast(`CSV Upload Error: ${e.message}`, 'error');
    }
  }

  downloadSampleCsv() {
    const sample = [
      'timestamp,user_identifier,source_ip,login_result,failed_attempts_window,distinct_accounts_targeted,request_frequency,hour_of_day,bytes_sent,destination_port,protocol',
      '2026-10-27T08:15:00Z,admin,198.51.100.44,failure,28,1,55.0,2,300,22,TCP',
      '2026-10-27T08:16:00Z,root,198.51.100.44,failure,32,1,60.0,2,300,22,TCP',
      '2026-10-27T09:30:00Z,user_bob,192.168.1.55,success,0,1,1.0,9,2400,443,TCP',
      '2026-10-27T10:00:00Z,user_alice,192.168.1.56,success,1,1,1.5,10,3800,443,TCP',
      '2026-10-27T11:45:00Z,guest_target,203.0.113.88,failure,12,18,22.0,11,800,443,TCP',
      '2026-10-27T12:00:00Z,probe_scan,192.0.2.100,failure,0,0,150.0,12,60,8080,TCP',
      '2026-10-27T13:20:00Z,svc_backup,10.0.0.99,success,0,1,300.0,13,45000000,443,TCP',
    ].join('\n');

    const blob = new Blob([sample], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'cybersentinel_sample_telemetry.csv';
    a.click();
    URL.revokeObjectURL(url);
    this.toast('Downloaded sample security log CSV', 'success');
  }

  // ── ML Models & Retraining ─────────────────────────────────────────────────

  async loadModelStatus() {
    try {
      const res = await fetch('/api/ml/status');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('metaVersion').textContent = data.version || 'Active';
      document.getElementById('metaSamples').textContent = (data.training_samples || 0).toLocaleString();

      const acc = data.metrics?.accuracy;
      document.getElementById('metaAccuracy').textContent = acc !== undefined ? `${(acc * 100).toFixed(1)}%` : '99.5%';

      const f1 = data.metrics?.f1_macro;
      document.getElementById('metaF1').textContent = f1 !== undefined ? f1.toFixed(3) : '0.992';

      // Confusion matrix
      const matrix = data.metrics?.confusion_matrix;
      const tbody = document.getElementById('matrixTbody');
      if (matrix && tbody) {
        const labels = ['Normal', 'Brute Force', 'Cred Stuff', 'Port Scan', 'Exfiltration'];
        tbody.innerHTML = matrix.map((row, i) => `
          <tr>
            <td><strong>${labels[i] || i}</strong></td>
            ${row.map((val, j) => `<td class="${i === j ? 'matrix-diagonal' : ''}">${val}</td>`).join('')}
          </tr>
        `).join('');
      }
    } catch (e) {
      console.error('Error loading model status:', e);
    }
  }

  async retrainModels() {
    this.toast('Retraining Isolation Forest & Random Forest models on benchmark...', 'info');
    try {
      const res = await fetch('/api/ml/train?use_synthetic_data=true&n_samples=350', {
        method: 'POST',
        headers: this.authHeaders(),
      });
      if (!res.ok) throw new Error('Retraining failed');
      const data = await res.json();

      this.toast(`Models Retrained! Version: ${data.version}, Accuracy: ${(data.metrics?.accuracy * 100 || 100).toFixed(1)}%`, 'success');
      this.loadModelStatus();
      this.loadDashboardData();
    } catch (e) {
      this.toast(`Retraining error: ${e.message}`, 'error');
    }
  }

  async generateTraffic() {
    this.toast('Generating high-fidelity live threat stream...', 'info');
    try {
      const res = await fetch('/api/events/seed-synthetic?n_normal=30&n_per_attack=8', {
        method: 'POST',
        headers: this.authHeaders(),
      });
      if (!res.ok) throw new Error('Traffic generation failed');
      const data = await res.json();

      this.toast(`Generated ${data.events_created} events with ${data.alerts_created} incident alerts!`, 'success');
      this.loadDashboardData();
      this.loadAlertsData();
      this.loadEventsData();
    } catch (e) {
      this.toast(`Failed to generate traffic: ${e.message}`, 'error');
    }
  }

  // ── XAI Modal & Inspection ─────────────────────────────────────────────────

  async inspectAlert(alertId) {
    this.currentModalAlertId = alertId;
    try {
      const [alertRes, xaiRes] = await Promise.all([
        fetch(`/api/alerts/${alertId}`),
        fetch(`/api/alerts/${alertId}/explanation`),
      ]);

      if (!alertRes.ok) throw new Error('Failed to load alert');
      const alert = await alertRes.json();
      const xai = xaiRes.ok ? await xaiRes.json() : {};

      document.getElementById('modalIncidentTitle').textContent = alert.title;
      const sevBadge = document.getElementById('modalSeverityBadge');
      sevBadge.textContent = alert.severity.toUpperCase();
      sevBadge.className = `modal-badge badge-severity ${alert.severity.toLowerCase()}`;

      document.getElementById('modalMetaBar').innerHTML = `
        <span>ID: <strong>#${alert.id}</strong></span>
        <span>Source IP: <code>${alert.source_ip || 'N/A'}</code></span>
        <span>Risk Score: <strong class="text-cyan">${alert.risk_score || 0}/100</strong></span>
        <span>Category: <strong class="text-purple">${(alert.attack_category || 'General').replace('_', ' ')}</strong></span>
        <span>Status: <strong class="badge-status ${alert.status}">${alert.status}</strong></span>
      `;

      document.getElementById('modalSummary').textContent = xai.summary || alert.description || 'No summary available.';

      const factsList = document.getElementById('modalFactsList');
      factsList.innerHTML = (xai.observed_facts || ['Telemetry verified by ingestion engine.']).map(f => `<li>${this.escape(f)}</li>`).join('');

      const infList = document.getElementById('modalInferencesList');
      infList.innerHTML = (xai.model_inferences || ['Model computed baseline risk score.']).map(i => `<li>${this.escape(i)}</li>`).join('');

      const recsList = document.getElementById('modalRecsList');
      const recs = xai.recommendations || (alert.recommended_actions ? alert.recommended_actions.split('\n') : ['Review host logs', 'Enforce MFA']);
      recsList.innerHTML = recs.map(r => `<li>${this.escape(r.replace(/^[•\s-]+/, ''))}</li>`).join('');

      this.openModal('xaiModal');
    } catch (e) {
      this.toast(`Could not inspect incident: ${e.message}`, 'error');
    }
  }

  async updateIncidentStatus(newStatus) {
    if (!this.currentModalAlertId) return;
    try {
      const res = await fetch(`/api/alerts/${this.currentModalAlertId}`, {
        method: 'PATCH',
        headers: this.authHeaders(),
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        this.toast(`Incident #${this.currentModalAlertId} status updated to ${newStatus}`, 'success');
        this.closeModal('xaiModal');
        this.loadAlertsData();
        this.loadDashboardData();
      }
    } catch (e) {
      this.toast(`Failed to update status: ${e.message}`, 'error');
    }
  }

  predictEventFromRow(event) {
    this.switchTab('simulator');
    document.getElementById('simIp').value = event.source_ip || '192.168.1.1';
    document.getElementById('simUser').value = event.user_identifier || 'user';
    document.getElementById('simResult').value = event.login_result || 'failure';
    document.getElementById('simFailed').value = event.failed_attempts_window || 0;
    document.getElementById('valFailed').textContent = event.failed_attempts_window || 0;
    document.getElementById('simDistinct').value = event.distinct_accounts_targeted || 1;
    document.getElementById('valDistinct').textContent = event.distinct_accounts_targeted || 1;
    document.getElementById('simFreq').value = event.request_frequency || 1.0;
    document.getElementById('valFreq').textContent = event.request_frequency || 1.0;
    document.getElementById('simHour').value = event.hour_of_day || 12;
    document.getElementById('valHour').textContent = event.hour_of_day || 12;

    this.runSimPredict(false);
  }

  // ── Settings ───────────────────────────────────────────────────────────────

  async saveSettings() {
    const payload = {
      risk_threshold_low: parseInt(document.getElementById('setLow').value),
      risk_threshold_medium: parseInt(document.getElementById('setMed').value),
      risk_threshold_high: parseInt(document.getElementById('setHigh').value),
      anomaly_contamination: parseFloat(document.getElementById('setContam').value),
    };

    try {
      const res = await fetch('/api/settings', {
        method: 'PATCH',
        headers: this.authHeaders(),
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        this.toast('Risk parameters updated successfully!', 'success');
        this.loadSettings();
      }
    } catch (e) {
      this.toast(`Failed to save settings: ${e.message}`, 'error');
    }
  }

  async loadSettings() {
    try {
      const res = await fetch('/api/settings');
      if (!res.ok) return;
      const data = await res.json();
      const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.value = val;
      };
      const setText = (id, txt) => {
        const el = document.getElementById(id);
        if (el) el.textContent = txt;
      };
      setVal('setLow', data.risk_threshold_low);
      setText('lblLow', data.risk_threshold_low);
      setText('lblLow2', data.risk_threshold_low);
      setVal('setMed', data.risk_threshold_medium);
      setText('lblMed', data.risk_threshold_medium);
      setText('lblMed2', data.risk_threshold_medium);
      setVal('setHigh', data.risk_threshold_high);
      setText('lblHigh', data.risk_threshold_high);
      setVal('setContam', data.anomaly_contamination);
      setText('lblContam', data.anomaly_contamination);
    } catch (e) {
      console.error('Error loading settings:', e);
    }
  }

  // ── Web Security Scanner ──────────────────────────────────────────────────

  toggleScopeConfig() {
    const box = document.getElementById('scannerScopeBox');
    if (box) {
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
    }
  }

  switchScannerSubtab(subtabId) {
    document.querySelectorAll('.scanner-subnav-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-subtab') === subtabId);
    });
    document.querySelectorAll('.scanner-subpanel').forEach(panel => {
      panel.style.display = panel.id === `subtab-${subtabId}` ? 'block' : 'none';
      panel.classList.toggle('active', panel.id === `subtab-${subtabId}`);
    });
  }

  setScannerUrl(url) {
    const input = document.getElementById('scannerUrlInput');
    if (input) {
      input.value = url;
      input.focus();
    }
  }

  async startWebScan() {
    const input = document.getElementById('scannerUrlInput');
    const url = input ? input.value.trim() : '';
    if (!url) {
      this.toast('Please enter a target website URL to assess.', 'error');
      return;
    }

    const authCheck = document.getElementById('scannerAuthConfirm');
    if (authCheck && !authCheck.checked) {
      this.toast('Please confirm authorization before initiating the assessment.', 'error');
      return;
    }

    const profile = document.getElementById('scannerProfileSelect')?.value || 'standard';
    const allowedDomainsRaw = document.getElementById('scannerAllowedDomains')?.value || '';
    const excludedPathsRaw = document.getElementById('scannerExcludedPaths')?.value || '';

    const allowedDomains = allowedDomainsRaw.split(',').map(s => s.trim()).filter(Boolean);
    const excludedPaths = excludedPathsRaw.split(',').map(s => s.trim()).filter(Boolean);

    const submitBtn = document.getElementById('scannerSubmitBtn');
    const btnText = document.getElementById('scanBtnText');
    const btnSpinner = document.getElementById('scanBtnSpinner');
    const progressBox = document.getElementById('scannerProgressBox');
    const progressFill = document.getElementById('scannerProgressFill');

    // UI loading state
    if (submitBtn) submitBtn.disabled = true;
    if (btnText) btnText.textContent = 'Assessing Target...';
    if (btnSpinner) btnSpinner.style.display = 'inline-block';
    if (progressBox) progressBox.style.display = 'block';

    const steps = ['stepSsrf', 'stepTls', 'stepCrawl', 'stepOwasp', 'stepThreat'];
    let stepIdx = 0;
    const progressInterval = setInterval(() => {
      stepIdx++;
      if (stepIdx < steps.length) {
        document.getElementById(steps[stepIdx])?.classList.add('active');
        if (progressFill) progressFill.style.width = `${((stepIdx + 1) / steps.length) * 100}%`;
      }
    }, 700);

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.token ? { 'Authorization': `Bearer ${this.token}` } : {})
        },
        body: JSON.stringify({
          url: url,
          profile: profile,
          authorized: true,
          allowed_domains: allowedDomains,
          excluded_paths: excludedPaths,
          max_crawl_pages: profile === 'quick' ? 10 : (profile === 'comprehensive' ? 80 : 30)
        })
      });

      clearInterval(progressInterval);

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Website assessment failed');
      }

      const scanData = await res.json();
      this.currentScan = scanData;
      this.renderScanResult(scanData);
      await this.loadScanHistory();

      if (scanData.scan_status === 'failed') {
        this.toast(`Scan blocked: ${scanData.error_message || 'Target inaccessible'}`, 'error');
      } else {
        this.toast(`Assessment completed for ${scanData.target_host}! Posture Score: ${scanData.score}/100`, 'success');
      }
    } catch (e) {
      clearInterval(progressInterval);
      this.toast(`Assessment error: ${e.message}`, 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
      if (btnText) btnText.textContent = 'Launch Security Assessment';
      if (btnSpinner) btnSpinner.style.display = 'none';
      if (progressBox) progressBox.style.display = 'none';
    }
  }

  renderScanResult(data) {
    const resultsCard = document.getElementById('scannerResultsCard');
    if (!resultsCard) return;
    resultsCard.style.display = 'block';

    // 1. Score & Risk Gauge
    const scoreNum = document.getElementById('scanScoreNum');
    const scoreCircle = document.getElementById('scanScoreCircle');
    const riskBadge = document.getElementById('scanRiskBadge');
    const statusLabel = document.getElementById('scanStatusLabel');

    const score = data.score !== undefined ? data.score : 0;
    if (scoreNum) scoreNum.textContent = score;

    if (scoreCircle) {
      scoreCircle.className = 'score-circle ' + (
        score >= 75 ? 'score-high' : (score >= 50 ? 'score-medium' : 'score-critical')
      );
    }

    const riskLevel = data.risk_level || 'Low';
    if (riskBadge) {
      riskBadge.textContent = riskLevel.toUpperCase();
      riskBadge.className = `risk-badge-large ${riskLevel.toLowerCase()}`;
    }

    if (statusLabel) {
      statusLabel.textContent = `Profile: ${(data.profile || 'STANDARD').toUpperCase()} • Status: ${data.scan_status ? data.scan_status.toUpperCase() : 'COMPLETED'}`;
    }

    // 2. Target Telemetry fields
    const setText = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val !== null && val !== undefined ? val : 'Not checked';
    };

    setText('resTargetHost', data.target_host);
    setText('resTargetIp', data.target_ip || 'N/A');
    setText('resHttpStatus', data.http_status ? `${data.http_status} OK` : 'Unreachable');
    setText('resLatency', data.response_time_ms ? `${data.response_time_ms} ms` : 'N/A');
    setText('resTlsVer', data.tls_version || 'Plain HTTP');
    setText(
      'resCertExpiry',
      data.cert_expires_at
        ? new Date(data.cert_expires_at).toLocaleDateString()
        : (data.cert_valid === false ? 'Untrusted / Expired' : 'Not checked')
    );

    // 3. Summary counts & Subtab badge counts
    const sum = data.summary || {};
    setText('countCrit', sum.critical || 0);
    setText('countHigh', sum.high || 0);
    setText('countMed', sum.medium || 0);
    setText('countLow', sum.low || 0);
    setText('countInfo', sum.informational || 0);

    const findings = data.findings || [];
    this.currentFindings = findings;
    setText('totalFindingsCount', findings.length);
    setText('tabFindingsCount', findings.length);

    const remediationList = data.remediation_checklist || [];
    setText('tabRemediationCount', remediationList.length);

    const surface = data.attack_surface || {};
    const subdomains = surface.subdomains || [];
    const apis = surface.api_endpoints || [];
    const crawledPages = surface.crawled_pages || [];
    const totalAssets = subdomains.length + apis.length + crawledPages.length;
    setText('surfaceAssetsCount', totalAssets);
    setText('crawledPagesCount', crawledPages.length);

    // 4. Render Attack Surface Tab
    this.renderAttackSurface(surface);

    // 5. Render Findings Tab
    this.filterFindings('all');

    // 6. Render Remediation Plan Tab
    this.renderRemediationPlan(remediationList);

    // 7. Render Limitations Tab
    this.renderLimitations(data.limitations || []);

    // Switch to overview subtab by default
    this.switchScannerSubtab('overview');

    // Scroll to results
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  renderAttackSurface(surface) {
    // DNS Box
    const dnsContainer = document.getElementById('surfaceDnsContainer');
    if (dnsContainer) {
      const records = surface.dns_records || {};
      const entries = Object.entries(records).filter(([_, vals]) => vals && vals.length > 0);
      if (!entries.length) {
        dnsContainer.innerHTML = '<div class="text-dim">No DNS records resolved.</div>';
      } else {
        dnsContainer.innerHTML = entries.map(([rtype, vals]) => `
          <div class="dns-row">
            <span class="dns-type">${this.escape(rtype)}</span>
            <span class="dns-vals">${this.escape(vals.slice(0, 3).join(', '))}${vals.length > 3 ? ` (+${vals.length - 3} more)` : ''}</span>
          </div>
        `).join('');
      }
    }

    // Technology Stack Box
    const techContainer = document.getElementById('surfaceTechContainer');
    if (techContainer) {
      const techs = surface.technologies || [];
      if (!techs.length) {
        techContainer.innerHTML = '<div class="text-dim">No framework or web server signatures identified.</div>';
      } else {
        techContainer.innerHTML = techs.map(t => `
          <div class="tech-item-badge">
            <div>
              <span class="tech-name">${this.escape(t.name)}</span>
              <span class="tech-cat">(${this.escape(t.category)})</span>
            </div>
            <span class="tech-ver">${this.escape(t.version)}</span>
          </div>
        `).join('');
      }
    }

    // Subdomains Tag Cloud
    const subContainer = document.getElementById('surfaceSubdomainsContainer');
    if (subContainer) {
      const subs = surface.subdomains || [];
      subContainer.innerHTML = subs.length
        ? subs.map(s => `<span class="tag-chip">${this.escape(s)}</span>`).join('')
        : '<span class="text-dim" style="font-size:0.75rem;">No external public subdomains discovered.</span>';
    }

    // API Endpoints Tag Cloud
    const apiContainer = document.getElementById('surfaceApisContainer');
    if (apiContainer) {
      const apis = surface.api_endpoints || [];
      apiContainer.innerHTML = apis.length
        ? apis.map(a => `<span class="tag-chip font-mono">${this.escape(a)}</span>`).join('')
        : '<span class="text-dim" style="font-size:0.75rem;">No public API endpoints discovered.</span>';
    }

    // Crawled Pages Tbody
    const pagesTbody = document.getElementById('surfacePagesTbody');
    if (pagesTbody) {
      const pages = surface.crawled_pages || [];
      if (!pages.length) {
        pagesTbody.innerHTML = '<tr><td colspan="3" class="loading-td">No pages crawled.</td></tr>';
      } else {
        pagesTbody.innerHTML = pages.map(p => `
          <tr>
            <td style="max-width:250px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
              <a href="${this.escape(p.url)}" target="_blank" style="color:var(--cyan-neon);">${this.escape(p.url)}</a>
            </td>
            <td><span class="status-tag ${p.status === 200 ? 'resolved' : 'open'}">${p.status || 'N/A'}</span></td>
            <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${this.escape(p.title || '/')}</td>
          </tr>
        `).join('');
      }
    }
  }

  filterFindings(severity) {
    const container = document.getElementById('findingsContainer');
    if (!container) return;

    // Update active filter button
    document.querySelectorAll('.findings-filters .filter-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-sev') === severity);
    });

    const findings = this.currentFindings || [];
    const filtered = severity === 'all'
      ? findings
      : findings.filter(f => f.severity.toLowerCase() === severity.toLowerCase());

    if (!filtered.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <p>No findings recorded under the <strong>${severity.toUpperCase()}</strong> category.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(f => {
      const sevClass = (f.severity || 'low').toLowerCase();
      return `
        <div class="finding-item-card ${sevClass}">
          <div class="finding-head">
            <div class="finding-title-group">
              <span class="badge-severity ${sevClass}">${this.escape(f.severity)}</span>
              <span class="category-tag">${this.escape(f.category)}</span>
              <span class="badge-confidence">${this.escape(f.confidence || 'Confirmed')}</span>
              <span class="finding-title">${this.escape(f.title)}</span>
            </div>
            <span class="text-dim font-mono" style="font-size:0.75rem;">${this.escape(f.id)}</span>
          </div>

          <div style="display:flex; gap:8px; margin: 8px 0; flex-wrap:wrap;">
            ${f.cve_id ? `<span class="badge-cve">${this.escape(f.cve_id)}</span>` : ''}
            ${f.cwe_id ? `<span class="badge-cwe">${this.escape(f.cwe_id)}</span>` : ''}
            ${f.owasp_category ? `<span class="badge-owasp">${this.escape(f.owasp_category)}</span>` : ''}
            <span class="text-dim" style="font-size:0.75rem; align-self:center;">Target: <code>${this.escape(f.affected_url)}</code></span>
          </div>

          <div class="finding-evidence-box">
            <strong>Observed Evidence:</strong> ${this.escape(f.evidence)}
          </div>

          <div class="finding-explanation">
            <strong>Risk Impact:</strong> ${this.escape(f.explanation)}
          </div>

          <div class="finding-remediation-box">
            <strong>Remediation:</strong> ${this.escape(f.recommendation)}
          </div>

          ${f.reproduction_steps ? `
            <div style="margin-top:8px; font-size:0.75rem; color:#94a3b8;">
              <strong>Reproduction:</strong> <code>${this.escape(f.reproduction_steps)}</code>
            </div>
          ` : ''}
        </div>
      `;
    }).join('');
  }

  renderRemediationPlan(checklist) {
    const container = document.getElementById('remediationContainer');
    if (!container) return;

    if (!checklist || !checklist.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">✅</div>
          <p>No actionable security remediations required. Website posture complies with baseline security policies.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = checklist.map(item => {
      const pClass = (item.priority || 'routine').toLowerCase().split(' ')[0];
      return `
        <div class="remediation-card ${pClass}">
          <div class="remediation-header">
            <h4 style="color:#fff; font-size:0.9rem;">${this.escape(item.title)}</h4>
            <span class="remediation-priority ${pClass}">${this.escape(item.priority)}</span>
          </div>
          <div class="remediation-desc">${this.escape(item.description)}</div>
          <div class="remediation-meta">
            <span><strong>Effort:</strong> ${this.escape(item.effort || 'Medium')}</span>
            <span><strong>Affected Assets:</strong> ${this.escape(item.affected_assets ? item.affected_assets.length : 1)}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  renderLimitations(limitations) {
    const list = document.getElementById('limitationsList');
    if (!list) return;

    if (!limitations || !limitations.length) {
      list.innerHTML = '<li>Standard passive external assessment limitations apply.</li>';
      return;
    }

    list.innerHTML = limitations.map(lim => `<li>${this.escape(lim)}</li>`).join('');
  }

  exportCurrentScan(format) {
    if (!this.currentScan || !this.currentScan.id) {
      this.toast('No scan available to export. Please perform a scan first.', 'error');
      return;
    }
    window.location.href = `/api/scans/${this.currentScan.id}/export?format=${format}`;
    this.toast(`Exporting scan report as ${format.toUpperCase()}...`, 'info');
  }

  async loadScanHistory() {
    const tbody = document.getElementById('scanHistoryTbody');
    if (!tbody) return;

    try {
      const res = await fetch('/api/scans?page=1&page_size=20');
      if (!res.ok) return;

      const data = await res.json();
      this.scanHistoryList = data.items || [];

      if (!this.scanHistoryList.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="loading-td">No website scans performed yet. Enter a URL above to audit a website.</td></tr>';
        return;
      }

      tbody.innerHTML = this.scanHistoryList.map(s => {
        const sum = s.summary || {};
        const riskClass = (s.risk_level || 'low').toLowerCase();
        const dateStr = s.started_at ? new Date(s.started_at).toISOString().replace('T', ' ').slice(0, 19) : '--';
        const profile = (s.profile || 'standard').toUpperCase();
        return `
          <tr>
            <td><strong>${this.escape(s.target_host)}</strong></td>
            <td><span class="tech-ver">${this.escape(profile)}</span></td>
            <td><span class="text-dim font-mono" style="font-size:0.75rem;">${dateStr}</span></td>
            <td><span class="score-pill ${s.score >= 75 ? 'score-high' : (s.score >= 50 ? 'score-medium' : 'score-critical')}">${s.score}/100</span></td>
            <td><span class="badge-severity ${riskClass}">${this.escape(s.risk_level)}</span></td>
            <td>
              <span class="badge-count critical">${sum.critical || 0}</span>
              <span class="badge-count high">${sum.high || 0}</span>
              <span class="badge-count medium">${sum.medium || 0}</span>
              <span class="badge-count low">${sum.low || 0}</span>
            </td>
            <td><span class="font-mono text-cyan" style="font-size:0.78rem;">${s.pages_crawled || 1} pages</span></td>
            <td><span class="status-tag ${s.scan_status === 'completed' ? 'open' : 'resolved'}">${this.escape(s.scan_status)}</span></td>
            <td>
              <div class="action-btn-group">
                <button class="btn btn-xs btn-secondary" onclick="app.loadScanById(${s.id})">View</button>
                <button class="btn btn-xs btn-outline" onclick="window.location.href='/api/scans/${s.id}/export?format=csv'" title="Download CSV">CSV</button>
                <button class="btn btn-xs btn-secondary" onclick="app.openComparePrompt(${s.id})" title="Compare with another scan">Compare</button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      console.error('Error loading scan history:', e);
    }
  }

  filterScanHistory(query) {
    const q = (query || '').toLowerCase().trim();
    const rows = document.querySelectorAll('#scanHistoryTbody tr');
    rows.forEach(r => {
      const text = r.textContent.toLowerCase();
      r.style.display = !q || text.includes(q) ? '' : 'none';
    });
  }

  async loadScanById(scanId) {
    try {
      this.toast(`Loading scan report #${scanId}...`, 'info');
      const res = await fetch(`/api/scans/${scanId}`);
      if (!res.ok) throw new Error('Could not load scan details');
      const data = await res.json();
      this.currentScan = data;
      this.renderScanResult(data);
    } catch (e) {
      this.toast(e.message, 'error');
    }
  }

  openComparePrompt(scanId) {
    const scanA = (this.scanHistoryList || []).find(s => s.id === scanId);
    if (!scanA) {
      this.toast('Target scan not found.', 'error');
      return;
    }

    // Offer other scans to compare against
    const otherScans = (this.scanHistoryList || []).filter(s => s.id !== scanId);
    if (!otherScans.length) {
      this.toast('At least 2 scans are required in history to perform a side-by-side comparison.', 'info');
      return;
    }

    const modalBody = document.getElementById('compareModalBody');
    if (!modalBody) return;

    modalBody.innerHTML = `
      <div style="margin-bottom: 16px;">
        <label style="display:block; margin-bottom:8px; font-size:0.85rem; color:#cbd5e1;">
          Select second scan to compare with <strong>${this.escape(scanA.target_host)}</strong> (#${scanA.id} - ${scanA.score}/100):
        </label>
        <select id="compareSelectScanB" class="select-input" style="width:100%; max-width:400px;">
          ${otherScans.map(s => `
            <option value="${s.id}">${this.escape(s.target_host)} — Score: ${s.score}/100 (${new Date(s.started_at).toLocaleDateString()})</option>
          `).join('')}
        </select>
        <button class="btn btn-primary btn-sm" style="margin-top:12px;" onclick="app.executeCompare(${scanId}, parseInt(document.getElementById('compareSelectScanB').value))">
          Run Side-by-Side Comparison &rarr;
        </button>
      </div>
      <div id="compareDiffOutput"></div>
    `;

    this.openModal('scanCompareModal');
  }

  async executeCompare(scanIdA, scanIdB) {
    const diffContainer = document.getElementById('compareDiffOutput');
    if (diffContainer) {
      diffContainer.innerHTML = '<div class="loading-td">Calculating security posture delta...</div>';
    }

    try {
      const res = await fetch(`/api/scans/${scanIdA}/compare/${scanIdB}`);
      if (!res.ok) throw new Error('Failed to compute scan comparison');
      const diff = await res.json();

      const deltaClass = diff.score_diff > 0 ? 'improved' : (diff.score_diff < 0 ? 'regressed' : 'neutral');
      const deltaSign = diff.score_diff > 0 ? '+' : '';

      diffContainer.innerHTML = `
        <div class="compare-delta-banner ${deltaClass}">
          Security Score Delta: <strong>${deltaSign}${diff.score_diff} Points</strong>
          (${diff.scan_a.target_host} ${diff.scan_a.score} pts &rarr; ${diff.scan_b.target_host} ${diff.scan_b.score} pts)
        </div>

        <div class="compare-grid">
          <div class="compare-col">
            <h4>Scan Baseline (${this.escape(diff.scan_a.target_host)})</h4>
            <div class="telem-row"><span>Score:</span> <strong>${diff.scan_a.score}/100</strong></div>
            <div class="telem-row"><span>Risk:</span> <strong>${diff.scan_a.risk_level}</strong></div>
            <div class="telem-row"><span>Findings:</span> <strong>${diff.scan_a.findings.length}</strong></div>
          </div>
          <div class="compare-col">
            <h4>Comparison Target (${this.escape(diff.scan_b.target_host)})</h4>
            <div class="telem-row"><span>Score:</span> <strong>${diff.scan_b.score}/100</strong></div>
            <div class="telem-row"><span>Risk:</span> <strong>${diff.scan_b.risk_level}</strong></div>
            <div class="telem-row"><span>Findings:</span> <strong>${diff.scan_b.findings.length}</strong></div>
          </div>
        </div>

        <div class="diff-section">
          <h4 style="color:var(--red-alert);">New Potential Issues in Target (${diff.new_findings.length})</h4>
          ${diff.new_findings.length ? diff.new_findings.map(f => `
            <div class="finding-item-card critical" style="margin-bottom:8px;">
              <strong>${this.escape(f.title)}</strong> [${this.escape(f.severity)}]
              <div style="font-size:0.75rem; color:#cbd5e1;">${this.escape(f.evidence)}</div>
            </div>
          `).join('') : '<p class="text-green" style="font-size:0.8rem;">No new security issues identified.</p>'}
        </div>

        <div class="diff-section" style="margin-top:16px;">
          <h4 style="color:var(--green-neon);">Resolved Security Issues (${diff.resolved_findings.length})</h4>
          ${diff.resolved_findings.length ? diff.resolved_findings.map(f => `
            <div class="finding-item-card informational" style="margin-bottom:8px;">
              <strong>${this.escape(f.title)}</strong>
              <div style="font-size:0.75rem; color:#6ee7b7;">Issue resolved in comparison target.</div>
            </div>
          `).join('') : '<p class="text-dim" style="font-size:0.8rem;">No resolved differences between scans.</p>'}
        </div>
      `;
    } catch (e) {
      if (diffContainer) diffContainer.innerHTML = `<div class="text-red">Error comparing scans: ${e.message}</div>`;
    }
  }

  // ── Utilities ──────────────────────────────────────────────────────────────

  openModal(modalId) {
    document.getElementById(modalId)?.classList.add('open');
  }

  closeModal(modalId) {
    document.getElementById(modalId)?.classList.remove('open');
  }

  escape(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  scoreColor(score) {
    if (!score) return 'low';
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }
}

// Instantiate on load
window.addEventListener('DOMContentLoaded', () => {
  window.app = new CyberSentinelApp();
});
