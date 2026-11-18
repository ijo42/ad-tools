/* AD Toolkit UI — Vue 3 SPA (vendored vue.global.prod.js, офлайн). */
const { createApp, reactive, ref, computed, watch } = Vue;

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

const FLAG_RE_SRC = "[A-Z0-9]{31}=";
const PKT_LIMIT = 200;

createApp({
  setup() {
    /* ---------- общее ---------- */
    const tab = ref('dets');
    const auto = ref(true);
    const meta = reactive({ stats: { detections: 0, payloads: 0, unique_flags: 0 }, teams: [], npc_count: 0 });
    const jobText = ref('');

    /* ---------- статус игры + NPC-автопроба ---------- */
    const gameStatus = reactive({ game: null, submitter: null, npc_autoprobe: null, alerts: [] });
    const alertsDismissed = ref(0);

    const alertText = computed(() => {
      const fresh = (gameStatus.alerts || []).slice(alertsDismissed.value);
      return fresh.length ? fresh.map(a => `[${a.level}] ${a.text}`).join('  ·  ') : '';
    });
    const lastAlert = computed(() => {
      const fresh = (gameStatus.alerts || []).slice(alertsDismissed.value);
      return fresh.length ? fresh[fresh.length - 1] : { level: 'info' };
    });
    function dismissAlerts() { alertsDismissed.value = (gameStatus.alerts || []).length; }

    async function loadSystemStatus() {
      try {
        const s = await api('/api/system/status');
        gameStatus.game = s.game;
        gameStatus.submitter = s.submitter;
        gameStatus.npc_autoprobe = s.npc_autoprobe;
        gameStatus.alerts = s.alerts || [];
      } catch (_) { /* ingest без game_monitor — молча */ }
    }
    const toggleMsg = ref('');
    let toggleMsgTimer = null;
    async function toggleNpcAutoprobe(ev) {
      const on = ev.target.checked;
      try {
        const r = await api('/api/system/npc_autoprobe', { enabled: on });
        gameStatus.npc_autoprobe = r.enabled;
        toggleMsg.value = r.enabled
          ? 'NPC-автопроба включена'
          : 'NPC-автопроба выключена (ручной ↻ работает)';
        jobText.value = toggleMsg.value;
      } catch (e) {
        ev.target.checked = !on;
        toggleMsg.value = 'ошибка: ' + e.message;
      }
      clearTimeout(toggleMsgTimer);
      toggleMsgTimer = setTimeout(() => { toggleMsg.value = ''; }, 6000);
    }

    function showTab(name) {
      tab.value = name;
      if (name === 'packets') loadPackets();
      if (name === 'analytics') loadAnalytics();
    }
    function refreshAll() { refreshList(); loadPackets(); loadAnalytics(); }

    /* ---------- детекты ---------- */
    const detections = ref([]);
    const detsFilter = reactive({ service: '', label: '', round: '', hasFlags: '', npc: '', q: '' });
    const selected = reactive(new Set());
    const bulkLabel = ref('exploit');
    const detail = ref(null);
    const replayMode = ref('verbatim');
    const cloneScript = ref('');
    const customHost = ref('');
    const customPort = ref('');
    const customPayload = ref('');

    async function api(url, body) {
      const r = await fetch(url, body ? {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      } : undefined);
      if (!r.ok) {
        let msg = r.statusText;
        try { msg = (await r.json()).detail || msg; } catch (_) {}
        throw new Error(msg);
      }
      return r.json();
    }

    async function refreshList() {
      const qp = new URLSearchParams();
      if (detsFilter.service) qp.set('service', detsFilter.service);
      if (detsFilter.label) qp.set('label', detsFilter.label);
      const data = await api('/api/detections?' + qp.toString());
      detections.value = data.detections;
      Object.assign(meta, data);
    }

    const filteredDetections = computed(() => {
      let list = detections.value;
      if (detsFilter.round) list = list.filter(d => d.rounds.includes(+detsFilter.round));
      if (detsFilter.hasFlags !== '') {
        list = list.filter(d => detsFilter.hasFlags === '1' ? d.flags.length > 0 : d.flags.length === 0);
      }
      if (detsFilter.npc) list = list.filter(d => d.npc_status === detsFilter.npc);
      const q = detsFilter.q.toLowerCase();
      if (q) {
        list = list.filter(d =>
          d.preview.toLowerCase().includes(q) ||
          d.srcs.join(' ').toLowerCase().includes(q) ||
          d.flags.join(' ').toLowerCase().includes(q) ||
          (d.note || '').toLowerCase().includes(q));
      }
      return list;
    });
    const detServices = computed(() =>
      [...new Set(detections.value.map(d => d.service))].sort());
    const detRounds = computed(() => {
      const s = new Set();
      for (const d of detections.value) for (const r of d.rounds) s.add(r);
      return [...s].sort((a, b) => a - b);
    });
    const allSelected = computed(() =>
      filteredDetections.value.length > 0 &&
      filteredDetections.value.every(d => selected.has(d.id)));

    function toggleAll(ev) {
      if (ev.target.checked) filteredDetections.value.forEach(d => selected.add(d.id));
      else filteredDetections.value.forEach(d => selected.delete(d.id));
    }
    function toggleSelect(id, on) {
      if (on) selected.add(id); else selected.delete(id);
    }
    function clearSelection() { selected.clear(); }

    async function applyBulk() {
      if (!selected.size) return;
      await api('/api/detections/bulk-label', { ids: [...selected], label: bulkLabel.value });
      selected.clear();
      await refreshList();
      if (detail.value) detail.value = await api('/api/detections/' + detail.value.id);
    }

    function npcBadge(d) {
      const flags = (d.npc_flags || []).map(f => `<span class="chip f">${f}</span>`).join(' ');
      if (d.npc_status === 'flags') return `<span class="badge npc-ok">✓ ${(d.npc_flags || []).length}</span> ${flags}`;
      if (d.npc_status === 'noflags') return '<span class="badge npc-none">✗ нет флагов</span>';
      if (d.npc_status === 'running') return '<span class="badge npc-run">⏳ проверка…</span>';
      if (d.npc_status === 'error') return '<span class="badge npc-err">! недоступен</span>';
      return '<span class="dim">—</span>';
    }

    const variantsText = computed(() => {
      if (!detail.value) return '';
      const vs = detail.value.variants || [];
      if (!vs.length) return '';
      return vs.map(v =>
        `[${new Date(v.ts * 1000).toLocaleTimeString()}] ${v.src || '?'} fp=${(v.fingerprint || '').slice(0, 8)}\n    ${v.payload.split('\n')[0].slice(0, 120)}`
      ).join('\n');
    });
    const replaysText = computed(() => {
      if (!detail.value) return '';
      const rps = detail.value.replays || [];
      if (!rps.length) return '';
      const lines = [];
      for (const rp of rps) {
        lines.push(`[${new Date(rp.ts * 1000).toLocaleTimeString()}] mode=${rp.mode} флагов: ${rp.flags_found.length}`);
        for (const r of rp.results) {
          lines.push(`  ${r.error ? '!!' : '->'} ${r.target}:${r.port} resp=${r.response_len}B flags=${r.flags.length}${r.error ? ' ' + r.error : ''}`);
        }
        for (const f of rp.flags_found) lines.push(`  FLAG ${f}`);
      }
      return lines.join('\n');
    });

    async function openDetail(id) {
      detail.value = await api('/api/detections/' + id);
      cloneScript.value = '';
      customPayload.value = detail.value.payload_text;
      if (!customHost.value && meta.teams.length) {
        // host первой команды; точный порт смотрите в teams.yaml
        customHost.value = meta.teams[0];
      }
    }
    async function saveLabel() {
      await api(`/api/detections/${detail.value.id}/label`,
                { label: detail.value.label, note: detail.value.note });
      await refreshList();
    }

    function pollJob(jobIdPromise, after) {
      jobIdPromise.then(jobId => {
        jobText.value = 'задача ' + jobId + ': выполняется…';
        const timer = setInterval(async () => {
          const job = await api('/api/jobs/' + jobId);
          jobText.value = job.log.join('\n') || 'выполняется…';
          if (job.status === 'done') {
            clearInterval(timer);
            jobText.value = job.log.join('\n') +
              `\nготово: флагов ${job.flags.length}` +
              (job.flags.length ? '\n' + job.flags.map(f => 'FLAG ' + f).join('\n') : '');
            if (after) after();
            refreshList();
            if (detail.value) detail.value = await api('/api/detections/' + detail.value.id);
          } else if (job.status === 'error') {
            clearInterval(timer);
            jobText.value = 'ошибка: ' + job.error;
          }
        }, 700);
      }).catch(e => { jobText.value = 'ошибка: ' + e.message; });
    }
    function startReplay() {
      if (!detail.value) return;
      pollJob(api(`/api/detections/${detail.value.id}/replay`, { mode: replayMode.value })
        .then(r => r.job_id));
    }
    function recheckNpc() {
      if (!detail.value) return;
      jobText.value = 'NPC-проверка…';
      pollJob(api(`/api/detections/${detail.value.id}/replay`, { mode: 'npc' })
        .then(r => r.job_id));
    }

    /* -------- клонер -------- */
    async function loadClone() {
      if (!detail.value) return;
      const d = await api(`/api/detections/${detail.value.id}/clone`);
      cloneScript.value = d.script;
    }
    function copyClone() {
      navigator.clipboard.writeText(cloneScript.value);
    }
    function sendCustom() {
      if (!detail.value) return;
      if (!customHost.value || !customPort.value) {
        jobText.value = 'укажите host и port цели';
        return;
      }
      pollJob(api('/api/replay_custom', {
        host: customHost.value, port: customPort.value,
        payload: customPayload.value,
      }).then(r => r.job_id), () => {});
    }

    /* ---------- пакеты ---------- */
    const packets = ref([]);
    const pktTotal = ref(0);
    const pktRounds = ref([]);
    const pktPage = ref(0);
    const pktNextDisabled = ref(true);
    const pktFilter = reactive({ round: '', service: '', direction: '', hasFlag: '', q: '' });
    const pktServices = ref([]);

    async function loadPackets() {
      const qp = new URLSearchParams();
      if (pktFilter.round) qp.set('round', pktFilter.round);
      if (pktFilter.service) qp.set('service', pktFilter.service);
      if (pktFilter.direction) qp.set('direction', pktFilter.direction);
      if (pktFilter.hasFlag !== '') qp.set('has_flag', pktFilter.hasFlag);
      if (pktFilter.q) qp.set('q', pktFilter.q);
      qp.set('limit', PKT_LIMIT);
      qp.set('offset', pktPage.value * PKT_LIMIT);
      const data = await api('/api/packets?' + qp.toString());
      // маркеры смены раунда
      let prev = null;
      for (const p of data.rows) { p._prevRound = prev; prev = p.round; }
      packets.value = data.rows;
      pktTotal.value = data.total;
      pktRounds.value = data.rounds;
      pktNextDisabled.value = (pktPage.value + 1) * PKT_LIMIT >= data.total;
      const svcs = [...new Set(data.rows.map(r => r.service).filter(Boolean))];
      if (svcs.length && !pktServices.value.length) pktServices.value = svcs;
    }
    const onPktQ = debounce(() => { pktPage.value = 0; loadPackets(); }, 400);

    function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
    function dirLabel(d) { return d === 'in' ? '→ in' : (d === 'out' ? '← out' : '·'); }

    /* ---------- аналитика ---------- */
    const analytics = reactive({ rounds: [], top_srcs: [], services: [] });

    function barChart(series, labels) {
      const W = 760, H = 180;
      const pad = { l: 40, r: 8, t: 8, b: 22 };
      const n = labels.length;
      const maxV = Math.max(1, ...series.flatMap(s => s.values));
      const bw = n ? (W - pad.l - pad.r) / n : 0;
      const bh = H - pad.t - pad.b;
      let bars = '';
      const groupW = bw / series.length;
      for (let i = 0; i < n; i++) {
        for (let s = 0; s < series.length; s++) {
          const v = series[s].values[i];
          const h = Math.round(v / maxV * (bh - 14));
          const x = pad.l + i * bw + s * groupW;
          bars += `<rect x="${x.toFixed(1)}" y="${(pad.t + bh - h).toFixed(1)}" width="${Math.max(2, groupW - 2).toFixed(1)}" height="${Math.max(1, h)}" fill="${series[s].color}"><title>${labels[i]}: ${series[s].name}=${v}</title></rect>`;
        }
        bars += `<text x="${(pad.l + i * bw + bw / 2).toFixed(1)}" y="${H - 6}" font-size="10" fill="#8a93a8" text-anchor="middle">${labels[i]}</text>`;
      }
      const axis = `<line x1="${pad.l}" y1="${pad.t + bh}" x2="${W - pad.r}" y2="${pad.t + bh}" stroke="#2a3040"/>` +
        `<text x="${pad.l - 4}" y="${pad.t + 10}" font-size="10" fill="#8a93a8" text-anchor="end">${maxV}</text>`;
      return `<svg width="100%" viewBox="0 0 ${W} ${H}">${axis}${bars}</svg>`;
    }

    async function loadAnalytics() {
      const a = await api('/api/analytics');
      Object.assign(analytics, a);
      const labels = a.rounds.map(r => 'r' + r.round);
      if (!labels.length) {
        chartRounds.value = '<div class="empty">нет данных</div>';
        chartHits.value = '';
        return;
      }
      chartRounds.value = barChart([
        { name: 'пакеты', color: '#4f8cff', values: a.rounds.map(r => r.packets) },
        { name: 'флаги', color: '#3ecf7a', values: a.rounds.map(r => r.flags) },
        { name: 'с флагом', color: '#ffb347', values: a.rounds.map(r => r.flagged) },
      ], labels);
      chartHits.value = barChart([
        { name: 'хиты', color: '#ffb347', values: a.rounds.map(r => r.hits) },
      ], labels);
    }
    const chartRounds = ref('');
    const chartHits = ref('');

    /* ---------- watchers / таймер ---------- */
    watch(() => [detsFilter.service, detsFilter.label], refreshList);
    watch(() => detsFilter.q, debounce(refreshList, 400));
    watch(() => [pktFilter.round, pktFilter.service, pktFilter.direction, pktFilter.hasFlag],
      () => { pktPage.value = 0; loadPackets(); });

    setInterval(() => {
      if (!auto.value) return;
      if (tab.value === 'dets') refreshList();
      if (tab.value === 'packets') loadPackets();
      loadSystemStatus();
    }, 5000);

    refreshList();
    api('/api/meta').then(m => Object.assign(meta, m));
    loadSystemStatus();

    return {
      tab, auto, meta, jobText, showTab, refreshAll,
      gameStatus, alertText, lastAlert, dismissAlerts, toggleNpcAutoprobe, toggleMsg,
      detections, detsFilter, filteredDetections, detServices, detRounds,
      selected, allSelected, toggleAll, toggleSelect, clearSelection,
      bulkLabel, applyBulk,
      detail, npcBadge, variantsText, replaysText, openDetail, saveLabel,
      replayMode, startReplay, recheckNpc,
      cloneScript, loadClone, copyClone,
      customHost, customPort, customPayload, sendCustom,
      packets, pktTotal, pktRounds, pktPage, pktNextDisabled, pktFilter,
      pktServices, loadPackets, onPktQ, fmtTime, dirLabel,
      analytics, chartRounds, chartHits, loadAnalytics,
    };
  },
}).mount('#app');
