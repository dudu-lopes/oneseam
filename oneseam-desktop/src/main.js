const BASE_URL = 'http://localhost:8000';
const API_KEY = 'local-ui-key';
const DEFAULT_CLIENT_ID = 'local_user';

const state = {
  active: 'home',
  history: [],
  intents: [],
  matches: [],
  swaps: {},
};

const intervals = {
  orders: null,
  node: null,
};

function headers() {
  return {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY,
  };
}

async function apiGet(path) {
  const resp = await fetch(`${BASE_URL}${path}`, { headers: headers() });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    const message = data.error || data.message || resp.statusText;
    throw new Error(message);
  }
  return resp.json();
}

async function apiPost(path, body) {
  const resp = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify(body),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const message = data.error || data.message || resp.statusText;
    throw new Error(message);
  }
  return data;
}

function updateBackButtons() {
  const hasHistory = state.history.length > 0;
  document.querySelectorAll('.os-back').forEach(btn => {
    if (hasHistory) {
      btn.disabled = false;
    } else {
      btn.disabled = true;
    }
  });
}

function switchScreen(id, push = true) {
  if (state.active === id) return;
  if (push) {
    state.history.push(state.active);
  }
  state.active = id;
  document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
  document.getElementById('screen-' + id).classList.add('active');
  updateBackButtons();

  if (id === 'orders') {
    startOrdersPolling();
  } else {
    stopOrdersPolling();
  }
  if (id === 'node') {
    startNodePolling();
  } else {
    stopNodePolling();
  }
}

function goBack() {
  if (!state.history.length) {
    return;
  }
  const prev = state.history.pop();
  switchScreen(prev, false);
}

function setPostError(message) {
  const el = document.getElementById('post-error');
  if (!message) {
    el.style.display = 'none';
    el.textContent = '';
    return;
  }
  el.style.display = 'block';
  el.textContent = message;
}

function setSubmitLoading(isLoading) {
  const btn = document.getElementById('submit-intent');
  btn.disabled = isLoading;
  btn.textContent = isLoading ? 'SUBMITTING...' : 'SUBMIT INTENT';
  btn.style.opacity = isLoading ? '0.7' : '1';
}

function updateSideAssets() {
  const side = document.getElementById('side-select').value;
  const sellAsset = document.getElementById('sell-asset');
  const buyAsset = document.getElementById('buy-asset');
  if (side === 'buy') {
    sellAsset.value = 'USDT';
    buyAsset.value = 'BTC';
  } else {
    sellAsset.value = 'BTC';
    buyAsset.value = 'USDT';
  }
}

async function submitIntent() {
  setPostError('');
  setSubmitLoading(true);
  try {
    const side = document.getElementById('side-select').value;
    const sellAsset = side === 'buy' ? 'USDT' : 'BTC';
    const buyAsset = side === 'buy' ? 'BTC' : 'USDT';
    const amount = parseFloat(document.getElementById('amount-input').value);
    const priceMin = parseFloat(document.getElementById('min-price-input').value);
    const priceMax = parseFloat(document.getElementById('max-price-input').value);
    const validity = parseInt(document.getElementById('validity-select').value, 10);
    if (!amount || !priceMin || !priceMax) {
      throw new Error('Fill amount and price range.');
    }
    const expiration = Date.now() + (validity * 1000);
    const payload = {
      maker_wallet: 'local_user',
      sell_asset: sellAsset,
      buy_asset: buyAsset,
      amount: amount,
      price_min: priceMin,
      price_max: priceMax,
      expiration: expiration,
      wallet_nonce: 'ui_' + Date.now(),
    };

    const prepared = await apiPost('/v2/intents/prepare-signature', payload);
    const attestation = prepared.attestation || {};
    const walletSig = prepared.wallet_signature || attestation.wallet_signature || '';
    const submitPayload = {
      ...payload,
      maker_wallet: (attestation.payload && attestation.payload.maker_wallet) || payload.maker_wallet,
      wallet_signature: walletSig,
    };

    const created = await apiPost('/v2/intents', submitPayload);
    const intentId = created.trade_intent && created.trade_intent.intent_id;
    if (intentId) {
      switchScreen('orders');
    }
  } catch (err) {
    setPostError(err.message || 'Failed to submit intent.');
  } finally {
    setSubmitLoading(false);
  }
}

async function loadOrders() {
  try {
    const intentsResp = await apiGet(`/v2/intents?client_id=${encodeURIComponent(DEFAULT_CLIENT_ID)}`);
    state.intents = intentsResp.intents || [];
    const matchesResp = await apiGet(`/v2/matches?client_id=${encodeURIComponent(DEFAULT_CLIENT_ID)}`);
    state.matches = matchesResp.matches || [];

    const matchDetails = [];
    for (const m of state.matches) {
      try {
        const detail = await apiGet(`/v2/matches/${m.match_id}`);
        matchDetails.push(detail.match || m);
      } catch {
        matchDetails.push(m);
      }
    }

    const swaps = {};
    for (const match of matchDetails) {
      const swapId = match.metadata && match.metadata.swap_id;
      if (swapId) {
        try {
          const swapResp = await apiGet(`/v2/swaps/${swapId}`);
          swaps[swapId] = swapResp.swap || swapResp;
        } catch {
          swaps[swapId] = null;
        }
      }
    }
    state.swaps = swaps;

    renderOrders(matchDetails);
  } catch (err) {
    renderOrders([]);
  }
}

function renderOrders(matchDetails) {
  const activeMatchesEl = document.getElementById('active-matches');
  const openIntentsEl = document.getElementById('open-intents');
  const matchBadge = document.getElementById('match-count-badge');

  activeMatchesEl.innerHTML = '';
  openIntentsEl.innerHTML = '';

  matchBadge.textContent = `${matchDetails.length} matches`;

  if (!matchDetails.length) {
    activeMatchesEl.innerHTML = `<div class="os-match-card"><div class="os-match-pair">No active matches</div></div>`;
  }

  matchDetails.forEach(match => {
    const matchId = match.match_id || '';
    const truncId = matchId ? matchId.slice(0, 6) + '..' + matchId.slice(-4) : 'unknown';
    const meta = match.metadata || {};
    const batchSize = meta.batch_size || (match.participants ? match.participants.length : 2);
    const amount = (match.amount || 0).toFixed(2);
    const pair = `${amount} BTC → USDT`;
    const swapId = meta.swap_id;
    const swap = swapId ? state.swaps[swapId] : null;
    const legs = (swap && swap.metadata && swap.metadata.legs) || meta.batch_allocations || [];

    const totalLegs = legs.length || (batchSize > 1 ? batchSize - 1 : 1);
    let confirmed = 0;
    const legBadges = [];

    if (legs.length) {
      legs.forEach(leg => {
        const legAmount = leg.amount || 0;
        const status = leg.state || '';
        const okStates = ['WAIT_LOCK_B', 'READY_CLAIM', 'CLAIMED_A', 'CLAIMED_B', 'COMPLETED'];
        const isConfirmed = okStates.includes(status);
        if (isConfirmed) confirmed += 1;
        legBadges.push(`<span class="os-leg ${isConfirmed ? 'confirmed' : ''}">${legAmount} BTC ${isConfirmed ? '✓' : '...'}</span>`);
      });
    } else {
      legBadges.push(`<span class="os-leg">pending...</span>`);
    }

    const progress = totalLegs ? Math.round((confirmed / totalLegs) * 100) : 0;
    const flowState = swap ? swap.state : 'WAIT_LOCK_A';
    const flow = buildFlow(flowState);

    const revealReady = totalLegs > 0 && confirmed >= totalLegs;
    const revealButton = revealReady
      ? `<button class="os-reveal-btn" data-match-id="${matchId}">REVEAL SECRET</button>`
      : '';

    const card = document.createElement('div');
    card.className = 'os-match-card new-match';
    card.innerHTML = `
      <div class="os-match-header">
        <span class="os-match-id">MATCH #${truncId}</span>
        <span class="os-badge os-badge-yellow">BATCH x${batchSize}</span>
      </div>
      <div class="os-match-pair">${pair}</div>
      <div class="os-legs">${legBadges.join('')}</div>
      <div>
        <div class="os-status-row" style="margin-bottom:5px;">
          <span class="os-status-text">locking HTLCs</span>
          <span class="os-status-text">${confirmed}/${totalLegs} confirmed</span>
        </div>
        <div class="os-progress-bar"><div class="os-progress-fill" style="width:${progress}%"></div></div>
      </div>
      ${flow}
      ${revealButton}
    `;
    activeMatchesEl.appendChild(card);
  });

  const openIntents = state.intents.filter(i => ['OPEN', 'PARTIAL', 'MATCHED'].includes(i.status || ''));
  if (!openIntents.length) {
    openIntentsEl.innerHTML = `<div class="os-match-card"><div class="os-match-pair">No open intents</div></div>`;
    return;
  }

  openIntents.forEach(intent => {
    const intentId = intent.intent_id || '';
    const truncId = intentId ? intentId.slice(0, 6) + '..' + intentId.slice(-4) : 'unknown';
    const amount = (intent.amount || 0).toFixed(2);
    const card = document.createElement('div');
    card.className = 'os-match-card';
    card.innerHTML = `
      <div class="os-match-header">
        <span class="os-match-id">INTENT #${truncId}</span>
        <span class="os-badge os-badge-gray">OPEN</span>
      </div>
      <div class="os-match-pair">${amount} BTC → USDT</div>
      <div style="font-size:10px;color:var(--os-muted);">awaiting counterparty via DHT...</div>
    `;
    openIntentsEl.appendChild(card);
  });

  document.querySelectorAll('.os-reveal-btn[data-match-id]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const matchId = btn.getAttribute('data-match-id');
      if (!matchId) return;
      btn.disabled = true;
      try {
        await apiPost(`/v2/matches/${matchId}/swap/start`, {});
        await loadOrders();
      } catch {
        btn.disabled = false;
      }
    });
  });
}

function buildFlow(state) {
  const doneStates = ['READY_CLAIM', 'CLAIMED_A', 'CLAIMED_B', 'COMPLETED'];
  const completeStates = ['COMPLETED'];
  const lockActive = state === 'WAIT_LOCK_A' || state === 'WAIT_LOCK_B' || state === 'SWAP_INIT';
  const revealActive = doneStates.includes(state) && !completeStates.includes(state);
  const settleDone = completeStates.includes(state);

  const hClass = 'done';
  const lClass = lockActive ? 'active' : (revealActive || settleDone ? 'done' : 'idle');
  const rClass = revealActive ? 'active' : (settleDone ? 'done' : 'idle');
  const cClass = settleDone ? 'done' : 'idle';

  return `
    <div class="os-flow-row">
      <div class="os-flow-step">
        <div class="os-flow-circle ${hClass}">H</div>
        <div class="os-flow-label">hash<br>shared</div>
      </div>
      <div class="os-flow-arrow">›</div>
      <div class="os-flow-step">
        <div class="os-flow-circle ${lClass}">L</div>
        <div class="os-flow-label">locking<br>HTLCs</div>
      </div>
      <div class="os-flow-arrow">›</div>
      <div class="os-flow-step">
        <div class="os-flow-circle ${rClass}">R</div>
        <div class="os-flow-label">reveal<br>secret</div>
      </div>
      <div class="os-flow-arrow">›</div>
      <div class="os-flow-step">
        <div class="os-flow-circle ${cClass}">✓</div>
        <div class="os-flow-label">atomic<br>settle</div>
      </div>
    </div>
  `;
}

async function loadNodeStatus() {
  const statusEl = document.getElementById('node-status');
  try {
    const data = await apiGet('/v2/node/status');
    statusEl.textContent = data.status || 'online';
    statusEl.style.color = data.status === 'online' ? 'var(--os-success)' : '#ff6b6b';
    document.getElementById('node-transport').textContent = data.transport || '-';
    document.getElementById('node-peers').textContent = data.peers_connected ?? '-';
    document.getElementById('node-dht').textContent = data.dht_peers ?? '-';
    document.getElementById('node-blind').textContent = data.blind_matching ? 'enabled' : 'disabled';
    document.getElementById('node-blind').style.color = data.blind_matching ? 'var(--os-accent)' : 'var(--os-muted)';
    document.getElementById('node-batch').textContent = data.batch_partial_fills ? 'enabled' : 'disabled';
    document.getElementById('node-batch').style.color = data.batch_partial_fills ? 'var(--os-accent)' : 'var(--os-muted)';
    document.getElementById('node-settlement').textContent = data.settlement || 'BTC + Lightning';
    document.getElementById('node-custody').textContent = data.custody || 'none';
    document.getElementById('node-custody').style.color = 'var(--os-success)';
    document.getElementById('node-fee').textContent = data.fee || '0.01%';
  } catch {
    try {
      const health = await apiGet('/health');
      statusEl.textContent = health.status === 'healthy' ? 'online' : 'offline';
      statusEl.style.color = health.status === 'healthy' ? 'var(--os-success)' : '#ff6b6b';
    } catch {
      statusEl.textContent = 'offline';
      statusEl.style.color = '#ff6b6b';
    }
  }
}

function startOrdersPolling() {
  if (intervals.orders) return;
  loadOrders();
  intervals.orders = setInterval(loadOrders, 3000);
}

function stopOrdersPolling() {
  if (!intervals.orders) return;
  clearInterval(intervals.orders);
  intervals.orders = null;
}

function startNodePolling() {
  if (intervals.node) return;
  loadNodeStatus();
  intervals.node = setInterval(loadNodeStatus, 5000);
}

function stopNodePolling() {
  if (!intervals.node) return;
  clearInterval(intervals.node);
  intervals.node = null;
}

document.getElementById('submit-intent').addEventListener('click', submitIntent);
document.getElementById('side-select').addEventListener('change', updateSideAssets);

updateBackButtons();
updateSideAssets();

window.switchScreen = switchScreen;
window.goBack = goBack;
