/**
 * NOBLE Dashboard — WebSocket Manager (JSON-RPC 2.0 subscriptions)
 *
 * BOMBPROOF: auto-reconnect, heartbeat watchdog, tab-wake recovery,
 * aggressive retry timing, and silent self-healing.  The dashboard
 * must never go dark.
 *
 * Speaks the jsonrpsee subscription protocol:
 *   Subscribe:   {"jsonrpc":"2.0","id":N,"method":"noble_subscribeXxx","params":[]}
 *   Confirm:     {"jsonrpc":"2.0","id":N,"result":"<sub_id>"}
 *   Notify:      {"jsonrpc":"2.0","method":"noble_subscribeXxx",
 *                 "params":{"subscription":"<sub_id>","result":{...}}}
 *   Unsubscribe: {"jsonrpc":"2.0","id":N,"method":"noble_unsubscribeXxx","params":["<sub_id>"]}
 *
 * jsonrpsee sends notifications with method = subscribe method name (NOT
 * "noble_subscription").  The SUB_METHOD_TO_TOPIC reverse map handles this.
 *
 * Topic → RPC method mapping:
 *   newBlocks        → noble_subscribeNewBlocks / noble_unsubscribeNewBlocks
 *   newTransactions  → noble_subscribeNewTransactions / noble_unsubscribeNewTransactions
 *   cyclePhaseChange → noble_subscribeCyclePhase / noble_unsubscribeCyclePhase
 *   peerUpdates      → noble_subscribePeerUpdates / noble_unsubscribePeerUpdates
 */

const TOPIC_METHODS = {
  newBlocks:        { sub: 'noble_subscribeNewBlocks',        unsub: 'noble_unsubscribeNewBlocks'        },
  newTransactions:  { sub: 'noble_subscribeNewTransactions',  unsub: 'noble_unsubscribeNewTransactions'  },
  cyclePhaseChange: { sub: 'noble_subscribeCyclePhase',       unsub: 'noble_unsubscribeCyclePhase'       },
  peerUpdates:      { sub: 'noble_subscribePeerUpdates',      unsub: 'noble_unsubscribePeerUpdates'      },
};

// Reverse lookup: subscribe method name → topic name.
// jsonrpsee uses the subscribe method name as the notification method.
const SUB_METHOD_TO_TOPIC = {};
for (const [topic, methods] of Object.entries(TOPIC_METHODS)) {
  SUB_METHOD_TO_TOPIC[methods.sub] = topic;
}

// ── Timing constants ────────────────────────────────────────────────────
const INITIAL_RETRY_MS    = 500;    // first retry after 500ms
const MAX_RETRY_MS        = 5_000;  // cap at 5s (not 30s — dashboard is primary UI)
const HEARTBEAT_INTERVAL  = 15_000; // send ping every 15s
const HEARTBEAT_TIMEOUT   = 5_000;  // if no pong in 5s, connection is dead
const HEALTH_CHECK_MS     = 10_000; // check WS state every 10s (catch silent deaths)

export class WsManager {
  #url;
  #ticketProvider;
  #ws = null;
  #handlers = new Map();          // topic → Set<{id, callback}>
  #subIds = new Map();            // topic → subscription_id string
  #pending = new Map();           // rpc_id → { topic, resolve }
  #nextId = 1;
  #nextSubEntryId = 0;
  #reconnectDelay = INITIAL_RETRY_MS;
  #shouldConnect = false;
  #onStatusChange = null;
  #authToken = null;              // SHA-256 hash of TOTP code (set via setAuthToken)
  #reconnectTimer = null;
  #heartbeatTimer = null;
  #heartbeatTimeout = null;
  #healthCheckTimer = null;
  #lastMessageAt = 0;             // timestamp of last received message
  #visibilityHandler = null;

  constructor(url, { onStatusChange, ticketProvider } = {}) {
    this.#url = url;
    this.#onStatusChange = onStatusChange;
    // K3-08: async () => ticket-hex — issued over the authenticated HTTP
    // channel so no credential material lands in the WS URL.
    this.#ticketProvider = ticketProvider || null;
  }

  /**
   * Set the pre-computed TOTP hash token for WS auth (F3).
   * Pass the value from rpc.getAuthToken() after TOTP login.
   * Pass null to clear (on logout).
   */
  setAuthToken(hash) {
    this.#authToken = hash;
  }

  connect() {
    this.#shouldConnect = true;
    this.#doConnect();
    this.#startVisibilityWatcher();
    this.#startHealthCheck();
  }

  async #doConnect() {
    if (!this.#shouldConnect) return;

    // Clean up any existing connection first.
    this.#stopHeartbeat();
    if (this.#ws) {
      try { this.#ws.onclose = null; this.#ws.onerror = null; this.#ws.close(); } catch {}
      this.#ws = null;
    }

    this.#onStatusChange?.('connecting');

    // K3-08: prefer a one-use ticket from noble_issueWsTicket (no credential
    // material in the URL). Fall back to the legacy ?token=<hash> only if the
    // ticket RPC is unavailable (older node) — that path is deprecated.
    let connectUrl = this.#url;
    if (this.#authToken) {
      let ticket = null;
      if (this.#ticketProvider) {
        try {
          ticket = await this.#ticketProvider();
        } catch { /* older node or RPC unavailable — legacy fallback below */ }
      }
      connectUrl = ticket
        ? `${this.#url}?ticket=${ticket}`
        : `${this.#url}?token=${this.#authToken}`;
    }

    try {
      this.#ws = new WebSocket(connectUrl);
    } catch {
      this.#onStatusChange?.('disconnected');
      this.#scheduleReconnect();
      return;
    }

    this.#ws.onopen = () => {
      this.#reconnectDelay = INITIAL_RETRY_MS;  // reset backoff on success
      this.#subIds.clear();
      this.#pending.clear();
      this.#lastMessageAt = Date.now();
      this.#onStatusChange?.('connected');
      this.#startHeartbeat();

      // Re-subscribe to all registered topics.
      for (const topic of this.#handlers.keys()) {
        this.#sendSubscribe(topic);
      }
    };

    this.#ws.onmessage = (event) => {
      this.#lastMessageAt = Date.now();
      this.#resetHeartbeatTimeout();  // got data — connection is alive

      let msg;
      try {
        msg = JSON.parse(event.data);
      } catch (e) {
        console.error('[ws] JSON parse error:', e);
        return;
      }

      try {
        // Subscription notification — jsonrpsee uses the subscribe method name
        // as the notification method (e.g. "noble_subscribeCyclePhase").
        const topic = SUB_METHOD_TO_TOPIC[msg.method];
        if (topic && msg.params?.subscription != null) {
          const set = this.#handlers.get(topic);
          if (set) for (const entry of set) entry.callback(msg.params.result);
          return;
        }

        // Subscription confirmation (response to our subscribe request)
        if (msg.id != null && msg.result != null && this.#pending.has(msg.id)) {
          const { topic: t } = this.#pending.get(msg.id);
          this.#pending.delete(msg.id);
          this.#subIds.set(t, msg.result);
          return;
        }
      } catch (e) {
        console.error('[ws] handler error:', e, msg);
      }
    };

    this.#ws.onclose = () => {
      this.#stopHeartbeat();
      this.#subIds.clear();
      this.#pending.clear();
      this.#onStatusChange?.('disconnected');
      this.#scheduleReconnect();
    };

    this.#ws.onerror = () => {
      // onerror is always followed by onclose — just let onclose handle recovery.
      try { this.#ws?.close(); } catch {}
    };
  }

  // ── Reconnect with exponential backoff ─────────────────────────────

  #scheduleReconnect() {
    if (!this.#shouldConnect) return;
    if (this.#reconnectTimer) return;  // already scheduled
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = null;
      this.#doConnect();
    }, this.#reconnectDelay);
    this.#reconnectDelay = Math.min(this.#reconnectDelay * 2, MAX_RETRY_MS);
  }

  #cancelReconnect() {
    if (this.#reconnectTimer) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
  }

  // ── Heartbeat: detect silent connection death ──────────────────────

  #startHeartbeat() {
    this.#stopHeartbeat();
    this.#heartbeatTimer = setInterval(() => {
      if (this.#ws?.readyState === WebSocket.OPEN) {
        // Send a JSON-RPC ping (harmless — server ignores unknown methods)
        this.#sendRaw({ jsonrpc: '2.0', id: this.#nextId++, method: 'noble_ping', params: [] });
        // If we don't get ANY message within HEARTBEAT_TIMEOUT, force reconnect
        this.#heartbeatTimeout = setTimeout(() => {
          const silentMs = Date.now() - this.#lastMessageAt;
          if (silentMs > HEARTBEAT_TIMEOUT) {
            console.warn(`[ws] heartbeat timeout (${silentMs}ms silent) — forcing reconnect`);
            this.#forceReconnect();
          }
        }, HEARTBEAT_TIMEOUT);
      }
    }, HEARTBEAT_INTERVAL);
  }

  #resetHeartbeatTimeout() {
    if (this.#heartbeatTimeout) {
      clearTimeout(this.#heartbeatTimeout);
      this.#heartbeatTimeout = null;
    }
  }

  #stopHeartbeat() {
    if (this.#heartbeatTimer) { clearInterval(this.#heartbeatTimer); this.#heartbeatTimer = null; }
    this.#resetHeartbeatTimeout();
  }

  // ── Health check: catch WS in CLOSING/CLOSED state without onclose ─

  #startHealthCheck() {
    if (this.#healthCheckTimer) return;
    this.#healthCheckTimer = setInterval(() => {
      if (!this.#shouldConnect) return;
      const ws = this.#ws;
      if (!ws || ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
        // WS is dead but no reconnect is scheduled
        if (!this.#reconnectTimer) {
          console.warn('[ws] health check: connection dead — triggering reconnect');
          this.#reconnectDelay = INITIAL_RETRY_MS;
          this.#doConnect();
        }
      }
    }, HEALTH_CHECK_MS);
  }

  // ── Tab visibility: reconnect immediately when tab wakes up ────────

  #startVisibilityWatcher() {
    if (this.#visibilityHandler) return;
    this.#visibilityHandler = () => {
      if (document.visibilityState === 'visible' && this.#shouldConnect) {
        const ws = this.#ws;
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          console.info('[ws] tab visible — forcing immediate reconnect');
          this.#cancelReconnect();
          this.#reconnectDelay = INITIAL_RETRY_MS;
          this.#doConnect();
        } else {
          // Connection looks alive — but send heartbeat to verify
          this.#sendRaw({ jsonrpc: '2.0', id: this.#nextId++, method: 'noble_ping', params: [] });
        }
      }
    };
    document.addEventListener('visibilitychange', this.#visibilityHandler);
  }

  // ── Force reconnect (kill existing + immediate retry) ──────────────

  #forceReconnect() {
    this.#cancelReconnect();
    this.#stopHeartbeat();
    if (this.#ws) {
      try { this.#ws.onclose = null; this.#ws.onerror = null; this.#ws.close(); } catch {}
      this.#ws = null;
    }
    this.#subIds.clear();
    this.#pending.clear();
    this.#reconnectDelay = INITIAL_RETRY_MS;
    this.#onStatusChange?.('disconnected');
    this.#doConnect();
  }

  // ── Send / Subscribe / Unsubscribe ─────────────────────────────────

  #sendRaw(msg) {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      try {
        this.#ws.send(JSON.stringify(msg));
      } catch {
        // Send failed — connection is likely dead
        this.#forceReconnect();
      }
    }
  }

  #sendSubscribe(topic) {
    const methods = TOPIC_METHODS[topic];
    if (!methods) {
      console.warn(`[ws] no subscription method for topic "${topic}" — skipping`);
      return;
    }
    const id = this.#nextId++;
    this.#pending.set(id, { topic });
    this.#sendRaw({ jsonrpc: '2.0', id, method: methods.sub, params: [] });
  }

  #sendUnsubscribe(topic) {
    const methods = TOPIC_METHODS[topic];
    const subId = this.#subIds.get(topic);
    if (!methods || !subId) return;
    const id = this.#nextId++;
    this.#sendRaw({ jsonrpc: '2.0', id, method: methods.unsub, params: [subId] });
    this.#subIds.delete(topic);
  }

  subscribe(topic, callback) {
    if (!this.#handlers.has(topic)) this.#handlers.set(topic, new Set());
    const entry = { id: ++this.#nextSubEntryId, callback };
    this.#handlers.get(topic).add(entry);
    if (this.#ws?.readyState === WebSocket.OPEN && !this.#subIds.has(topic)) {
      this.#sendSubscribe(topic);
    }
    // Return unsubscribe function
    return () => {
      const set = this.#handlers.get(topic);
      if (set) {
        set.delete(entry);
        if (set.size === 0) {
          this.#handlers.delete(topic);
          this.#sendUnsubscribe(topic);
        }
      }
    };
  }

  unsubscribe(topic) {
    this.#sendUnsubscribe(topic);
    this.#handlers.delete(topic);
  }

  disconnect() {
    this.#shouldConnect = false;
    this.#cancelReconnect();
    this.#stopHeartbeat();
    if (this.#healthCheckTimer) { clearInterval(this.#healthCheckTimer); this.#healthCheckTimer = null; }
    if (this.#visibilityHandler) {
      document.removeEventListener('visibilitychange', this.#visibilityHandler);
      this.#visibilityHandler = null;
    }
    this.#ws?.close();
    this.#ws = null;
  }
}
