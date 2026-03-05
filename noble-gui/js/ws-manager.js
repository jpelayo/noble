/**
 * NOBLE Dashboard — WebSocket Manager (JSON-RPC 2.0 subscriptions)
 *
 * Speaks the jsonrpsee subscription protocol:
 *   Subscribe:   {"jsonrpc":"2.0","id":N,"method":"noble_subscribeXxx","params":[]}
 *   Confirm:     {"jsonrpc":"2.0","id":N,"result":"<sub_id>"}
 *   Notify:      {"jsonrpc":"2.0","method":"noble_subscription",
 *                 "params":{"subscription":"<sub_id>","result":{...}}}
 *   Unsubscribe: {"jsonrpc":"2.0","id":N,"method":"noble_unsubscribeXxx","params":["<sub_id>"]}
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

export class WsManager {
  #url;
  #ws = null;
  #handlers = new Map();          // topic → Set<{id, callback}>
  #subIds = new Map();            // topic → subscription_id string
  #pending = new Map();           // rpc_id → { topic, resolve }
  #nextId = 1;
  #nextSubEntryId = 0;
  #reconnectDelay = 1000;
  #maxDelay = 30_000;
  #shouldConnect = false;
  #onStatusChange = null;
  #authToken = null;              // SHA-256 hash of TOTP code (set via setAuthToken)

  constructor(url, { onStatusChange } = {}) {
    this.#url = url;
    this.#onStatusChange = onStatusChange;
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
  }

  #doConnect() {
    if (!this.#shouldConnect) return;

    this.#onStatusChange?.('connecting');

    // F3: append ?token=<hash> when TOTP auth is active.
    // The browser WebSocket API cannot set custom headers, so the auth token
    // is passed as a query parameter and validated by the auth middleware.
    const connectUrl = this.#authToken
      ? `${this.#url}?token=${this.#authToken}`
      : this.#url;

    try {
      this.#ws = new WebSocket(connectUrl);
    } catch {
      this.#onStatusChange?.('disconnected');
      this.#scheduleReconnect();
      return;
    }

    this.#ws.onopen = () => {
      this.#reconnectDelay = 1000;
      this.#subIds.clear();
      this.#pending.clear();
      this.#onStatusChange?.('connected');

      // Re-subscribe to all registered topics.
      for (const topic of this.#handlers.keys()) {
        this.#sendSubscribe(topic);
      }
    };

    this.#ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        // Subscription notification: {"jsonrpc":"2.0","method":"noble_subscription","params":{...}}
        if (msg.method === 'noble_subscription' && msg.params?.subscription) {
          const subId = msg.params.subscription;
          // Find which topic owns this sub_id.
          for (const [topic, id] of this.#subIds.entries()) {
            if (id === subId) {
              const set = this.#handlers.get(topic);
              if (set) for (const entry of set) entry.callback(msg.params.result);
              break;
            }
          }
          return;
        }

        // Subscription confirmation: {"jsonrpc":"2.0","id":N,"result":"sub_id"}
        // jsonrpsee sends sub_id as a number (not a string)
        if (msg.id != null && msg.result != null && this.#pending.has(msg.id)) {
          const { topic } = this.#pending.get(msg.id);
          this.#pending.delete(msg.id);
          this.#subIds.set(topic, msg.result);
          return;
        }
      } catch (e) {
        console.error('[ws] message parse error:', e);
      }
    };

    this.#ws.onclose = () => {
      this.#subIds.clear();
      this.#pending.clear();
      this.#onStatusChange?.('disconnected');
      this.#scheduleReconnect();
    };

    this.#ws.onerror = () => {
      this.#ws?.close();
    };
  }

  #scheduleReconnect() {
    if (!this.#shouldConnect) return;
    setTimeout(() => this.#doConnect(), this.#reconnectDelay);
    this.#reconnectDelay = Math.min(this.#reconnectDelay * 2, this.#maxDelay);
  }

  #sendRaw(msg) {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify(msg));
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
    this.#ws?.close();
    this.#ws = null;
  }
}
