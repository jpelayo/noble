/**
 * NOBLE Dashboard — WebSocket Manager with Auto-Reconnect
 *
 * Usage:
 *   const ws = new WsManager('ws://localhost:8784');
 *   ws.subscribe('newBlocks', (block) => { ... });
 *   ws.connect();
 *   ws.unsubscribe('newBlocks');
 */

export class WsManager {
  #url;
  #ws = null;
  #handlers = new Map();
  #reconnectDelay = 1000;
  #maxDelay = 30_000;
  #shouldConnect = false;
  #onStatusChange = null;

  constructor(url, { onStatusChange } = {}) {
    this.#url = url;
    this.#onStatusChange = onStatusChange;
  }

  connect() {
    this.#shouldConnect = true;
    this.#doConnect();
  }

  #doConnect() {
    if (!this.#shouldConnect) return;

    try {
      this.#ws = new WebSocket(this.#url);
    } catch {
      this.#scheduleReconnect();
      return;
    }

    this.#ws.onopen = () => {
      this.#reconnectDelay = 1000;
      this.#onStatusChange?.('connected');

      // Re-subscribe to all topics
      for (const topic of this.#handlers.keys()) {
        this.#send({ method: 'subscribe', params: { topic } });
      }
    };

    this.#ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.params && msg.params.topic) {
          const handler = this.#handlers.get(msg.params.topic);
          if (handler) handler(msg.params.data);
        }
      } catch (e) {
        console.error('[ws] message parse error:', e);
      }
    };

    this.#ws.onclose = () => {
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

  #send(msg) {
    if (this.#ws && this.#ws.readyState === WebSocket.OPEN) {
      this.#ws.send(JSON.stringify(msg));
    }
  }

  subscribe(topic, callback) {
    this.#handlers.set(topic, callback);
    this.#send({ method: 'subscribe', params: { topic } });
  }

  unsubscribe(topic) {
    this.#handlers.delete(topic);
    this.#send({ method: 'unsubscribe', params: { topic } });
  }

  disconnect() {
    this.#shouldConnect = false;
    this.#ws?.close();
    this.#ws = null;
  }
}
