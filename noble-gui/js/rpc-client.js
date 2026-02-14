/**
 * NOBLE Dashboard — JSON-RPC 2.0 Client
 *
 * Usage:
 *   const rpc = new RpcClient('http://localhost:9332');
 *   const block = await rpc.call('noble_getLatestBlock');
 *   const results = await rpc.batch([
 *     ['noble_getBlockCount'],
 *     ['noble_getMempoolInfo'],
 *   ]);
 */

export class RpcError extends Error {
  constructor(code, message, data) {
    super(message);
    this.name = 'RpcError';
    this.code = code;
    this.data = data;
  }
}

export class RpcClient {
  #url;
  #timeout;
  #nextId = 1;
  #authToken = null;

  constructor(url, { timeout = 10_000 } = {}) {
    this.#url = url;
    this.#timeout = timeout;
  }

  /** Set the TOTP auth token (6-digit code). Pass null to clear. */
  setAuthToken(token) {
    this.#authToken = token;
  }

  /** Check whether an auth token is currently set. */
  hasAuthToken() {
    return this.#authToken !== null;
  }

  #buildHeaders() {
    const h = { 'Content-Type': 'application/json' };
    if (this.#authToken) h['Authorization'] = `Bearer ${this.#authToken}`;
    return h;
  }

  async call(method, params = {}) {
    const id = this.#nextId++;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.#timeout);

    try {
      const res = await fetch(this.#url, {
        method: 'POST',
        headers: this.#buildHeaders(),
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal,
      });

      if (!res.ok) throw new RpcError(-32000, `HTTP ${res.status}`);

      const json = await res.json();
      if (json.error) {
        throw new RpcError(json.error.code, json.error.message, json.error.data);
      }
      return json.result;
    } catch (e) {
      if (e instanceof RpcError) throw e;
      if (e.name === 'AbortError') throw new RpcError(-32001, 'Request timeout');
      throw new RpcError(-32002, e.message);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  async batch(calls) {
    const requests = calls.map(([method, params = {}]) => ({
      jsonrpc: '2.0',
      id: this.#nextId++,
      method,
      params,
    }));

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.#timeout);

    try {
      const res = await fetch(this.#url, {
        method: 'POST',
        headers: this.#buildHeaders(),
        body: JSON.stringify(requests),
        signal: controller.signal,
      });

      if (!res.ok) throw new RpcError(-32000, `HTTP ${res.status}`);
      const results = await res.json();
      return results.map(r => r.error ? new RpcError(r.error.code, r.error.message) : r.result);
    } catch (e) {
      if (e instanceof RpcError) throw e;
      if (e.name === 'AbortError') throw new RpcError(-32001, 'Batch timeout');
      throw new RpcError(-32002, e.message);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
