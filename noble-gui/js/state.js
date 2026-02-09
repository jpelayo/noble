/**
 * NOBLE Dashboard — Proxy-based Reactive State Store
 *
 * Usage:
 *   const { state, subscribe } = createStore({ blockHeight: 0 });
 *   const unsub = subscribe('blockHeight', (val, old) => { ... });
 *   state.blockHeight = 100; // triggers subscriber
 *   unsub(); // remove subscriber
 */

export function createStore(initialState) {
  const subscribers = new Map();

  function getSubscribers(path) {
    if (!subscribers.has(path)) subscribers.set(path, new Set());
    return subscribers.get(path);
  }

  function notify(path, value, oldValue) {
    const subs = subscribers.get(path);
    if (subs) {
      for (const cb of subs) {
        try { cb(value, oldValue); } catch (e) { console.error(`[state] subscriber error on "${path}":`, e); }
      }
    }
  }

  const handler = {
    set(target, prop, value) {
      const old = target[prop];
      if (old === value) return true;
      target[prop] = value;
      notify(prop, value, old);
      return true;
    },
  };

  const state = new Proxy({ ...initialState }, handler);

  function subscribe(path, callback) {
    const subs = getSubscribers(path);
    subs.add(callback);
    return () => subs.delete(callback);
  }

  function getState() {
    return { ...state };
  }

  return { state, subscribe, getState };
}
