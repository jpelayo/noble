/**
 * NOBLE Dashboard — Hash-based SPA Router
 *
 * Usage:
 *   const router = new Router(document.getElementById('content'));
 *   router.add('/', overviewPage);
 *   router.add('/block/:height', blockDetailPage);
 *   router.start();
 *
 * Each page module must export: init(root, ctx) => { destroy() }
 */

export class Router {
  #routes = [];
  #root = null;
  #current = null;
  #ctx = {};

  constructor(root, ctx = {}) {
    this.#root = root;
    this.#ctx = ctx;
  }

  add(pattern, page) {
    const paramNames = [];
    const regexStr = pattern.replace(/:(\w+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    });
    this.#routes.push({
      regex: new RegExp(`^${regexStr}$`),
      paramNames,
      page,
    });
    return this;
  }

  start() {
    window.addEventListener('hashchange', () => this.#resolve());
    this.#resolve();
  }

  #resolve() {
    const raw = location.hash.slice(1) || '/';
    const [path, queryStr] = raw.split('?', 2);
    const hash = path || '/';

    // Parse query parameters from hash
    const query = {};
    if (queryStr) {
      for (const part of queryStr.split('&')) {
        const [k, v] = part.split('=', 2);
        if (k) query[decodeURIComponent(k)] = decodeURIComponent(v || '');
      }
    }

    for (const route of this.#routes) {
      const match = hash.match(route.regex);
      if (match) {
        const params = { ...query };
        route.paramNames.forEach((name, i) => {
          params[name] = decodeURIComponent(match[i + 1]);
        });

        // Destroy previous page
        if (this.#current && this.#current.destroy) {
          try { this.#current.destroy(); } catch (e) { console.error('[router] destroy error:', e); }
        }

        // Update active nav link
        document.querySelectorAll('#sidebar a').forEach(a => {
          const href = a.getAttribute('href');
          if (href === `#${hash}` || (hash === '/' && href === '#/')) {
            a.classList.add('active');
          } else if (hash.startsWith(href.slice(1) + '/') && href !== '#/') {
            a.classList.add('active');
          } else {
            a.classList.remove('active');
          }
        });

        // Initialize new page
        this.#root.innerHTML = '';
        this.#current = route.page.init(this.#root, { ...this.#ctx, params });
        return;
      }
    }

    // 404
    this.#root.innerHTML = '<div class="empty-state"><div class="empty-icon">?</div><p>Page not found</p></div>';
  }
}
