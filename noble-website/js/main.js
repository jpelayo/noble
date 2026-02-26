/**
 * NOBLE Website — Main Script
 * Theme toggle + mobile nav + smooth scroll
 */

// ── Theme ──
const html = document.documentElement;
const themeBtn = document.getElementById('theme-toggle');

function applyTheme(t) {
  html.setAttribute('data-theme', t);
  localStorage.setItem('noble-theme', t);
  themeBtn.textContent = t === 'dark' ? 'Light' : 'Dark';
}

(function initTheme() {
  const saved = localStorage.getItem('noble-theme');
  if (saved) return applyTheme(saved);
  applyTheme(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
})();

themeBtn.addEventListener('click', () => {
  applyTheme(html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
});

// ── Mobile menu ──
const menuBtn = document.getElementById('mobile-menu');
const nav = document.getElementById('site-nav');

menuBtn.addEventListener('click', () => {
  nav.classList.toggle('open');
});

// Close mobile menu on link click
nav.querySelectorAll('a').forEach(a => {
  a.addEventListener('click', () => nav.classList.remove('open'));
});

// ── Active nav highlight on scroll ──
const sections = document.querySelectorAll('section[id]');
const navLinks = nav.querySelectorAll('a[href^="#"]');

function updateActive() {
  const scrollY = window.scrollY + 100;
  sections.forEach(section => {
    const top = section.offsetTop;
    const height = section.offsetHeight;
    const id = section.getAttribute('id');
    if (scrollY >= top && scrollY < top + height) {
      navLinks.forEach(link => {
        link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
      });
    }
  });
}

window.addEventListener('scroll', updateActive, { passive: true });
updateActive();
