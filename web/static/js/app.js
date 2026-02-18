/**
 * PENT Web UI - Shared JavaScript
 */

// Escape HTML to prevent XSS in rendered content
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Highlight active nav item based on current path
document.addEventListener('DOMContentLoaded', () => {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-item').forEach(item => {
    item.classList.remove('active');
    const href = item.getAttribute('href');
    if (path === href || (href !== '/' && path.startsWith(href))) {
      item.classList.add('active');
    }
  });
});
