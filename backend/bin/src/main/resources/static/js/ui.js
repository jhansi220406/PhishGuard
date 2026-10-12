/**
 * PhishGuard UI Utilities & Component Helpers
 * Lucide icon initialization, toast system, security sanitization, modal management
 */

const PhishGuardUI = {
  // Toast notifications
  showToast(message, type = 'info', duration = 3500) {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let iconName = 'info';
    if (type === 'success') iconName = 'check-circle-2';
    if (type === 'error') iconName = 'alert-triangle';

    toast.innerHTML = `
      <i data-lucide="${iconName}" style="width: 20px; height: 20px; flex-shrink: 0;"></i>
      <span style="flex: 1; word-break: break-word;">${this.sanitize(message)}</span>
      <button style="background: none; border: none; color: inherit; cursor: pointer; padding: 2px;" onclick="this.parentElement.remove()">
        <i data-lucide="x" style="width: 16px; height: 16px;"></i>
      </button>
    `;

    container.appendChild(toast);
    this.initIcons();

    setTimeout(() => {
      if (toast && toast.parentElement) {
        toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(50px)';
        setTimeout(() => toast.remove(), 300);
      }
    }, duration);
  },

  // HTML sanitization to prevent XSS
  sanitize(text) {
    if (text === null || text === undefined) return '';
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, m => map[m]);
  },

  // Safe truncation of URLs/Payloads
  truncate(str, max = 50) {
    if (!str) return '';
    return str.length > max ? str.substring(0, max) + '...' : str;
  },

  // Risk Badge Component
  renderRiskBadge(riskLevel) {
    const level = (riskLevel || 'UNKNOWN').toUpperCase();
    let badgeClass = 'badge-unknown';
    let icon = 'help-circle';

    switch (level) {
      case 'LOW':
        badgeClass = 'badge-low';
        icon = 'shield-check';
        break;
      case 'MEDIUM':
        badgeClass = 'badge-med';
        icon = 'alert-circle';
        break;
      case 'HIGH':
        badgeClass = 'badge-high';
        icon = 'shield-alert';
        break;
    }

    return `
      <span class="badge ${badgeClass}">
        <i data-lucide="${icon}" style="width: 13px; height: 13px;"></i>
        ${level} RISK
      </span>
    `;
  },

  // Formatted date string
  formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return dateStr;
    }
  },

  // Copy to clipboard with feedback
  async copyToClipboard(text, successMsg = 'Copied to clipboard!') {
    if (!navigator.clipboard) {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        this.showToast(successMsg, 'success');
      } catch (err) {
        this.showToast('Failed to copy text', 'error');
      }
      document.body.removeChild(textarea);
      return;
    }

    try {
      await navigator.clipboard.writeText(text);
      this.showToast(successMsg, 'success');
    } catch (err) {
      this.showToast('Clipboard access denied', 'error');
    }
  },

  // Modal helpers
  openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.add('active');
      this.initIcons();
    }
  },

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
      modal.classList.remove('active');
    }
  },

  // Global Navigation & Auth status renderer
  setupNavAuth() {
    const navAuth = document.getElementById('nav-auth-container');
    if (!navAuth) return;

    const user = window.PhishGuardApi ? window.PhishGuardApi.getUser() : null;

    if (user) {
      navAuth.innerHTML = `
        <div class="flex items-center gap-3">
          <a href="/dashboard.html" class="btn btn-secondary btn-sm">
            <i data-lucide="layout-dashboard" style="width: 15px; height: 15px;"></i>
            Dashboard
          </a>
          <div class="user-pill flex items-center gap-2" style="background: rgba(255,255,255,0.06); padding: 0.35rem 0.75rem; border-radius: 9999px; border: 1px solid var(--border-subtle);">
            <div style="width: 26px; height: 26px; border-radius: 50%; background: linear-gradient(135deg, var(--primary-purple), var(--electric-cyan)); display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold; color: #FFF;">
              ${(user.name || user.email || 'U').charAt(0).toUpperCase()}
            </div>
            <span style="font-size: 0.85rem; font-weight: 500; color: var(--text-main); max-width: 110px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              ${this.sanitize(user.name || user.email.split('@')[0])}
            </span>
            <button onclick="PhishGuardApi.auth.logout()" title="Logout" style="background: none; border: none; color: var(--text-muted); cursor: pointer; display: flex; align-items: center; padding: 2px;">
              <i data-lucide="log-out" style="width: 14px; height: 14px;"></i>
            </button>
          </div>
        </div>
      `;
    } else {
      navAuth.innerHTML = `
        <div class="flex items-center gap-2">
          <a href="/login.html" class="btn btn-ghost btn-sm">Sign In</a>
          <a href="/register.html" class="btn btn-primary btn-sm">Get Started</a>
        </div>
      `;
    }

    this.initIcons();
  },

  // Initialize Lucide icons
  initIcons() {
    if (window.lucide && typeof window.lucide.createIcons === 'function') {
      window.lucide.createIcons();
    }
  }
};

window.PhishGuardUI = PhishGuardUI;

// Auto initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  PhishGuardUI.setupNavAuth();
  PhishGuardUI.initIcons();

  // Mobile menu toggle
  const mobileToggle = document.getElementById('mobile-toggle');
  const navLinks = document.getElementById('nav-links');
  if (mobileToggle && navLinks) {
    mobileToggle.addEventListener('click', () => {
      navLinks.classList.toggle('open');
    });
  }
});
