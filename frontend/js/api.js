/**
 * PhishGuard REST API Client
 * Enterprise-grade client with JWT authentication and resilient error handling.
 */

const API_BASE = window.location.origin.includes('localhost') || window.location.origin.includes('127.0.0.1')
  ? `${window.location.origin}/api`
  : '/api';

const TOKEN_KEY = 'phishguard_token';
const USER_KEY = 'phishguard_user';

const PhishGuardApi = {
  // Token management
  getToken() {
    return localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
  },

  setToken(token, remember = true) {
    if (remember) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      sessionStorage.setItem(TOKEN_KEY, token);
    }
  },

  getUser() {
    const raw = localStorage.getItem(USER_KEY) || sessionStorage.getItem(USER_KEY);
    try {
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  },

  setUser(user, remember = true) {
    const serialized = JSON.stringify(user);
    if (remember) {
      localStorage.setItem(USER_KEY, serialized);
    } else {
      sessionStorage.setItem(USER_KEY, serialized);
    }
  },

  clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(USER_KEY);
  },

  isAuthenticated() {
    return !!this.getToken();
  },

  // HTTP Request Helper
  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...options.headers,
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(url, config);

      if (response.status === 401) {
        // Token expired or invalid
        this.clearAuth();
        if (!window.location.pathname.includes('login') && !window.location.pathname.includes('index') && window.location.pathname !== '/') {
          // Do not redirect if already on login/landing page
          console.warn('Session expired. Redirecting to login.');
        }
      }

      const contentType = response.headers.get('content-type');
      let data = null;
      if (contentType && contentType.includes('application/json')) {
        data = await response.json();
      } else {
        data = await response.text();
      }

      if (!response.ok) {
        const errorMsg = (data && data.message) ? data.message : `HTTP Error ${response.status}: ${response.statusText}`;
        const error = new Error(errorMsg);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      console.error(`API Error on [${options.method || 'GET'}] ${endpoint}:`, err);
      throw err;
    }
  },

  // Auth Endpoints
  auth: {
    async login(email, password, remember = true) {
      const res = await PhishGuardApi.request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      if (res && res.token) {
        PhishGuardApi.setToken(res.token, remember);
        PhishGuardApi.setUser(res.user, remember);
      }
      return res;
    },

    async register(name, email, password) {
      const res = await PhishGuardApi.request('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ name, email, password }),
      });
      if (res && res.token) {
        PhishGuardApi.setToken(res.token, true);
        PhishGuardApi.setUser(res.user, true);
      }
      return res;
    },

    async me() {
      try {
        const res = await PhishGuardApi.request('/auth/me');
        if (res) {
          PhishGuardApi.setUser(res);
        }
        return res;
      } catch (e) {
        PhishGuardApi.clearAuth();
        return null;
      }
    },

    logout() {
      PhishGuardApi.clearAuth();
      window.location.href = '/login.html';
    }
  },

  // Scan Endpoints
  scans: {
    analyzeUrl(url) {
      return PhishGuardApi.request('/scans/url', {
        method: 'POST',
        body: JSON.stringify({ url }),
      });
    },

    analyzeQr(content, scanType = 'QR') {
      return PhishGuardApi.request('/scans/qr', {
        method: 'POST',
        body: JSON.stringify({ content, scanType }),
      });
    },

    list(page = 0, size = 10, scanType = '', riskLevel = '', search = '') {
      const params = new URLSearchParams();
      params.append('page', page);
      params.append('size', size);
      if (scanType) params.append('scanType', scanType);
      if (riskLevel) params.append('riskLevel', riskLevel);
      if (search) params.append('search', search);

      return PhishGuardApi.request(`/scans?${params.toString()}`);
    },

    getById(id) {
      return PhishGuardApi.request(`/scans/${id}`);
    },

    delete(id) {
      return PhishGuardApi.request(`/scans/${id}`, {
        method: 'DELETE',
      });
    }
  },

  // Dashboard Endpoints
  dashboard: {
    getSummary() {
      return PhishGuardApi.request('/dashboard/summary');
    },

    getActivity() {
      return PhishGuardApi.request('/dashboard/activity');
    }
  },

  // Awareness & Quizzes Endpoints
  awareness: {
    getArticles() {
      return PhishGuardApi.request('/awareness/articles');
    },

    getQuizzes() {
      return PhishGuardApi.request('/awareness/quizzes');
    },

    submitQuiz(quizId, answers) {
      return PhishGuardApi.request('/awareness/quiz-results', {
        method: 'POST',
        body: JSON.stringify({ quizId, answers }),
      });
    }
  }
};

window.PhishGuardApi = PhishGuardApi;
