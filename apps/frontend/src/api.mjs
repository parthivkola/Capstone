function configuredApiBase() {
  const configured = import.meta.env?.VITE_API_BASE_URL || globalThis.SENTINEL_API_BASE_URL;
  return (configured || 'http://127.0.0.1:18000/api/v1').replace(/\/$/, '');
}

function resolveApiBase() {
  const configured = configuredApiBase();
  if (typeof window === 'undefined' || !window.location?.hostname) {
    return configured;
  }
  const pageHost = window.location.hostname;
  if (pageHost !== 'localhost' && pageHost !== '127.0.0.1') {
    return configured;
  }
  try {
    const url = new URL(configured);
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
      url.hostname = pageHost;
      return url.toString().replace(/\/$/, '');
    }
  } catch {
    return configured;
  }
  return configured;
}

export const API_BASE = resolveApiBase();

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  let body;
  try {
    body = await response.json();
  } catch {
    throw new ApiError(response.status, 'The API returned an unreadable response.');
  }
  if (!response.ok) {
    throw new ApiError(response.status, body?.error?.message || body?.error || `Request failed (${response.status})`);
  }
  return body;
}

export const get = (path) => request(path);
export const post = (path, payload = {}) => request(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
});
