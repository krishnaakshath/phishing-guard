// Small fetch wrapper for the Phishing Guard backend.
// Reads the API key from localStorage and attaches it as X-API-Key when present.

export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'
export const API_KEY_STORAGE_KEY = 'pg_api_key'

export function getApiKey() {
  return localStorage.getItem(API_KEY_STORAGE_KEY)
}

export function setApiKey(key) {
  if (key) {
    localStorage.setItem(API_KEY_STORAGE_KEY, key)
  } else {
    localStorage.removeItem(API_KEY_STORAGE_KEY)
  }
}

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const key = getApiKey()
  if (key) {
    headers['X-API-Key'] = key
  }

  let res
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new ApiError('Could not reach the Phishing Guard API. Is the backend running?', 0, null)
  }

  let data = null
  try {
    data = await res.json()
  } catch {
    // No JSON body (e.g. empty 204) - that's fine.
  }

  if (!res.ok) {
    const message = (data && data.error) || res.statusText || 'Request failed'
    throw new ApiError(message, res.status, data)
  }

  return data
}

export const apiGet = (path) => request('GET', path)
export const apiPost = (path, body) => request('POST', path, body)
export const apiPut = (path, body) => request('PUT', path, body)
export const apiDelete = (path) => request('DELETE', path)
