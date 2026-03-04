const API_BASE = '/api/v1';

interface ApiResponse<T> {
  data: T | null;
  error: string | null;
}

export interface User {
  id: string;
  username: string;
  role: string;
}

export interface AuthResponse {
  token: string;
  user: User;
}

export interface ScanSummary {
  id: string;
  target: string;
  scan_type: string;
  status: string;
  finding_count: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface Scan extends ScanSummary {
  options: Record<string, unknown>;
  output: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  category: string;
  evidence: string;
  recommendation: string;
}

export interface Stats {
  total_scans: number;
  active_scans: number;
  completed_scans: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  recent_scans: ScanSummary[];
}

export interface GuideTopic {
  topic: string;
  title: string;
  description: string;
}

export interface Guide {
  title: string;
  content: string;
}

let authToken: string | null = localStorage.getItem('pent_token');

export function setToken(token: string | null): void {
  authToken = token;
  if (token) {
    localStorage.setItem('pent_token', token);
  } else {
    localStorage.removeItem('pent_token');
  }
}

export function getToken(): string | null {
  return authToken;
}

async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      const errorMessage =
        errorBody.error || errorBody.message || `Request failed with status ${response.status}`;
      return { data: null, error: errorMessage };
    }

    const data = await response.json();
    return { data: data as T, error: null };
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : 'Network error',
    };
  }
}

export async function login(
  username: string,
  password: string
): Promise<ApiResponse<AuthResponse>> {
  const result = await request<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (result.data) {
    setToken(result.data.token);
  }
  return result;
}

export async function register(
  username: string,
  password: string
): Promise<ApiResponse<AuthResponse>> {
  const result = await request<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  if (result.data) {
    setToken(result.data.token);
  }
  return result;
}

export async function getScans(): Promise<ApiResponse<ScanSummary[]>> {
  return request<ScanSummary[]>('/scans');
}

export async function getScan(id: string): Promise<ApiResponse<Scan>> {
  return request<Scan>(`/scans/${id}`);
}

export async function startScan(
  target: string,
  scanType: string,
  options: Record<string, unknown> = {}
): Promise<ApiResponse<Scan>> {
  return request<Scan>('/scans', {
    method: 'POST',
    body: JSON.stringify({ target, scan_type: scanType, options }),
  });
}

export async function getScanFindings(
  scanId: string
): Promise<ApiResponse<Finding[]>> {
  return request<Finding[]>(`/scans/${scanId}/findings`);
}

export async function getStats(): Promise<ApiResponse<Stats>> {
  return request<Stats>('/stats');
}

export async function getGuides(): Promise<ApiResponse<GuideTopic[]>> {
  return request<GuideTopic[]>('/guides');
}

export async function getGuide(topic: string): Promise<ApiResponse<Guide>> {
  return request<Guide>(`/guides/${topic}`);
}

export async function exportScanReport(
  scanId: string,
  format: 'md' | 'html' | 'json'
): Promise<Blob | null> {
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  try {
    const response = await fetch(
      `${API_BASE}/scans/${scanId}/export?format=${format}`,
      { headers }
    );
    if (!response.ok) return null;
    return await response.blob();
  } catch {
    return null;
  }
}
