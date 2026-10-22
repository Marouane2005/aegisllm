import { useState, useEffect } from 'react';
import api from '../api/client';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';

interface Project { id: string; name: string; }
interface Metrics {
  total_requests: number; blocked_requests: number; masked_requests: number; allowed_requests: number;
  avg_latency_ms: number; p95_latency_ms: number;
  total_input_tokens: number; total_output_tokens: number;
  requests_by_provider: Record<string, number>; requests_by_action: Record<string, number>;
}

const COLORS = ['#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#8b5cf6'];

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<string>('');
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [hours, setHours] = useState(24);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get('/admin/projects').then((res) => {
      setProjects(res.data);
      if (res.data.length > 0) setProjectId(res.data[0].id);
    });
  }, []);

  useEffect(() => {
    if (!projectId) return;
    setLoading(true);
    api.get(`/admin/projects/${projectId}/metrics`, { params: { hours } })
      .then((res) => setMetrics(res.data))
      .catch(() => setMetrics(null))
      .finally(() => setLoading(false));
  }, [projectId, hours]);

  const actionData = metrics ? Object.entries(metrics.requests_by_action).map(([action, count]) => ({ action, count })) : [];
  const providerData = metrics ? Object.entries(metrics.requests_by_provider).map(([provider, count]) => ({ provider, count })) : [];

  return (
    <div>
      <div className="flex flex-wrap justify-between items-center mb-6 gap-4">
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <div className="flex gap-2">
          <select value={projectId} onChange={(e) => setProjectId(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md">
            {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select value={hours} onChange={(e) => setHours(Number(e.target.value))} className="px-3 py-2 border border-gray-300 rounded-md">
            <option value={1}>Last hour</option>
            <option value={24}>Last 24 hours</option>
            <option value={168}>Last 7 days</option>
            <option value={720}>Last 30 days</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading metrics...</div>
      ) : !metrics || metrics.total_requests === 0 ? (
        <div className="bg-white p-12 rounded-lg shadow text-center text-gray-500">
          No requests in this time window. Send a request through the proxy to see metrics.
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="bg-white p-6 rounded-lg shadow">
              <p className="text-sm text-gray-600">Total Requests</p>
              <p className="text-3xl font-bold">{metrics.total_requests.toLocaleString()}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <p className="text-sm text-gray-600">Blocked</p>
              <p className="text-3xl font-bold text-red-600">{metrics.blocked_requests}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <p className="text-sm text-gray-600">Masked (PII)</p>
              <p className="text-3xl font-bold text-yellow-600">{metrics.masked_requests}</p>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <p className="text-sm text-gray-600">P95 Latency</p>
              <p className="text-3xl font-bold">{metrics.p95_latency_ms}ms</p>
              <p className="text-xs text-gray-500">avg: {metrics.avg_latency_ms}ms</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-lg font-semibold mb-4">Requests by Action</h2>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={actionData} dataKey="count" nameKey="action" cx="50%" cy="50%" outerRadius={90} label>
                    {actionData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Tooltip /><Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="bg-white p-6 rounded-lg shadow">
              <h2 className="text-lg font-semibold mb-4">Requests by Provider</h2>
              <ResponsiveContainer width="100%" height={280}>
                <BarChart data={providerData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="provider" /><YAxis /><Tooltip />
                  <Bar dataKey="count" fill="#0ea5e9" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="bg-white p-6 rounded-lg shadow">
            <h2 className="text-lg font-semibold mb-4">Token Usage</h2>
            <div className="grid grid-cols-2 gap-4">
              <div><p className="text-sm text-gray-600">Input Tokens</p><p className="text-2xl font-bold">{metrics.total_input_tokens.toLocaleString()}</p></div>
              <div><p className="text-sm text-gray-600">Output Tokens</p><p className="text-2xl font-bold">{metrics.total_output_tokens.toLocaleString()}</p></div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
