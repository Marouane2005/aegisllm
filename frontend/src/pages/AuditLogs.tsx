import { useState, useEffect } from 'react';
import api from '../api/client';

interface AuditLog { id: string; request_id: string; provider: string; model: string; timestamp: string; latency_ms: number; input_tokens: number; output_tokens: number; action_taken: string; threat_summary: any; status_code: number; client_ip: string | null; }
interface AuditPayload { id: string; audit_log_id: string; masked_request: string | null; masked_response: string | null; raw_request?: string | null; raw_response?: string | null; }
interface Project { id: string; name: string; }

export default function AuditLogs() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<string>('');
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [totalCount, setTotalCount] = useState(0);
  const [actionFilter, setActionFilter] = useState('');
  const [providerFilter, setProviderFilter] = useState('');
  const [requestIdFilter, setRequestIdFilter] = useState('');
  const [startTime, setStartTime] = useState('');
  const [endTime, setEndTime] = useState('');
  const [selectedLog, setSelectedLog] = useState<AuditLog | null>(null);
  const [payload, setPayload] = useState<AuditPayload | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [payloadLoading, setPayloadLoading] = useState(false);

  useEffect(() => {
    api.get('/admin/projects').then((res) => {
      setProjects(res.data);
      if (res.data.length > 0 && !projectId) setProjectId(res.data[0].id);
    });
  }, []);

  useEffect(() => { if (projectId) fetchLogs(true); }, [projectId, actionFilter, providerFilter, requestIdFilter, startTime, endTime]);

  const fetchLogs = async (reset: boolean) => {
    if (!projectId) return;
    setLoading(true);
    try {
      const params: any = { limit: 50 };
      if (!reset && nextCursor) params.cursor = nextCursor;
      if (actionFilter) params.action_taken = actionFilter;
      if (providerFilter) params.provider = providerFilter;
      if (requestIdFilter) params.request_id = requestIdFilter;
      if (startTime) params.start_time = new Date(startTime).toISOString();
      if (endTime) params.end_time = new Date(endTime).toISOString();
      const res = await api.get(`/admin/projects/${projectId}/audit-logs`, { params });
      if (reset) setLogs(res.data.items);
      else setLogs((prev) => [...prev, ...res.data.items]);
      setNextCursor(res.data.next_cursor);
      setTotalCount(res.data.total_count);
    } finally { setLoading(false); }
  };

  const openDetail = async (log: AuditLog) => {
    setSelectedLog(log); setShowRaw(false); setPayloadLoading(true); setPayload(null);
    try {
      const res = await api.get(`/admin/projects/${projectId}/audit-logs/${log.id}`, { params: { include_raw: false } });
      setPayload(res.data);
    } finally { setPayloadLoading(false); }
  };

  const loadRawPayload = async () => {
    if (!selectedLog) return;
    setPayloadLoading(true);
    try {
      const res = await api.get(`/admin/projects/${projectId}/audit-logs/${selectedLog.id}`, { params: { include_raw: true } });
      setPayload(res.data);
    } catch (err: any) {
      const status = err?.response?.status;
      alert(status === 403 ? 'Raw payloads are restricted to admins.' : 'Failed to load raw payload.');
      setShowRaw(false);
    } finally { setPayloadLoading(false); }
  };

  const actionColor = (action: string) => {
    switch (action) {
      case 'blocked': return 'bg-red-100 text-red-800';
      case 'masked': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-green-100 text-green-800';
    }
  };

  return (
    <div>
      <h1 className="text-3xl font-bold mb-6">Audit Logs</h1>

      <div className="bg-white p-4 rounded-lg shadow mb-4">
        <label className="block text-sm font-medium mb-2">Project</label>
        <select value={projectId} onChange={(e) => setProjectId(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md">
          {projects.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="bg-white p-4 rounded-lg shadow mb-4">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md">
            <option value="">All actions</option>
            <option value="allowed">Allowed</option>
            <option value="masked">Masked</option>
            <option value="blocked">Blocked</option>
          </select>
          <input type="text" placeholder="Provider" value={providerFilter} onChange={(e) => setProviderFilter(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md" />
          <input type="text" placeholder="Request ID" value={requestIdFilter} onChange={(e) => setRequestIdFilter(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md font-mono text-sm" />
          <input type="datetime-local" value={startTime} onChange={(e) => setStartTime(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md text-sm" />
          <input type="datetime-local" value={endTime} onChange={(e) => setEndTime(e.target.value)} className="px-3 py-2 border border-gray-300 rounded-md text-sm" />
        </div>
      </div>

      <p className="text-sm text-gray-600 mb-2">Showing {logs.length} of {totalCount} total requests</p>

      <div className="bg-white rounded-lg shadow overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Provider</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Model</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Latency</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tokens</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Request ID</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading && logs.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">Loading...</td></tr>
            ) : logs.length === 0 ? (
              <tr><td colSpan={8} className="px-4 py-8 text-center text-gray-500">No logs found</td></tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} onClick={() => openDetail(log)} className="hover:bg-gray-50 cursor-pointer">
                  <td className="px-4 py-3 text-sm">{new Date(log.timestamp).toLocaleString()}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-1 text-xs rounded-full ${actionColor(log.action_taken)}`}>{log.action_taken}</span></td>
                  <td className="px-4 py-3 text-sm">{log.provider}</td>
                  <td className="px-4 py-3 text-sm font-mono">{log.model}</td>
                  <td className="px-4 py-3 text-sm">{log.latency_ms}ms</td>
                  <td className="px-4 py-3 text-sm">{log.input_tokens + log.output_tokens}</td>
                  <td className="px-4 py-3 text-sm">{log.status_code}</td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-500">{log.request_id.substring(0, 8)}...</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {nextCursor && (
        <button onClick={() => fetchLogs(false)} disabled={loading} className="mt-4 bg-gray-200 px-4 py-2 rounded-md hover:bg-gray-300 disabled:opacity-50">
          {loading ? 'Loading...' : 'Load more'}
        </button>
      )}

      {selectedLog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={() => setSelectedLog(null)}>
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
            <div className="p-6 border-b border-gray-200 flex justify-between items-start">
              <div>
                <h2 className="text-xl font-bold">Request Detail</h2>
                <p className="text-sm text-gray-500 font-mono mt-1">{selectedLog.request_id}</p>
              </div>
              <button onClick={() => setSelectedLog(null)} className="text-gray-400 hover:text-gray-600 text-2xl">×</button>
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div><p className="text-xs text-gray-500 uppercase">Action</p><p className={`inline-block px-2 py-1 text-xs rounded-full mt-1 ${actionColor(selectedLog.action_taken)}`}>{selectedLog.action_taken}</p></div>
                <div><p className="text-xs text-gray-500 uppercase">Provider</p><p className="font-medium">{selectedLog.provider}</p></div>
                <div><p className="text-xs text-gray-500 uppercase">Latency</p><p className="font-medium">{selectedLog.latency_ms}ms</p></div>
                <div><p className="text-xs text-gray-500 uppercase">Tokens</p><p className="font-medium">{selectedLog.input_tokens} in / {selectedLog.output_tokens} out</p></div>
              </div>

              {Object.keys(selectedLog.threat_summary || {}).length > 0 && (
                <div className="bg-red-50 border border-red-200 p-4 rounded-md">
                  <h3 className="font-semibold text-red-800 mb-2">Threat Summary</h3>
                  <pre className="text-xs overflow-auto text-red-900">{JSON.stringify(selectedLog.threat_summary, null, 2)}</pre>
                </div>
              )}

              <div className="flex items-center gap-4">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={showRaw} onChange={(e) => {
                    setShowRaw(e.target.checked);
                    if (e.target.checked && payload && !payload.raw_request) loadRawPayload();
                  }} />
                  <span className="text-sm">Show raw (unmasked) payloads</span>
                </label>
                {payloadLoading && <span className="text-sm text-gray-500">Loading...</span>}
              </div>

              {payload && (
                <div className="space-y-4">
                  <div>
                    <h3 className="font-semibold mb-2">Request</h3>
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-xs overflow-auto max-h-64">
                      {(showRaw && payload.raw_request) ? payload.raw_request : (payload.masked_request || '(empty)')}
                    </pre>
                  </div>
                  <div>
                    <h3 className="font-semibold mb-2">Response</h3>
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-md text-xs overflow-auto max-h-64">
                      {(showRaw && payload.raw_response) ? payload.raw_response : (payload.masked_response || '(empty)')}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
