import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client';

interface ProviderConfig { id: string; provider: string; base_url: string | null; is_active: boolean; created_at: string; }

export default function Providers() {
  const { projectId } = useParams<{ projectId: string }>();
  const [configs, setConfigs] = useState<ProviderConfig[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [provider, setProvider] = useState<'openai' | 'anthropic'>('openai');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => { fetchConfigs(); }, [projectId]);

  const fetchConfigs = async () => {
    setLoading(true);
    try { const res = await api.get(`/admin/projects/${projectId}/providers`); setConfigs(res.data); }
    finally { setLoading(false); }
  };

  const resetForm = () => { setProvider('openai'); setApiKey(''); setBaseUrl(''); setShowCreate(false); setEditingId(null); };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.post(`/admin/projects/${projectId}/providers`, { provider, api_key: apiKey, base_url: baseUrl || null });
    resetForm(); fetchConfigs();
  };

  const handleUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingId) return;
    const payload: any = {};
    if (apiKey) payload.api_key = apiKey;
    if (baseUrl !== undefined) payload.base_url = baseUrl || null;
    await api.patch(`/admin/projects/${projectId}/providers/${editingId}`, payload);
    resetForm(); fetchConfigs();
  };

  const handleToggleActive = async (config: ProviderConfig) => {
    await api.patch(`/admin/projects/${projectId}/providers/${config.id}`, { is_active: !config.is_active });
    fetchConfigs();
  };

  const startEdit = (config: ProviderConfig) => {
    setEditingId(config.id);
    setProvider(config.provider as 'openai' | 'anthropic');
    setApiKey('');
    setBaseUrl(config.base_url || '');
    setShowCreate(true);
  };

  return (
    <div>
      <div className="mb-4"><Link to="/projects" className="text-primary-600 hover:underline">← Back to Projects</Link></div>
      <h1 className="text-3xl font-bold mb-2">Provider Configurations</h1>
      <p className="text-gray-600 mb-6">Upstream API keys are encrypted at rest. They are never returned to the dashboard.</p>

      <button onClick={() => { resetForm(); setShowCreate(true); }} className="bg-primary-600 text-white px-4 py-2 rounded-md hover:bg-primary-700 mb-6">+ Add Provider</button>

      {showCreate && (
        <div className="bg-white p-6 rounded-lg shadow mb-6">
          <h2 className="text-lg font-semibold mb-4">{editingId ? 'Update Provider' : 'Add Provider'}</h2>
          <form onSubmit={editingId ? handleUpdate : handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Provider</label>
              <select value={provider} onChange={(e) => setProvider(e.target.value as any)} disabled={!!editingId} className="w-full px-3 py-2 border border-gray-300 rounded-md disabled:bg-gray-100">
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">API Key {editingId && <span className="text-gray-500">(leave blank to keep current)</span>}</label>
              <input type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} required={!editingId} placeholder={editingId ? '••••••••••••' : 'sk-...'} className="w-full px-3 py-2 border border-gray-300 rounded-md font-mono" />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Base URL <span className="text-gray-500">(optional)</span></label>
              <input type="url" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://api.openai.com" className="w-full px-3 py-2 border border-gray-300 rounded-md" />
            </div>
            <div className="flex gap-2">
              <button type="submit" className="bg-primary-600 text-white px-4 py-2 rounded-md">{editingId ? 'Update' : 'Create'}</button>
              <button type="button" onClick={resetForm} className="bg-gray-200 px-4 py-2 rounded-md">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Provider</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Base URL</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500">Loading...</td></tr>
            ) : configs.length === 0 ? (
              <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500">No providers configured</td></tr>
            ) : (
              configs.map((config) => (
                <tr key={config.id}>
                  <td className="px-6 py-4 font-medium capitalize">{config.provider}</td>
                  <td className="px-6 py-4 font-mono text-sm text-gray-600">{config.base_url || <span className="text-gray-400">(default)</span>}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${config.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                      {config.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">{new Date(config.created_at).toLocaleDateString()}</td>
                  <td className="px-6 py-4 space-x-3">
                    <button onClick={() => startEdit(config)} className="text-primary-600 hover:underline text-sm">Edit</button>
                    <button onClick={() => handleToggleActive(config)} className="text-gray-600 hover:underline text-sm">{config.is_active ? 'Disable' : 'Enable'}</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
