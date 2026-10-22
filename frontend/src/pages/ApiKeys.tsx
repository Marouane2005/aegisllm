import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client';

interface ApiKey { id: string; name: string; key_prefix: string; is_active: boolean; created_at: string; last_used_at: string | null; }

export default function ApiKeys() {
  const { projectId } = useParams<{ projectId: string }>();
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => { fetchKeys(); }, [projectId]);

  const fetchKeys = async () => {
    setLoading(true);
    try { const res = await api.get(`/admin/projects/${projectId}/api-keys`); setKeys(res.data); }
    finally { setLoading(false); }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await api.post(`/admin/projects/${projectId}/api-keys`, { name });
    setNewKey(res.data.key);
    setShowCreate(false);
    setName('');
    fetchKeys();
  };

  const handleRevoke = async (keyId: string) => {
    if (!confirm('Revoke this API key?')) return;
    await api.delete(`/admin/projects/${projectId}/api-keys/${keyId}`);
    fetchKeys();
  };

  const handleCopy = () => {
    if (newKey) {
      navigator.clipboard.writeText(newKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div>
      <div className="mb-4"><Link to="/projects" className="text-primary-600 hover:underline">← Back to Projects</Link></div>
      <h1 className="text-3xl font-bold mb-6">API Keys</h1>

      {newKey && (
        <div className="bg-yellow-50 border-2 border-yellow-400 p-6 rounded-lg mb-6">
          <h2 className="text-lg font-semibold mb-2 text-yellow-800">⚠️ Save this key now — it will never be shown again!</h2>
          <p className="text-sm text-yellow-700 mb-3">Use this as the <code className="bg-yellow-100 px-1 rounded">Authorization: Bearer ...</code> header.</p>
          <div className="flex gap-2">
            <input type="text" value={newKey} readOnly className="flex-1 px-3 py-2 border border-gray-300 rounded-md font-mono text-sm bg-white" />
            <button onClick={handleCopy} className="bg-primary-600 text-white px-4 py-2 rounded-md hover:bg-primary-700">{copied ? '✓ Copied' : 'Copy'}</button>
          </div>
          <button onClick={() => setNewKey(null)} className="mt-3 text-sm text-yellow-800 hover:underline">I've saved it, dismiss</button>
        </div>
      )}

      <button onClick={() => setShowCreate(true)} className="bg-primary-600 text-white px-4 py-2 rounded-md hover:bg-primary-700 mb-6">+ New API Key</button>

      {showCreate && (
        <div className="bg-white p-6 rounded-lg shadow mb-6">
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Key Name</label>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} required maxLength={100} className="w-full px-3 py-2 border border-gray-300 rounded-md" />
            </div>
            <div className="flex gap-2">
              <button type="submit" className="bg-primary-600 text-white px-4 py-2 rounded-md">Create</button>
              <button type="button" onClick={() => setShowCreate(false)} className="bg-gray-200 px-4 py-2 rounded-md">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Prefix</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Used</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading ? (
              <tr><td colSpan={6} className="px-6 py-8 text-center text-gray-500">Loading...</td></tr>
            ) : keys.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-8 text-center text-gray-500">No API keys yet</td></tr>
            ) : (
              keys.map((key) => (
                <tr key={key.id}>
                  <td className="px-6 py-4 font-medium">{key.name}</td>
                  <td className="px-6 py-4 font-mono text-sm text-gray-600">{key.key_prefix}</td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded-full ${key.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                      {key.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600">{new Date(key.created_at).toLocaleDateString()}</td>
                  <td className="px-6 py-4 text-sm text-gray-600">{key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}</td>
                  <td className="px-6 py-4">
                    {key.is_active && <button onClick={() => handleRevoke(key.id)} className="text-red-600 hover:underline text-sm">Revoke</button>}
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
