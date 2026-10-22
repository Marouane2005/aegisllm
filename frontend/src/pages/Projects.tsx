import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client';

interface Project { id: string; name: string; retention_days: number; created_at: string; }

export default function Projects() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState('');
  const [retentionDays, setRetentionDays] = useState(30);

  useEffect(() => { fetchProjects(); }, []);

  const fetchProjects = async () => {
    const res = await api.get('/admin/projects');
    setProjects(res.data);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await api.post('/admin/projects', { name, retention_days: retentionDays });
    setShowCreate(false);
    setName('');
    setRetentionDays(30);
    fetchProjects();
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Projects</h1>
        <button onClick={() => setShowCreate(true)} className="bg-primary-600 text-white px-4 py-2 rounded-md hover:bg-primary-700">+ New Project</button>
      </div>

      {showCreate && (
        <div className="bg-white p-6 rounded-lg shadow mb-6">
          <h2 className="text-lg font-semibold mb-4">Create Project</h2>
          <form onSubmit={handleCreate} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Name</label>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)} required className="w-full px-3 py-2 border border-gray-300 rounded-md" />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Retention (days)</label>
              <input type="number" value={retentionDays} onChange={(e) => setRetentionDays(Number(e.target.value))} min={1} max={365} className="w-full px-3 py-2 border border-gray-300 rounded-md" />
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
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Retention</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {projects.map((project) => (
              <tr key={project.id}>
                <td className="px-6 py-4">{project.name}</td>
                <td className="px-6 py-4">{project.retention_days} days</td>
                <td className="px-6 py-4">{new Date(project.created_at).toLocaleDateString()}</td>
                <td className="px-6 py-4">
                  <Link to={`/projects/${project.id}/api-keys`} className="text-primary-600 hover:underline mr-4">API Keys</Link>
                  <Link to={`/projects/${project.id}/providers`} className="text-primary-600 hover:underline">Providers</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
