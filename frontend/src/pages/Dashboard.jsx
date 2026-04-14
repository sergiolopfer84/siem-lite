import { useEffect, useState } from "react";
import { api } from "../api";
import StatCard from "../components/StatCard";
import SeverityBadge from "../components/SeverityBadge";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api.getStats()
      .then(setStats)
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <p className="text-red-600">Error: {error}</p>;
  if (!stats) return <p className="text-gray-500">Loading…</p>;

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-800">Dashboard</h2>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard title="Total Events" value={stats.total_events} color="blue" />
        <StatCard title="Total Alerts" value={stats.total_alerts} color="red" />
        <StatCard title="Critical" value={stats.severity_counts.critical} color="red" />
        <StatCard title="High" value={stats.severity_counts.high} color="orange" />
        <StatCard title="Medium" value={stats.severity_counts.medium} color="yellow" />
        <StatCard title="Low" value={stats.severity_counts.low} color="green" />
      </div>

      <div>
        <h3 className="mb-3 text-lg font-semibold text-gray-700">Recent Alerts</h3>
        {stats.recent_alerts.length === 0 ? (
          <p className="text-gray-400">No alerts yet. Upload an .evtx file to start.</p>
        ) : (
          <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Rule</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {stats.recent_alerts.map((a) => (
                  <tr key={a.id} className="hover:bg-gray-50">
                    <td className="px-4 py-2 text-gray-500">
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-4 py-2 font-medium text-gray-800">{a.rule_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
