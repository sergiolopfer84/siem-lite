import { useEffect, useState } from "react";
import { api } from "../api";
import SeverityBadge from "../components/SeverityBadge";

const SEVERITIES = ["", "low", "medium", "high", "critical"];

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [severity, setSeverity] = useState("");
  const [error, setError] = useState(null);

  const load = () => {
    const params = {};
    if (severity) params.severity = severity;
    api.getAlerts(params)
      .then((data) => setAlerts(data.items))
      .catch((e) => setError(e.message));
  };

  useEffect(load, [severity]);

  const handleDelete = async (id) => {
    await api.deleteAlert(id);
    setAlerts((prev) => prev.filter((a) => a.id !== id));
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-800">Alerts</h2>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s || "All severities"}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="text-red-600">{error}</p>}

      {alerts.length === 0 ? (
        <p className="text-gray-400">No alerts found.</p>
      ) : (
        <div className="overflow-hidden rounded-xl border border-gray-200 bg-white shadow-sm">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Rule</th>
                <th className="px-4 py-3">MITRE</th>
                <th className="px-4 py-3">Description</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {alerts.map((a) => (
                <tr key={a.id} className="hover:bg-gray-50">
                  <td className="whitespace-nowrap px-4 py-2 text-gray-500">
                    {new Date(a.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={a.severity} />
                  </td>
                  <td className="px-4 py-2 font-medium text-gray-800">{a.rule_name}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">
                    {a.mitre_technique && (
                      <span className="rounded bg-gray-100 px-1.5 py-0.5">{a.mitre_technique}</span>
                    )}
                  </td>
                  <td className="max-w-xs truncate px-4 py-2 text-gray-600">{a.description}</td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => handleDelete(a.id)}
                      className="text-xs text-red-500 hover:text-red-700"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
