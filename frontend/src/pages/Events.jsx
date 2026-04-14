import { useEffect, useState } from "react";
import { api } from "../api";

export default function Events() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [error, setError] = useState(null);
  const LIMIT = 50;

  useEffect(() => {
    api.getEvents({ skip: page * LIMIT, limit: LIMIT })
      .then((data) => {
        setEvents(data.items);
        setTotal(data.total);
      })
      .catch((e) => setError(e.message));
  }, [page]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-800">
          Events <span className="text-base font-normal text-gray-500">({total} total)</span>
        </h2>
      </div>

      {error && <p className="text-red-600">{error}</p>}

      {events.length === 0 ? (
        <p className="text-gray-400">No events found.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-xl border border-gray-200 bg-white shadow-sm">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 text-left text-xs font-semibold uppercase text-gray-500">
                <tr>
                  <th className="px-4 py-3">Event ID</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Computer</th>
                  <th className="px-4 py-3">Process</th>
                  <th className="px-4 py-3">Command Line</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {events.map((e) => (
                  <tr key={e.id} className="hover:bg-gray-50">
                    <td className="px-4 py-2">
                      <span className="rounded bg-blue-50 px-1.5 py-0.5 text-xs font-mono text-blue-700">
                        {e.event_id}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-gray-500">
                      {e.timestamp ? new Date(e.timestamp).toLocaleString() : "–"}
                    </td>
                    <td className="px-4 py-2 text-gray-700">{e.computer || "–"}</td>
                    <td className="max-w-[160px] truncate px-4 py-2 font-mono text-xs text-gray-600">
                      {e.process_name || "–"}
                    </td>
                    <td className="max-w-xs truncate px-4 py-2 font-mono text-xs text-gray-500">
                      {e.command_line || "–"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex items-center gap-3 text-sm">
            <button
              disabled={page === 0}
              onClick={() => setPage((p) => p - 1)}
              className="rounded-lg border px-3 py-1.5 disabled:opacity-40 hover:bg-gray-50"
            >
              Prev
            </button>
            <span className="text-gray-600">
              Page {page + 1} / {Math.ceil(total / LIMIT) || 1}
            </span>
            <button
              disabled={(page + 1) * LIMIT >= total}
              onClick={() => setPage((p) => p + 1)}
              className="rounded-lg border px-3 py-1.5 disabled:opacity-40 hover:bg-gray-50"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}
