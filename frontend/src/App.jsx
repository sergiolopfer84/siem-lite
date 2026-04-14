import { useState } from "react";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Events from "./pages/Events";
import Upload from "./pages/Upload";

const NAV = [
  { id: "dashboard", label: "Dashboard" },
  { id: "alerts", label: "Alerts" },
  { id: "events", label: "Events" },
  { id: "upload", label: "Upload" },
];

const PAGES = {
  dashboard: Dashboard,
  alerts: Alerts,
  events: Events,
  upload: Upload,
};

export default function App() {
  const [active, setActive] = useState("dashboard");
  const Page = PAGES[active];

  return (
    <div className="flex min-h-screen bg-gray-100">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-900 text-white flex flex-col">
        <div className="px-6 py-5 border-b border-gray-700">
          <p className="text-lg font-bold tracking-wide text-white">SIEM-Lite</p>
          <p className="text-xs text-gray-400 mt-0.5">Sysmon Log Analyzer</p>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map((item) => (
            <button
              key={item.id}
              onClick={() => setActive(item.id)}
              className={`w-full text-left rounded-lg px-4 py-2.5 text-sm font-medium transition-colors ${
                active === item.id
                  ? "bg-blue-600 text-white"
                  : "text-gray-300 hover:bg-gray-700 hover:text-white"
              }`}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="px-6 py-4 border-t border-gray-700 text-xs text-gray-500">
          v0.1.0
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-auto">
        <Page />
      </main>
    </div>
  );
}
