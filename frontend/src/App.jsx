import { useState } from "react";
import { ShieldAlert, LayoutDashboard, Bell, List, Upload as UploadIcon, BookOpen } from "lucide-react";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import Events from "./pages/Events";
import Upload from "./pages/Upload";
import Guide from "./pages/Guide";

const NAV = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "alerts",    label: "Alerts",    icon: Bell },
  { id: "events",    label: "Events",    icon: List },
  { id: "upload",    label: "Upload",    icon: UploadIcon },
  { id: "guide",     label: "Guide",     icon: BookOpen },
];

const PAGES = {
  dashboard: Dashboard,
  alerts: Alerts,
  events: Events,
  upload: Upload,
  guide: Guide,
};

export default function App() {
  const [active, setActive] = useState("dashboard");
  const Page = PAGES[active];

  return (
    <div className="flex min-h-screen bg-gray-100">
      {/* Sidebar */}
      <aside className="w-56 bg-gray-900 text-white flex flex-col">
        <div className="px-5 py-5 border-b border-gray-700">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600">
              <ShieldAlert size={18} className="text-white" />
            </div>
            <div>
              <p className="text-base font-bold tracking-wide text-white leading-tight">ThreatScope</p>
              <p className="text-xs text-gray-400 leading-tight">Windows Log Analyzer</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActive(id)}
              className={`w-full flex items-center gap-3 rounded-lg px-4 py-2.5 text-sm font-medium transition-colors ${
                active === id
                  ? "bg-blue-600 text-white"
                  : "text-gray-300 hover:bg-gray-700 hover:text-white"
              }`}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </nav>
        <div className="px-5 py-4 border-t border-gray-700 text-xs text-gray-500">
          ThreatScope v0.2.0
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-8 overflow-auto">
        <Page />
      </main>
    </div>
  );
}
