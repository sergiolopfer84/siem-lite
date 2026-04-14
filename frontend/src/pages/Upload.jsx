import { useRef, useState } from "react";
import { api } from "../api";

export default function Upload() {
  const inputRef = useRef(null);
  const [status, setStatus] = useState(null); // null | "loading" | "done" | "error"
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setStatus("loading");
    setResult(null);
    setErrorMsg("");
    try {
      const data = await api.uploadEvtx(file);
      setResult(data);
      setStatus("done");
    } catch (err) {
      setErrorMsg(err.message);
      setStatus("error");
    }
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-gray-800">Upload EVTX</h2>

      <div
        onClick={() => inputRef.current?.click()}
        className="flex cursor-pointer flex-col items-center justify-center rounded-2xl border-2 border-dashed border-blue-300 bg-blue-50 px-8 py-16 text-center hover:bg-blue-100 transition-colors"
      >
        <svg
          className="mb-3 h-10 w-10 text-blue-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5m-13.5-9L12 3m0 0 4.5 4.5M12 3v13.5"
          />
        </svg>
        <p className="text-sm text-blue-600 font-medium">Click to select a .evtx file</p>
        <p className="mt-1 text-xs text-blue-400">Sysmon Windows Event Log format</p>
        <input
          ref={inputRef}
          type="file"
          accept=".evtx"
          className="hidden"
          onChange={handleUpload}
        />
      </div>

      {status === "loading" && (
        <div className="rounded-xl bg-yellow-50 border border-yellow-200 p-4 text-yellow-700">
          Parsing and analysing log… please wait.
        </div>
      )}

      {status === "error" && (
        <div className="rounded-xl bg-red-50 border border-red-200 p-4 text-red-700">
          Error: {errorMsg}
        </div>
      )}

      {status === "done" && result && (
        <div className="rounded-xl bg-green-50 border border-green-200 p-4 space-y-1">
          <p className="font-semibold text-green-800">Upload complete</p>
          <p className="text-sm text-green-700">Events parsed: {result.events_parsed}</p>
          <p className="text-sm text-green-700">Alerts triggered: {result.alerts_triggered}</p>
          {result.alert_rules?.length > 0 && (
            <ul className="mt-2 list-disc pl-5 text-sm text-green-700">
              {result.alert_rules.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
