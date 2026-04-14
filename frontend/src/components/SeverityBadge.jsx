const SEVERITY_STYLES = {
  low: "bg-green-100 text-green-800",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export default function SeverityBadge({ severity }) {
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-semibold uppercase ${
        SEVERITY_STYLES[severity] ?? "bg-gray-100 text-gray-700"
      }`}
    >
      {severity}
    </span>
  );
}
