"use client";

import { useMemo, useState } from "react";
import useSWR from "swr";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  HardDrive,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Zap,
} from "lucide-react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const API_BASE = "http://127.0.0.1:8000";
const ENTROPY_THRESHOLD = 7.2;

const fetcher = async (url: string) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
};

const fileName = (path?: string) =>
  path?.split(/[\\/]/).pop() || "unknown";

const time = (value?: string) => {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? value
    : d.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
};

export default function Dashboard() {
  const [scanning, setScanning] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [message, setMessage] = useState("");

  const { data: status, mutate: refreshStatus } = useSWR(
    `${API_BASE}/status`,
    fetcher,
    { refreshInterval: 2000 }
  );
  const { data: alerts, mutate: refreshAlerts } = useSWR(
    `${API_BASE}/alerts?limit=8`,
    fetcher,
    { refreshInterval: 3000 }
  );
  const { data: events, mutate: refreshEvents } = useSWR(
    `${API_BASE}/events?limit=20`,
    fetcher,
    { refreshInterval: 2000 }
  );

  const level = status?.threat_level || "Normal";
  const score = Math.round(status?.threat_score || 0);

  const chartData = useMemo(
    () =>
      (events || [])
        .slice()
        .reverse()
        .map((e: any, i: number) => ({
          n: i + 1,
          entropy: Number((e.entropy || 0).toFixed(2)),
        })),
    [events]
  );

  const scan = async () => {
    setScanning(true);
    setMessage("");
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: "./data/sandbox" }),
      });
      if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
      await res.json();
      await Promise.all([refreshStatus(), refreshAlerts(), refreshEvents()]);
      setMessage("Sandbox scan completed");
    } catch {
      setMessage("Scan failed — verify the API service");
    } finally {
      setScanning(false);
      setTimeout(() => setMessage(""), 4000);
    }
  };

  const refresh = () =>
    Promise.all([refreshStatus(), refreshAlerts(), refreshEvents()]);

  return (
    <main className="min-h-screen bg-[#070b12] text-slate-200">
      <div className="mx-auto max-w-[1500px] px-5 py-5 lg:px-7">
        <header className="border-b border-slate-800 pb-4">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md border border-indigo-500/30 bg-indigo-500/10">
                <ShieldAlert className="h-5 w-5 text-indigo-300" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-sm font-semibold tracking-wide text-white">
                    RDRS
                  </h1>
                  <span className="text-[10px] uppercase tracking-[.2em] text-slate-600">
                    Security Operations Console
                  </span>
                </div>
                <p className="mt-1 text-[11px] text-slate-500">
                  Heuristic ransomware detection · telemetry · response
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <StatusPill dot="bg-emerald-400" text="API CONNECTED" />
              <StatusPill dot="bg-amber-400" text="SIMULATION MODE" />
              <button
                onClick={refresh}
                className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-[11px] text-slate-400 hover:text-white"
              >
                <RefreshCw className="mr-1.5 inline h-3 w-3" />
                Refresh
              </button>
              <button
                onClick={scan}
                disabled={scanning}
                className="rounded-md bg-indigo-500 px-3 py-1.5 text-[11px] font-semibold text-white hover:bg-indigo-400 disabled:opacity-50"
              >
                {scanning ? (
                  <RefreshCw className="mr-1.5 inline h-3 w-3 animate-spin" />
                ) : (
                  <Search className="mr-1.5 inline h-3 w-3" />
                )}
                {scanning ? "Scanning..." : "Scan sandbox"}
              </button>
            </div>
          </div>
        </header>

        {message && (
          <div className="mt-3 rounded-md border border-indigo-500/20 bg-indigo-500/5 px-3 py-2 text-[11px] text-indigo-200">
            <CheckCircle2 className="mr-2 inline h-3.5 w-3.5" />
            {message}
          </div>
        )}

        <section className="mt-5 grid gap-3 lg:grid-cols-4">
          <Posture level={level} score={score} />
          <Metric
            label="EVENTS OBSERVED"
            value={status?.total_events_observed ?? 0}
            note="file telemetry"
            icon={<HardDrive />}
          />
          <Metric
            label="ALERTS RAISED"
            value={status?.total_alerts_raised ?? 0}
            note="heuristic triggers"
            icon={<AlertTriangle />}
          />
          <Metric
            label="INCIDENT RECORDS"
            value={status?.total_incidents_recorded ?? 0}
            note="evidence vault"
            icon={<ShieldCheck />}
          />
        </section>

        <section className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.65fr)_390px]">
          <Panel
            title="Entropy telemetry"
            subtitle="Rolling file-event observations"
            right={`THRESHOLD ${ENTROPY_THRESHOLD.toFixed(2)}`}
          >
            <div className="h-[300px] p-3">
              {chartData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={chartData}
                    margin={{ top: 8, right: 10, bottom: 2, left: -18 }}
                  >
                    <CartesianGrid
                      stroke="#1e293b"
                      strokeDasharray="2 5"
                      vertical={false}
                    />
                    <XAxis
                      dataKey="n"
                      stroke="#475569"
                      tick={{ fontSize: 10 }}
                      tickLine={false}
                      axisLine={false}
                    />
                    <YAxis
                      domain={[0, 8]}
                      stroke="#475569"
                      tick={{ fontSize: 10 }}
                      tickLine={false}
                      axisLine={false}
                    />
                    <ReferenceLine
                      y={ENTROPY_THRESHOLD}
                      stroke="#ef4444"
                      strokeDasharray="5 5"
                    />
                    <Tooltip
                      contentStyle={{
                        background: "#0b111c",
                        border: "1px solid #334155",
                        borderRadius: 5,
                        fontSize: 11,
                      }}
                      formatter={(value) => [String(value ?? ""), "Entropy"]}
                    />
                    <Line
                      type="monotone"
                      dataKey="entropy"
                      stroke="#818cf8"
                      strokeWidth={2}
                      dot={false}
                      isAnimationActive={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full items-center justify-center text-xs text-slate-600">
                  Waiting for telemetry...
                </div>
              )}
            </div>
            <div className="grid grid-cols-3 border-t border-slate-800">
              <Telemetry label="LATEST EVENT" value={events?.[0]?.event_type || "—"} />
              <Telemetry
                label="LATEST FILE"
                value={fileName(events?.[0]?.dest_path || events?.[0]?.src_path)}
              />
              <Telemetry
                label="LATEST TIME"
                value={time(events?.[0]?.timestamp)}
              />
            </div>
          </Panel>

          <Panel
            title="Detection queue"
            subtitle="Most recent heuristic decisions"
            right="LIVE"
          >
            <div className="max-h-[365px] overflow-y-auto">
              {alerts?.length ? (
                alerts.map((a: any) => (
                  <div
                    key={a.id}
                    className="border-b border-slate-800/80 px-4 py-3 last:border-0"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span
                        className={`rounded border px-2 py-1 text-[11px] font-semibold ${
                          a.severity === "Critical"
                            ? "border-red-500/30 bg-red-500/10 text-red-300"
                            : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                        }`}
                      >
                        {a.severity || "UNKNOWN"} · {a.score ?? "—"}
                      </span>
                      <span className="font-mono text-[12px] text-slate-400">
                        {time(a.timestamp)}
                      </span>
                    </div>
                    <p className="mt-2 text-[14px] font-medium leading-6 text-slate-200">
                      {a.rule_name}
                    </p>
                    <p className="mt-1 text-[13px] text-slate-400">
                      suspect{" "}
                      <span className="font-mono text-indigo-300">
                        {a.suspect_process || "Unknown"}
                      </span>{" "}
                      · pid {a.suspect_pid || 0}
                    </p>
                  </div>
                ))
              ) : (
                <div className="px-4 py-16 text-center text-xs text-slate-600">
                  No detection records.
                </div>
              )}
            </div>
          </Panel>
        </section>

        <section className="mt-5 rounded-lg border border-slate-800 bg-slate-900/40">
          <div className="flex flex-col gap-2 border-b border-slate-800 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <div className="flex items-center gap-2">
                <Terminal className="h-4 w-4 text-slate-500" />
                <h2 className="text-sm font-semibold">File event stream</h2>
              </div>
              <p className="mt-1 text-[13px] text-slate-400">
                Raw ingestion records · monitored sandbox
              </p>
            </div>
            <span className="font-mono text-[12px] text-slate-400">
              ./data/sandbox · LIMIT 20
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left">
              <thead className="border-b border-slate-800 bg-slate-950/40 text-[11px] font-semibold uppercase tracking-[.15em] text-slate-400">
                <tr>
                  <th className="px-4 py-2.5">Type</th>
                  <th className="px-4 py-2.5">File</th>
                  <th className="px-4 py-2.5">Entropy</th>
                  <th className="px-4 py-2.5">Timestamp</th>
                  <th className="px-4 py-3 text-right">Signal</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {events?.length ? (
                  events.map((e: any) => {
                    const entropy = Number(e.entropy || 0);
                    const elevated = entropy >= ENTROPY_THRESHOLD;
                    return (
                      <tr key={e.id} className="hover:bg-slate-800/20">
                        <td className="px-4 py-3 text-[13px] uppercase text-slate-400">
                          <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-indigo-400" />
                          {e.event_type || "unknown"}
                        </td>
                        <td
                          className="max-w-[420px] truncate px-4 py-3 font-mono text-[14px] font-medium text-slate-200"
                          title={e.dest_path || e.src_path}
                        >
                          {fileName(e.dest_path || e.src_path)}
                        </td>
                        <td className="px-4 py-3 font-mono text-[14px]">
                          <span className={elevated ? "font-semibold text-red-400" : "text-slate-500"}>
                            {entropy.toFixed(2)}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-[13px] text-slate-400">
                          {time(e.timestamp)}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {elevated ? (
                            <span className="text-[13px] font-semibold uppercase text-red-400">
                              <Zap className="mr-1 inline h-3 w-3" />
                              Elevated
                            </span>
                          ) : (
                            <span className="text-[13px] uppercase text-slate-500">
                              Baseline
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-xs text-slate-600">
                      No file events recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="flex justify-between border-t border-slate-900 py-4 text-[9px] text-slate-700">
          <span>RDRS v1.0.0 · local security research environment</span>
          <span>SIMULATION RESPONSE · NO PROCESS TERMINATION</span>
        </footer>
      </div>
    </main>
  );
}

function StatusPill({ dot, text }: { dot: string; text: string }) {
  return (
    <span className="rounded-md border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-[9px] font-semibold tracking-wide text-slate-500">
      <span className={`mr-1.5 inline-block h-1.5 w-1.5 rounded-full ${dot}`} />
      {text}
    </span>
  );
}

function Posture({ level, score }: { level: string; score: number }) {
  const critical = level === "Critical";
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/55 p-4">
      <div className="flex items-center justify-between">
        <p className="text-[9px] font-semibold uppercase tracking-[.18em] text-slate-600">
          Current threat posture
        </p>
        <Activity className="h-4 w-4 text-slate-600" />
      </div>
      <div className="mt-2 flex items-baseline gap-3">
        <span className={`text-2xl font-bold ${critical ? "text-red-400" : level === "Warning" ? "text-amber-300" : "text-emerald-300"}`}>
          {level.toUpperCase()}
        </span>
        <span className="font-mono text-[10px] text-slate-600">{score}/100</span>
      </div>
      <div className="mt-4 h-1 rounded-full bg-slate-800">
        <div
          className={`h-1 rounded-full ${critical ? "bg-red-500" : level === "Warning" ? "bg-amber-400" : "bg-emerald-400"}`}
          style={{ width: `${Math.min(score, 100)}%` }}
        />
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  note,
  icon,
}: {
  label: string;
  value: number;
  note: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/55 p-4">
      <div className="flex justify-between text-slate-600">
        <p className="text-[9px] font-semibold tracking-[.18em]">{label}</p>
        <span className="h-4 w-4">{icon}</span>
      </div>
      <p className="mt-2 font-mono text-2xl font-semibold text-slate-100">{value}</p>
      <p className="mt-1 text-[9px] text-slate-600">{note}</p>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle: string;
  right: string;
  children: React.ReactNode;
}) {
  return (
    <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/40">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <div>
          <h2 className="text-[16px] font-semibold text-slate-100">{title}</h2>
          <p className="mt-1 text-[13px] text-slate-400">{subtitle}</p>
        </div>
        <span className="font-mono text-[12px] text-slate-400">{right}</span>
      </div>
      {children}
    </div>
  );
}

function Telemetry({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-r border-slate-800 px-4 py-3 last:border-0">
      <p className="text-[8px] tracking-[.16em] text-slate-700">{label}</p>
      <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{value}</p>
    </div>
  );
}



