"use client";

import React, { useState } from "react";
import useSWR from "swr";
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  HardDrive,
  AlertTriangle,
  FileCode,
  RefreshCw,
  Search,
  CheckCircle2,
  Terminal as TerminalIcon,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

const API_BASE = "http://127.0.0.1:8000";
const fetcher = (url: string) => fetch(url).then((res) => res.json());

export default function Dashboard() {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any>(null);

  // Auto-polling SWR hooks
  const { data: status } = useSWR(`${API_BASE}/status`, fetcher, {
    refreshInterval: 2000,
  });
  const { data: alerts } = useSWR(`${API_BASE}/alerts?limit=8`, fetcher, {
    refreshInterval: 3000,
  });
  const { data: events } = useSWR(`${API_BASE}/events?limit=20`, fetcher, {
    refreshInterval: 2000,
  });

  const triggerScan = async () => {
    setScanning(true);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_path: "./data/sandbox" }),
      });
      const data = await res.json();
      setScanResult(data);
    } catch (e) {
      console.error(e);
    } finally {
      setScanning(false);
    }
  };

  // Format entropy telemetry for chart
  const chartData = (events || [])
    .slice()
    .reverse()
    .map((ev: any, idx: number) => ({
      index: idx + 1,
      entropy: Number((ev.entropy || 0).toFixed(2)),
      file: (ev.dest_path || ev.src_path || "").split(/[\\/]/).pop(),
    }));

  const threatLevel = status?.threat_level || "Normal";
  const threatScore = Math.round(status?.threat_score || 0);

  const getThreatColor = () => {
    if (threatLevel === "Critical") return "text-red-500 border-red-500/30 bg-red-500/10";
    if (threatLevel === "Warning") return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans p-6 space-y-6">
      {/* Header */}
      <header className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-xl bg-indigo-600/20 border border-indigo-500/40 text-indigo-400">
            <ShieldAlert className="w-7 h-7" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              RDRS Security Operations Center
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">
                v1.0.0
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Heuristic Ransomware Detection & Automated Quarantine Response
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <span className="flex items-center gap-1.5 px-3 py-1 text-xs rounded-full border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Simulation Mode Active
          </span>

          <button
            onClick={triggerScan}
            disabled={scanning}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white rounded-lg transition shadow-lg shadow-indigo-600/20"
          >
            {scanning ? (
              <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            {scanning ? "Scanning..." : "Quick Scan Sandbox"}
          </button>
        </div>
      </header>

      {/* Top 4 Metrics Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Threat Level */}
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 shadow-sm space-y-3">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-medium tracking-wider">
            <span>Threat Level</span>
            <Activity className="w-4 h-4 text-slate-400" />
          </div>
          <div className="flex items-baseline justify-between">
            <span className={`text-2xl font-black px-2.5 py-0.5 rounded-lg border ${getThreatColor()}`}>
              {threatLevel.toUpperCase()}
            </span>
            <span className="text-xs font-mono text-slate-400">{threatScore} / 100</span>
          </div>
          <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
            <div
              className={`h-1.5 transition-all duration-500 ${
                threatLevel === "Critical"
                  ? "bg-red-500"
                  : threatLevel === "Warning"
                  ? "bg-amber-400"
                  : "bg-emerald-400"
              }`}
              style={{ width: `${Math.min(100, threatScore)}%` }}
            />
          </div>
        </div>

        {/* Total File Events */}
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-medium tracking-wider">
            <span>Observed Events</span>
            <HardDrive className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {status?.total_events_observed ?? 0}
          </div>
          <p className="text-xs text-slate-500">Live file telemetry stream</p>
        </div>

        {/* Alerts Raised */}
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-medium tracking-wider">
            <span>Threat Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {status?.total_alerts_raised ?? 0}
          </div>
          <p className="text-xs text-slate-500">Rule heuristics triggered</p>
        </div>

        {/* Contained Incidents */}
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 shadow-sm space-y-2">
          <div className="flex items-center justify-between text-xs text-slate-400 uppercase font-medium tracking-wider">
            <span>Quarantined</span>
            <ShieldCheck className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">
            {status?.total_incidents_recorded ?? 0}
          </div>
          <p className="text-xs text-slate-500">Forensic evidence isolated</p>
        </div>
      </section>

      {/* Middle Row: Entropy Graph + Active Alert Feed */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real-time Entropy Spike Graph */}
        <div className="lg:col-span-2 p-5 rounded-2xl bg-slate-900/70 border border-slate-800 flex flex-col space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-400" />
              Shannon Entropy Stream (0.0 - 8.0 Scale)
            </h2>
            <span className="text-[11px] font-mono text-slate-400">Threshold: 7.20</span>
          </div>

          <div className="h-64 w-full">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="index" stroke="#64748b" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 8]} stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0f172a",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="entropy"
                    stroke="#6366f1"
                    strokeWidth={2.5}
                    dot={{ r: 3, fill: "#818cf8" }}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-500">
                Waiting for file modifications...
              </div>
            )}
          </div>
        </div>

        {/* Live Alerts Stream */}
        <div className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 flex flex-col space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Recent Threat Alerts
            </h2>
            <span className="text-[10px] text-slate-400 font-mono">Live feed</span>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-64 pr-1">
            {alerts && alerts.length > 0 ? (
              alerts.map((a: any) => (
                <div
                  key={a.id}
                  className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1.5"
                >
                  <div className="flex items-center justify-between text-xs">
                    <span
                      className={`font-bold px-2 py-0.5 rounded text-[10px] ${
                        a.severity === "Critical"
                          ? "bg-red-500/20 text-red-400 border border-red-500/30"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                      }`}
                    >
                      {a.severity.toUpperCase()} ({a.score})
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ""}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 font-medium">{a.rule_name}</p>
                  <p className="text-[11px] text-slate-400">
                    Suspect: <span className="font-mono text-indigo-300">{a.suspect_process || "Unknown"} (PID: {a.suspect_pid || 0})</span>
                  </p>
                </div>
              ))
            ) : (
              <p className="text-xs text-slate-500 text-center py-12">
                No active threats detected.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* Bottom Table: Raw File Events Stream */}
      <section className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
        <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <TerminalIcon className="w-4 h-4 text-indigo-400" />
          Raw File System Ingestion Telemetry
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="text-[11px] uppercase bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Event Type</th>
                <th className="py-2.5 px-3">File Path</th>
                <th className="py-2.5 px-3">Entropy</th>
                <th className="py-2.5 px-3">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {events && events.length > 0 ? (
                events.map((ev: any) => (
                  <tr key={ev.id} className="hover:bg-slate-800/30 transition">
                    <td className="py-2 px-3">
                      <span className="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 font-bold uppercase text-[10px]">
                        {ev.event_type}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-200 truncate max-w-xs" title={ev.dest_path || ev.src_path}>
                      {(ev.dest_path || ev.src_path || "").split(/[\\/]/).pop()}
                    </td>
                    <td className="py-2 px-3">
                      <span className={ev.entropy >= 7.2 ? "text-red-400 font-bold" : "text-slate-400"}>
                        {ev.entropy.toFixed(2)}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-500 text-[11px]">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : ""}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-slate-500 text-xs">
                    No file events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
