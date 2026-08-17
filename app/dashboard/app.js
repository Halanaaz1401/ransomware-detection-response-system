// Polling engine for live UI updates
async function fetchStatus() {
    try {
        const res = await fetch('/status');
        if (!res.ok) return;
        const data = await res.json();

        // Update stats
        document.getElementById('val-total-events').innerText = data.total_events_observed;
        document.getElementById('val-total-alerts').innerText = data.total_alerts_raised;
        document.getElementById('val-total-incidents').innerText = data.total_incidents_recorded;
        document.getElementById('val-threat-score').innerText = `${Math.round(data.threat_score)} / 100`;

        const levelElem = document.getElementById('val-threat-level');
        const barElem = document.getElementById('bar-threat-score');
        levelElem.innerText = data.threat_level.toUpperCase();
        barElem.style.width = `${Math.min(100, data.threat_score)}%`;

        // Color coding
        if (data.threat_level === 'Critical') {
            levelElem.className = 'text-2xl font-black text-red-400';
            barElem.className = 'bg-red-500 h-2 rounded-full transition-all duration-500';
        } else if (data.threat_level === 'Warning') {
            levelElem.className = 'text-2xl font-black text-amber-400';
            barElem.className = 'bg-amber-500 h-2 rounded-full transition-all duration-500';
        } else {
            levelElem.className = 'text-2xl font-black text-emerald-400';
            barElem.className = 'bg-emerald-400 h-2 rounded-full transition-all duration-500';
        }
    } catch (e) {
        console.error("Error fetching status:", e);
    }
}

async function fetchAlerts() {
    try {
        const res = await fetch('/alerts?limit=10');
        if (!res.ok) return;
        const alerts = await res.json();

        const container = document.getElementById('alerts-container');
        if (alerts.length === 0) {
            container.innerHTML = '<p class="text-xs text-slate-500 text-center mt-10">No threat alerts generated yet.</p>';
            return;
        }

        container.innerHTML = alerts.map(a => {
            const isCrit = a.severity === 'Critical';
            const badgeColor = isCrit ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-amber-500/20 text-amber-400 border-amber-500/30';
            return `
                <div class="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-col space-y-1">
                    <div class="flex items-center justify-between">
                        <span class="px-2 py-0.5 text-[10px] rounded border ${badgeColor} font-bold">${a.severity.toUpperCase()} (Score: ${a.score})</span>
                        <span class="text-[10px] text-slate-500 font-mono">${new Date(a.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <p class="text-xs text-slate-200 font-medium">${a.rule_name}</p>
                    <p class="text-[11px] text-slate-400">Suspect: <span class="text-indigo-300 font-mono">${a.suspect_process || 'Unknown'} (PID: ${a.suspect_pid || 0})</span></p>
                </div>
            `;
        }).join('');
    } catch (e) {
        console.error("Error fetching alerts:", e);
    }
}

async function fetchEvents() {
    try {
        const res = await fetch('/events?limit=15');
        if (!res.ok) return;
        const events = await res.json();

        const container = document.getElementById('events-container');
        if (events.length === 0) {
            container.innerHTML = '<p class="text-xs text-slate-500 text-center mt-10">Awaiting file system activity...</p>';
            return;
        }

        container.innerHTML = events.map(ev => {
            const pathName = (ev.dest_path || ev.src_path).split('\\').pop().split('/').pop();
            const isHighEntropy = ev.entropy >= 7.2;
            const entropyBadge = isHighEntropy 
                ? `<span class="text-red-400 font-bold ml-2">Entropy: ${ev.entropy.toFixed(2)}</span>`
                : `<span class="text-slate-500 ml-2">Entropy: ${ev.entropy.toFixed(2)}</span>`;

            return `
                <div class="p-2 bg-slate-950/40 border border-slate-800/60 rounded flex items-center justify-between">
                    <div class="truncate max-w-[280px]">
                        <span class="text-indigo-400 uppercase font-semibold">[${ev.event_type}]</span> 
                        <span class="text-slate-300 ml-1" title="${ev.dest_path || ev.src_path}">${pathName}</span>
                    </div>
                    <div class="text-[10px]">
                        ${entropyBadge}
                    </div>
                </div>
            `;
        }).join('');
    } catch (e) {
        console.error("Error fetching events:", e);
    }
}

async function triggerManualScan() {
    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_path: './data/sandbox' })
        });
        const result = await res.json();
        alert(`Scan Completed!\nTotal Files Scanned: ${result.total_scanned}\nSuspicious Files Found: ${result.suspicious_found}`);
    } catch (e) {
        alert("Scan failed: " + e);
    }
}

// Polling intervals
setInterval(fetchStatus, 2000);
setInterval(fetchAlerts, 3000);
setInterval(fetchEvents, 2000);

// Initial call
fetchStatus();
fetchAlerts();
fetchEvents();
