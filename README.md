[RDRS_README_FINAL.md](https://github.com/user-attachments/files/31649703/RDRS_README_FINAL.md)
# RDRS — Ransomware Detection & Response System

> ** Security Engineering Project**  
> A local-first ransomware detection and response platform for
> identifying ransomware-like filesystem behavior through behavioral
> telemetry, Shannon entropy analysis, process monitoring, threat
> scoring, evidence preservation, incident persistence, and security
> reporting.

**Author:** Hala Naaz  
**Environment:** Controlled local simulation / defensive security
research

> **Safety:** RDRS is configured for simulation mode. The demonstrated
> containment workflow records what would happen instead of terminating
> a real process.

------------------------------------------------------------------------

## Overview

RDRS demonstrates an end-to-end defensive ransomware detection and
response workflow in a controlled local environment.

The system correlates rapid file modifications, mass renames, suspicious
extension changes, Shannon entropy, sliding-window activity, CPU/I/O
observations, process telemetry, and unknown-process context. These
signals are converted into a threat score and severity level. Critical
activity triggers evidence preservation, incident creation, and a
simulation-safe containment record.

The backend is exposed through **FastAPI** and the operational data is
presented through a **Next.js dashboard**.

## Architecture

``` mermaid
flowchart LR
    A["Controlled Sandbox<br/>./data/sandbox"] --> B["File Monitor"]
    B --> C["Event Persistence"]
    C --> D["Entropy Analysis"]
    C --> E["Behavioral Detection"]
    C --> F["Process Telemetry"]
    D --> G["Threat Scorer"]
    E --> G
    F --> G
    G --> H{"Severity"}
    H -->|"Normal"| I["Continue Monitoring"]
    H -->|"Warning"| J["Alert"]
    H -->|"Critical"| K["Incident Response"]
    K --> L["Evidence Quarantine"]
    K --> M["Incident Record"]
    K --> N["Simulation-Safe Containment"]
    M --> O["SQLite"]
    L --> P["Forensic Evidence"]
    O --> Q["FastAPI"]
    Q --> R["Next.js SOC Dashboard"]
    Q --> S["JSON / CSV / PDF Reports"]
```

### Architectural layers

| Layer       | Responsibility                                       |
|-------------|------------------------------------------------------|
| Collection  | Captures filesystem and process telemetry            |
| Analysis    | Calculates entropy and evaluates behavioral activity |
| Detection   | Correlates suspicious signals                        |
| Scoring     | Produces the threat score                            |
| Response    | Preserves evidence and creates incidents             |
| Persistence | Stores events, alerts, incidents, and telemetry      |
| API         | Exposes operational data through FastAPI             |
| Dashboard   | Provides analyst-facing visibility                   |
| Reporting   | Produces forensic/security reports                   |

## Detection Pipeline

``` mermaid
flowchart TD
    A["Filesystem Activity"] --> B["Capture Event"]
    B --> C["Entropy Analysis"]
    C --> D["Sliding-Window Analysis"]
    D --> E["Mass Modification"]
    D --> F["Rapid Rename"]
    D --> G["Extension Changes"]
    P["Process CPU / I/O"] --> H["Signal Correlation"]
    U["Unknown Process"] --> H
    E --> H
    F --> H
    G --> H
    H --> I["Threat Score"]
    I --> J{"Severity"}
    J -->|"Normal"| K["Continue Monitoring"]
    J -->|"Warning"| L["Persist Alert"]
    J -->|"Critical"| M["Preserve Evidence"]
    M --> N["Create Incident"]
    N --> O["Record Simulated Containment"]
    O --> Q["Dashboard / Reports"]
```

## Detection Engine

RDRS uses multiple behavioral indicators because a single signal can
produce false positives.

| Signal                    | Purpose                                  |
|---------------------------|------------------------------------------|
| Rapid encryption/activity | Detects rapid file modification behavior |
| Mass rename               | Detects large-scale rename activity      |
| High entropy              | Adds an encryption/randomness indicator  |
| CPU spike                 | Adds process execution context           |
| Unknown program           | Adds process identity/context            |

### Sliding-window configuration

``` text
Window:                 60 seconds
Entropy threshold:      7.20
Sample size:            65,536 bytes
Modifications/minute:   20
Renames/minute:          10
Extension changes/min:   5
Entropy spike count:     5
```

High entropy is treated as a supporting behavioral signal, not proof of
ransomware by itself.

## Threat Scoring

| Detection Signal | Weight |
|------------------|-------:|
| Rapid encryption |     40 |
| Mass rename      |     30 |
| High entropy     |     25 |
| CPU spike        |     15 |
| Unknown program  |     10 |

``` mermaid
flowchart LR
    A["Threat Score"] --> B["0–40<br/>NORMAL"]
    A --> C[">40–70<br/>WARNING"]
    A --> D[">=70<br/>CRITICAL"]
    D --> E["Response Workflow"]
```

|   Score | Severity | Response                              |
|--------:|----------|---------------------------------------|
|    0–40 | Normal   | Continue monitoring                   |
| \>40–70 | Warning  | Generate/persist alert                |
|   \>=70 | Critical | Preserve evidence and create incident |

The displayed threat posture is normalized to a maximum of **100**.

## Process Telemetry

RDRS collects process context to correlate execution activity with
filesystem behavior.

``` text
PID
Process name
Executable path
CPU %
Memory %
Read bytes
Write bytes
Parent PID
Suspicious flag
Timestamp
```

## Incident Response

``` mermaid
flowchart TD
    A["Critical Detection"] --> B["Preserve Evidence"]
    B --> C["Create Incident"]
    C --> D["Persist Incident"]
    D --> E["Record Mitigation Action"]
    E --> F["Expose / Generate Reports"]
    F --> G["Analyst Dashboard"]
```

For a Critical assessment, RDRS preserves affected evidence, creates an
incident-specific quarantine location, records the suspected process and
PID, persists the incident, and records the mitigation action.

### Simulation-safe containment

``` yaml
simulation_mode: true
```

Instead of terminating a real process, the response layer records an
action such as:

``` text
SIMULATION: Would terminate PID <pid>
```

## Evidence Quarantine

``` text
data/
└── quarantine/
    └── incident_<timestamp>/
        └── preserved evidence
```

The purpose is to preserve evidence for investigation rather than
immediately destroying the original sandbox artifacts.

## REST API

The backend runs locally at:

``` text
http://127.0.0.1:8000
```

FastAPI documentation:

``` text
http://127.0.0.1:8000/docs
```

| Method | Endpoint     | Purpose                      |
|--------|--------------|------------------------------|
| GET    | `/health`    | Service health               |
| GET    | `/status`    | Current system/threat status |
| GET    | `/events`    | Recent filesystem events     |
| GET    | `/alerts`    | Recent detection alerts      |
| GET    | `/incidents` | Incident records             |
| GET    | `/processes` | Process telemetry            |
| POST   | `/scan`      | Scan the configured target   |

## Dashboard

The Next.js dashboard provides analyst-facing visibility into:

- Threat posture and score
- Observed events
- Threat alerts
- Quarantined evidence
- Entropy telemetry
- Raw filesystem telemetry
- Process telemetry
- Response state
- Sandbox scanning

``` mermaid
flowchart LR
    API["FastAPI"] --> S["Status"]
    API --> E["Events"]
    API --> A["Alerts"]
    API --> I["Incidents"]
    API --> P["Processes"]
    S --> UI["Next.js SOC Dashboard"]
    E --> UI
    A --> UI
    I --> UI
    P --> UI
```

The dashboard identifies the environment as **Simulation Mode** during
the controlled demonstration.

## Technology Stack

| Technology   | Role                           |
|--------------|--------------------------------|
| Python       | Detection and response backend |
| FastAPI      | REST API                       |
| Uvicorn      | ASGI server                    |
| SQLAlchemy   | Database persistence           |
| SQLite       | Local database                 |
| Pydantic     | Data validation                |
| psutil       | Process telemetry              |
| Pytest       | Automated testing              |
| Next.js      | Web dashboard                  |
| React        | Dashboard UI                   |
| Tailwind CSS | Dashboard styling              |
| Recharts     | Telemetry visualization        |
| Lucide React | Interface icons                |

## Project Structure

``` text
rdrs/
├── app/
│   ├── api/
│   ├── core/
│   ├── database/
│   ├── detectors/
│   │   ├── detection_engine.py
│   │   ├── file_monitor.py
│   │   ├── process_monitor.py
│   │   ├── responder.py
│   │   └── threat_scorer.py
│   ├── reports/
│   │   └── generator.py
│   └── main.py
├── dashboard/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── ...
├── data/
│   ├── sandbox/
│   └── quarantine/
├── reports/
├── tests/
│   └── test_rdrs.py
├── config.yaml
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── pytest.ini
└── README.md
```

## Configuration

``` yaml
simulation_mode: true

monitor:
  watch_paths:
    - "./data/sandbox"
  recursive: true

detection:
  sliding_window_seconds: 60
  entropy_threshold: 7.2
  sample_size_bytes: 65536

scoring:
  weights:
    rapid_encryption: 40
    mass_rename: 30
    high_entropy: 25
    cpu_spike: 15
    unknown_program: 10
```

For the internship demonstration, keep `simulation_mode: true` and
restrict monitoring to the dedicated sandbox.

## Installation

### Prerequisites

- Python 3.x
- Node.js and npm
- Git
- Required Python dependencies

### Backend

``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Dashboard

``` powershell
cd dashboard
npm install
cd ..
```

## Running RDRS

### Start the backend

``` powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

### Start the dashboard

Open a second terminal:

``` powershell
cd dashboard
npm run dev
```

Then open:

``` text
http://localhost:3000
```

## Demonstration

Use only controlled test activity inside:

``` text
./data/sandbox
```

Recommended sequence:

1.  Start the backend.
2.  Start the dashboard.
3.  Verify `/health`.
4.  Verify sandbox monitoring.
5.  Generate controlled test activity.
6.  Observe filesystem events and entropy.
7.  Observe alerts and threat scoring.
8.  Verify Critical classification.
9.  Verify evidence quarantine.
10. Inspect the incident record.
11. Generate/inspect reports.

``` mermaid
sequenceDiagram
    participant Analyst
    participant Sandbox
    participant RDRS
    participant DB
    participant Dashboard

    Analyst->>Sandbox: Generate controlled test activity
    Sandbox->>RDRS: Filesystem events
    RDRS->>RDRS: Entropy + behavioral analysis
    RDRS->>RDRS: Process correlation
    RDRS->>RDRS: Calculate threat score
    alt Normal
        RDRS->>DB: Persist telemetry
    else Warning
        RDRS->>DB: Persist alert
    else Critical
        RDRS->>DB: Persist incident
        RDRS->>Sandbox: Preserve evidence
        RDRS->>RDRS: Record simulated containment
    end
    DB->>Dashboard: Events / alerts / incidents
    RDRS->>Dashboard: Current telemetry
    Analyst->>Dashboard: Review security posture
```

## Testing

Run:

``` powershell
.\.venv\Scripts\python.exe -m pytest -v
```

Current validated result:

``` text
8 passed
```

## Reports & Evidence

RDRS supports:

``` text
JSON
CSV
PDF
```

Reports:

``` text
reports/
```

Evidence:

``` text
data/quarantine/
```

These artifacts provide a reproducible record of the simulated detection
and response workflow.

## Verification Checklist

``` text
[ ] Backend starts successfully
[ ] Dashboard starts successfully
[ ] /health responds successfully
[ ] /status reports current system state
[ ] /events returns filesystem telemetry
[ ] /alerts returns detection alerts
[ ] /incidents returns incident records
[ ] /processes returns process telemetry
[ ] /scan accepts the sandbox target
[ ] Sandbox monitoring works
[ ] Entropy detection works
[ ] Behavioral scoring works
[ ] Critical classification works
[ ] Evidence quarantine works
[ ] Incident persistence works
[ ] Simulation mode remains enabled
[ ] JSON/CSV/PDF reporting works
[ ] Pytest suite passes
[ ] Generated artifacts are excluded from Git
```

## Security & Safety

RDRS is intended for controlled defensive security research and
internship demonstration.

- Monitor only a dedicated sandbox.
- Keep simulation mode enabled during demonstrations.
- Do not perform destructive containment on real systems.
- Preserve evidence for investigation.
- Keep generated test artifacts isolated.
- Do not use production data as test input.

> Do not configure the system to monitor or modify sensitive production
> directories during experimentation.

## Limitations

RDRS is an internship/security research implementation rather than a
production EDR platform.

- Heuristic detection rather than a complete ML ransomware classifier.
- Thresholds require tuning for different environments.
- SQLite is suitable for local demonstration but not a production-scale
  event store.
- Process telemetry depends on operating-system permissions and
  available telemetry.
- Simulation mode records containment rather than performing real
  process isolation.
- Detection quality depends on available behavioral signals.
- The dashboard is primarily designed for local analysis and
  demonstration.

## Future Enhancements

- Production-grade process isolation
- Windows service deployment
- Centralized event collection
- PostgreSQL or another production database
- SIEM integration
- Sigma/YARA integration
- Threat-intelligence enrichment
- Machine-learning behavioral classification
- Authentication and role-based access control
- Alert notification integrations
- Distributed endpoint monitoring
- Dockerized deployment
- Expanded integration testing
- Advanced incident correlation
- Analyst investigation workflows

## Project Status

``` text
Filesystem monitoring        ✓
Entropy analysis             ✓
Behavioral detection         ✓
Process telemetry            ✓
Threat scoring               ✓
Critical classification      ✓
Alert persistence            ✓
Incident persistence         ✓
Evidence quarantine          ✓
Simulation-safe response     ✓
FastAPI REST API             ✓
Web dashboard                ✓
JSON / CSV / PDF reporting   ✓
Automated tests              ✓ 8 passed
```

### End-to-end workflow

``` text
Filesystem Behavior
        ↓
Telemetry Collection
        ↓
Behavioral Analysis
        ↓
Threat Scoring
        ↓
Severity Classification
        ↓
Evidence Preservation
        ↓
Incident Persistence
        ↓
Security Reporting
        ↓
Analyst Dashboard
```

## Author

**Hala Naaz**  
Cybersecurity Professional · GenAI Developer · Security Tool Builder

**AshlynxCyber**

## Disclaimer

RDRS is an educational and defensive security project developed for
controlled testing and internship demonstration.

Use it only on systems and data that you are authorized to monitor.
