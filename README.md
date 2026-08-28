[README (2).md](https://github.com/user-attachments/files/31545005/README.2.md)
# RDRS — Ransomware Detection & Response System

A local-first ransomware detection and response platform for identifying ransomware-like file activity through behavioral telemetry, entropy analysis, process monitoring, threat scoring, evidence quarantine, incident persistence, and security reporting.

RDRS is designed as a controlled security research and internship project. It monitors a dedicated sandbox, correlates multiple behavioral signals, assigns a threat score, records alerts and incidents, preserves evidence, and exposes the resulting telemetry through a FastAPI backend and web dashboard.

> **Safety:** RDRS is configured for simulation mode. The demonstrated containment workflow does not terminate real processes.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [Solution](#solution)
- [Key Features](#key-features)
- [Detection Engine](#detection-engine)
- [Threat Scoring](#threat-scoring)
- [Process Telemetry](#process-telemetry)
- [Incident Response](#incident-response)
- [Evidence Quarantine](#evidence-quarantine)
- [Architecture](#architecture)
- [System Workflow](#system-workflow)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Configuration](#configuration)
- [API](#api)
- [Dashboard](#dashboard)
- [Installation](#installation)
- [Running RDRS](#running-rdrs)
- [Demonstration](#demonstration)
- [Testing](#testing)
- [Reports and Evidence](#reports-and-evidence)
- [Security and Safety](#security-and-safety)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Future Enhancements](#future-enhancements)
- [License](#license)
- [Author](#author)

---

## Overview

Ransomware can generate a large number of filesystem changes in a short period of time. RDRS focuses on the behavioral signals that accompany this activity instead of relying only on a known ransomware signature.

The system observes activity inside a controlled sandbox and combines:

- File creation and modification telemetry
- File rename activity
- Suspicious extension changes
- Shannon entropy measurements
- Sliding-window activity rates
- Process telemetry
- CPU and I/O observations
- Unknown/suspicious program signals
- Weighted threat scoring
- Severity classification
- Alert and incident persistence
- Evidence quarantine
- Simulation-safe response
- JSON, CSV, and PDF reporting

The backend is exposed through a FastAPI service and consumed by a live web dashboard.

---

## Problem Statement

A ransomware detection system needs to identify suspicious behavior early enough to support investigation and containment.

A single signal is often insufficient:

- High entropy can occur in legitimate compressed or encrypted data.
- A file extension change can be benign.
- A process writing heavily to disk can be legitimate.
- A large number of modifications can occur during normal bulk operations.

RDRS therefore combines multiple signals inside a behavioral detection pipeline and converts those signals into a normalized threat score and incident record.

---

## Solution

RDRS follows a layered detection and response model:

```text
                    FILESYSTEM ACTIVITY
                           |
                           v
                  +-------------------+
                  |   File Monitor    |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  | Event Persistence |
                  +---------+---------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
      +---------------+           +---------------+
      | Entropy       |           | Behavioral    |
      | Analysis      |           | Detection     |
      +-------+-------+           +-------+-------+
              |                           |
              +-------------+-------------+
                            |
                            v
                  +-------------------+
                  | Process Telemetry |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  | Threat Scoring    |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  | Severity Decision |
                  +---------+---------+
                            |
                  +---------+---------+
                  |                   |
                  v                   v
               ALERT              CRITICAL
                                      |
                                      v
                           +-------------------+
                           | Evidence          |
                           | Quarantine        |
                           +---------+---------+
                                     |
                                     v
                           +-------------------+
                           | Incident Record   |
                           +---------+---------+
                                     |
                                     v
                           +-------------------+
                           | JSON / CSV / PDF  |
                           +-------------------+
```

---

## Key Features

### Behavioral File Monitoring

RDRS monitors the configured sandbox recursively and records filesystem events.

Captured information includes:

- Event type
- Source/destination path
- File extension
- Entropy
- Timestamp
- Related telemetry

### Entropy Analysis

RDRS calculates Shannon entropy for file content.

The configured detection threshold is:

```text
Entropy threshold: 7.20
```

High entropy is treated as one behavioral indicator rather than a standalone verdict.

### Sliding-Window Detection

The detection engine evaluates activity over a configured time window.

Current configuration:

```text
Window:             60 seconds
Modifications/min:  20
Renames/min:        10
Extension changes:   5
Entropy spike count: 5
```

These thresholds are intended for controlled ransomware-behavior simulation and can be tuned for another environment.

### Suspicious Extension Detection

The system can identify suspicious extension changes such as ransomware-style `.locked` activity.

### Process Telemetry

RDRS records process-level observations including:

- PID
- Process name
- Executable path
- CPU usage
- Memory usage
- Read/write byte counters
- Parent PID
- Suspicious-process state
- Timestamp

### Threat Scoring

Multiple detection signals are combined into a weighted score.

### Alerts and Incidents

Detection results are persisted so that alerts and incidents can be investigated after the original filesystem event.

### Evidence Preservation

Critical activity can create an incident-specific quarantine directory containing preserved evidence from the controlled sandbox.

### REST API

FastAPI exposes monitoring, detection, incident, process, scan, and reporting functionality to the dashboard and other clients.

### Live Dashboard

The dashboard provides:

- Current threat posture
- Event counts
- Alert counts
- Incident counts
- Entropy telemetry
- Detection queue
- Raw file-event stream
- Process snapshots
- Response state
- Manual sandbox scan control

---

## Detection Engine

RDRS uses several behavioral indicators.

### Core Indicators

| Signal | Purpose |
|---|---|
| Rapid encryption/activity | Detects rapid file modification behavior |
| Mass rename | Detects large-scale rename activity |
| High entropy | Identifies files whose content resembles randomized/encrypted data |
| CPU spike | Adds process-level execution context |
| Unknown program | Adds context for previously unrecognized process activity |

The engine is intentionally multi-signal: a single observation should not be interpreted as definitive proof of ransomware.

---

## Threat Scoring

The configured signal weights are:

| Detection Signal | Weight |
|---|---:|
| Rapid encryption | 40 |
| Mass rename | 30 |
| High entropy | 25 |
| CPU spike | 15 |
| Unknown program | 10 |

The scoring system uses a normalized maximum of 100 for the final threat posture.

### Severity Classification

| Score | Severity |
|---:|---|
| 0–40 | Normal |
| >40–70 | Warning |
| >=70 | Critical |

A Critical assessment activates the response workflow.

---

## Process Telemetry

RDRS collects process snapshots to provide execution context around suspicious filesystem behavior.

Example telemetry fields:

```text
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

Process telemetry is correlated with filesystem behavior to improve the context available to the scoring and response layers.

---

## Incident Response

The response workflow is designed for controlled security research:

```text
Critical assessment
       |
       v
Evidence preservation
       |
       v
Incident creation
       |
       v
Incident persistence
       |
       v
Report generation
```

When simulation mode is enabled, the system records the containment action that would have been taken instead of terminating the process.

Example:

```text
SIMULATION: Would terminate PID <pid>
```

This allows the complete detection and response workflow to be demonstrated without destructive process termination.

---

## Evidence Quarantine

Evidence generated by a Critical event is preserved in an incident-specific quarantine location.

Example:

```text
data/
└── quarantine/
    └── incident_<timestamp>/
        ├── evidence files
        └── ...
```

The controlled demonstration copies affected evidence into the quarantine area so that the response can be inspected without destroying the original sandbox artifacts.

---

## Architecture

```text
+---------------------------+
|      Next.js Dashboard    |
|                           |
| Status / Alerts / Events  |
| Processes / Telemetry     |
+-------------+-------------+
              |
              | HTTP / JSON
              v
+---------------------------+
|       FastAPI API         |
+-------------+-------------+
              |
       +------+------+
       |             |
       v             v
+-------------+  +-------------+
| Detection   |  | Process     |
| Engine      |  | Telemetry   |
+------+------+  +------+------+
       |                |
       +--------+-------+
                |
                v
        +---------------+
        | Threat Scorer |
        +-------+-------+
                |
                v
        +---------------+
        | Responder     |
        +-------+-------+
                |
       +--------+---------+
       |                  |
       v                  v
+--------------+   +---------------+
| SQLite       |   | Quarantine    |
| Persistence  |   | Evidence      |
+--------------+   +---------------+
       |
       v
+------------------------+
| JSON / CSV / PDF       |
| Security Reports       |
+------------------------+
```

---

## System Workflow

### 1. Monitor

RDRS monitors:

```text
./data/sandbox
```

recursively.

### 2. Collect

Filesystem events are captured and persisted.

### 3. Analyze

The system evaluates:

- Event frequency
- Rename behavior
- Extension changes
- Entropy
- Process telemetry
- CPU/I/O context

### 4. Score

Behavioral signals are combined into a threat score.

### 5. Classify

The score is classified as Normal, Warning, or Critical.

### 6. Respond

Critical activity triggers evidence preservation and incident handling.

### 7. Persist

Events, alerts, incidents, and process observations are retained in the local database.

### 8. Report

Security information can be exposed through the API and generated reports.

---

## Project Structure

The repository is organized around the backend, dashboard, data, reports, and tests.

```text
rders/
├── app/
│   ├── api/
│   ├── detectors/
│   └── ...
├── dashboard/
│   ├── src/
│   │   └── app/
│   ├── public/
│   ├── package.json
│   └── ...
├── data/
│   ├── sandbox/
│   └── quarantine/
├── reports/
├── tests/
├── config.yaml
├── requirements.txt
└── README.md
```

> The exact generated/cache files such as `node_modules`, Python cache directories, and virtual-environment contents should not be committed to source control.

---

## Technology Stack

| Technology | Role |
|---|---|
| Python | Detection and response backend |
| FastAPI | REST API |
| Uvicorn | ASGI application server |
| SQLAlchemy | Database persistence |
| SQLite | Local database |
| Pydantic | Data validation |
| psutil | Process telemetry |
| Pytest | Automated testing |
| Next.js | Web dashboard |
| React | Dashboard UI |
| Tailwind CSS | Dashboard styling |
| Recharts | Telemetry visualization |
| Lucide React | Interface icons |

---

## Configuration

RDRS uses YAML configuration for detection and runtime behavior.

Important settings include:

```yaml
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

### Simulation Mode

For the internship demonstration, keep:

```yaml
simulation_mode: true
```

This prevents the response layer from performing real process termination.

---

## API

The backend is served locally at:

```text
http://127.0.0.1:8000
```

FastAPI also provides interactive API documentation when enabled:

```text
http://127.0.0.1:8000/docs
```

Core endpoints used by the dashboard include:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| GET | `/status` | Current system and threat status |
| GET | `/events` | Recent filesystem events |
| GET | `/alerts` | Recent detection alerts |
| GET | `/incidents` | Incident records |
| GET | `/processes` | Process telemetry |
| POST | `/scan` | Scan the configured target path |

Additional reporting/configuration routes are exposed by the backend where implemented.

---

## Dashboard

The web dashboard is located under:

```text
dashboard/
```

It consumes the local FastAPI service and automatically refreshes operational data.

### Dashboard Sections

```text
Threat posture
      |
File telemetry
      |
Detection queue
      |
Raw event stream
      |
Process snapshots
      |
Response state
```

The dashboard intentionally identifies the environment as **Simulation Mode** so that a reviewer can distinguish controlled testing from production containment.

---

## Installation

### Prerequisites

Recommended environment:

- Python 3.x
- Node.js and npm
- Git
- Windows, Linux, or macOS environment with the required Python dependencies

### Backend Setup

From the project root:

```powershell
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install Python dependencies:

```powershell
pip install -r requirements.txt
```

### Dashboard Setup

```powershell
cd dashboard
npm install
```

Return to the project root when finished:

```powershell
cd ..
```

---

## Running RDRS

### Start the Backend

From the project root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

The API should become available at:

```text
http://127.0.0.1:8000
```

### Start the Dashboard

Open a second terminal:

```powershell
cd dashboard
npm run dev
```

Then open:

```text
http://localhost:3000
```

Keep both services running during the live demonstration.

---

## Demonstration

RDRS includes a controlled sandbox for demonstrating ransomware-like behavior.

### Recommended Demonstration Sequence

1. Start the backend.
2. Start the dashboard.
3. Verify the API health endpoint.
4. Verify that monitoring is pointed at `./data/sandbox`.
5. Generate controlled test activity inside the sandbox.
6. Observe filesystem events.
7. Observe entropy measurements.
8. Observe the detection queue.
9. Verify the resulting threat score.
10. Verify Critical classification when thresholds are exceeded.
11. Verify evidence quarantine.
12. Inspect the incident record.
13. Generate/read the security reports.

### Safe Simulation Example

The demonstration should only create test artifacts under:

```text
./data/sandbox
```

Do not point the monitor at personal directories, operating-system directories, or production data.

---

## Testing

The project currently has an automated test suite.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The validated test result during development is:

```text
8 passed
```

A passing test suite verifies the currently covered application behaviors. It should be combined with the live integration checks described above rather than treated as the only validation method.

---

## Reports and Evidence

RDRS supports security report generation in multiple formats:

```text
JSON
CSV
PDF
```

Reports are stored under:

```text
reports/
```

Evidence generated during Critical simulations is preserved under:

```text
data/quarantine/
```

The report and quarantine artifacts provide a reproducible record of the simulated detection and response workflow.

---

## Security and Safety

RDRS is intended for controlled defensive research and demonstration.

### Safety Controls

- Monitoring is directed at a dedicated sandbox.
- Simulation mode is enabled for the demonstration.
- Process termination is not executed in simulation mode.
- Evidence is preserved rather than destructively deleted.
- The system is designed for local operation.
- Test artifacts should remain inside the project sandbox.

### Important Operational Rule

Do not configure the system to monitor or modify sensitive production directories during experimentation.

---

## Troubleshooting

### API does not start

Verify the virtual environment and dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Then start Uvicorn again:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.api.main:app --host 127.0.0.1 --port 8000
```

### Dashboard cannot load data

Confirm that the backend is running:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

The dashboard expects the API at:

```text
http://127.0.0.1:8000
```

### Dashboard build fails

From `dashboard/`:

```powershell
npm install
npm run build
```

### No file events appear

Verify the configured path:

```text
./data/sandbox
```

and confirm that the monitoring process has started successfully.

### No Critical detection occurs

Check:

- Activity is occurring inside the monitored sandbox.
- The activity is sufficient to cross the configured sliding-window thresholds.
- File entropy exceeds the configured threshold where applicable.
- The backend is running.
- Simulation mode is enabled.

---

## Limitations

RDRS is an internship/security research implementation rather than a production EDR platform.

Current limitations include:

- Heuristic detection rather than a full machine-learning ransomware classifier.
- Thresholds require tuning for different environments.
- Local SQLite is appropriate for the demonstration but is not a replacement for a production event store.
- Process telemetry can vary by operating system and permissions.
- Simulation mode does not perform real process isolation.
- Detection quality depends on the behavioral signals available to the host.
- The current dashboard is intended for local demonstration and analysis.

---

## Future Enhancements

Potential future development includes:

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
- Expanded automated integration testing
- More advanced incident correlation
- Analyst investigation workflows

---

## License

Add the project's chosen license here before public release.

Example:

```text
MIT License
```

Do not claim a license unless a corresponding license file is included in the repository.

---

## Author

**Hala Naaz**

Cybersecurity Professional · GenAI Developer · Security Tool Builder

**AshlynxCyber**

---

## Project Status

RDRS currently demonstrates a working local ransomware detection and response pipeline with:

```text
Filesystem monitoring       ✓
Entropy analysis            ✓
Behavioral detection        ✓
Process telemetry           ✓
Threat scoring              ✓
Critical classification     ✓
Alert persistence           ✓
Incident persistence        ✓
Evidence quarantine         ✓
Simulation-safe response    ✓
REST API                    ✓
Web dashboard               ✓
JSON / CSV / PDF reporting  ✓
Automated tests             ✓ 8 passed
```

The system is intended to demonstrate the engineering workflow from suspicious filesystem behavior through detection, scoring, evidence preservation, incident recording, and analyst-facing visualization.
