# Find Evil! Hackathon — Project Instructions for Claude Code

## Project Overview

Build a Python-based MCP (Model Context Protocol) middleware server that wraps SANS SIFT
Workstation forensic tools, reducing hallucinations in autonomous AI-driven incident response.
This project targets the **Find Evil! Hackathon** hosted by SANS DFIR on Devpost.

**Deadline: June 15, 2026**
**Prize: $22,000+**
**Team: Alpha (lead), Beta (benchmark + video), Gamma (RAG pipeline)**

---

## The Problem We Are Solving

Protocol SIFT is the existing proof-of-concept that connects Claude Code to SANS SIFT
Workstation forensic tools. It works but hallucinates more than acceptable because:

1. **Raw CLI output dumped directly into Claude's context window** — volatility output
   can be 10,000+ lines. Claude gets overwhelmed and hallucinates findings.

2. **Generic shell execution** — Protocol SIFT exposes `execute_shell_cmd` to Claude.
   The agent guesses tool names and parameters, causing wasted API calls and wrong results.

3. **Prompt-based safety only** — Protocol SIFT relies on instructions like
   "never modify evidence files" in CLAUDE.md. These can be ignored by the model.
   No architectural enforcement exists.

4. **No threat intelligence context** — Claude relies purely on training data to identify
   threats. New malware families, new IOCs, new TTPs are unknown to it.

**Our hypothesis:** A Python middleware layer between Claude Code and SIFT tools that
parses raw output into structured data, exposes typed functions instead of generic shell
commands, and injects RAG-retrieved threat intelligence will significantly reduce
hallucinations compared to baseline Protocol SIFT.

---

## Our Architecture

```
Claude Code (autonomous execution engine)
        ↓ calls typed MCP functions
Python MCP Server (our middleware)
        ↓ executes and PARSES raw output
SIFT Tools (volatility, log2timeline, sleuthkit, etc.)
        ↑ structured JSON returned (not raw text)
RAG Pipeline (ChromaDB + threat intelligence)
        ↑ injected into Claude's context before analysis
Benchmark Framework (scores our system vs Protocol SIFT baseline)
```

**Key design principle:** The agent physically cannot call invalid tool parameters
because we expose separate typed functions per tool action, not one generic function
with a plugin parameter.

---

## Repository Structure To Build

```
find-evil/
├── mcp_server/
│   ├── server.py              ← Main MCP server (FastMCP)
│   ├── tools/
│   │   ├── volatility.py      ← Volatility 3 wrappers
│   │   ├── log2timeline.py    ← Plaso/log2timeline wrappers
│   │   ├── sleuthkit.py       ← Sleuth Kit wrappers
│   │   ├── yara_tools.py      ← YARA hunting wrappers
│   │   └── windows_artifacts.py ← EZ Tools wrappers
│   └── parsers/
│       ├── pslist_parser.py   ← Parse volatility pslist output
│       ├── netscan_parser.py  ← Parse volatility netscan output
│       ├── malfind_parser.py  ← Parse volatility malfind output
│       └── timeline_parser.py ← Parse log2timeline output
├── rag/
│   ├── knowledge_base.py      ← ChromaDB setup and querying
│   ├── ingest/
│   │   ├── mitre_attack.py    ← Load MITRE ATT&CK framework
│   │   ├── threat_intel.py    ← Load threat intelligence feeds
│   │   └── case_history.py    ← Load previous case findings
│   └── query.py               ← Semantic search interface
├── benchmark/
│   ├── runner.py              ← Benchmark execution engine
│   ├── scorer.py              ← Score findings vs ground truth
│   ├── ground_truth/
│   │   └── rocba_ground_truth.json ← ROCBA case answer key
│   └── reports/
│       └── comparison_report.py    ← Generate comparison PDF
├── agents/
│   ├── orchestrator.py        ← LangGraph multi-agent coordinator
│   ├── memory_agent.py        ← Memory forensics specialist
│   ├── disk_agent.py          ← Disk forensics specialist
│   └── network_agent.py       ← Network forensics specialist
├── docs/
│   ├── architecture.md        ← Architecture diagram description
│   └── accuracy_report.md     ← Hallucination comparison report
├── tests/
│   └── test_parsers.py        ← Unit tests for parsers
├── CLAUDE.md                  ← Project instructions for Claude Code
├── README.md                  ← Setup and usage instructions
└── requirements.txt           ← Python dependencies
```

---

## Phase 1: MCP Server (Most Critical — Build First)

### Goal
Wrap SIFT forensic tools as typed, structured Python functions exposed via MCP protocol.

### Key Design Decisions
- **No generic `run_volatility(plugin, image_path)` function**
- **Each tool action = separate function with specific parameters**
- **Every function returns structured JSON, never raw text**
- **Python parses raw CLI output before it reaches Claude**

### Tools to Wrap (Priority Order)

#### Volatility 3 (Memory Forensics)

```python
from mcp.server.fastmcp import FastMCP
import subprocess
import json

mcp = FastMCP("SIFT Forensic Server")

@mcp.tool()
def get_process_list(image_path: str) -> str:
    """
    Lists all running processes from a memory image.
    Use this FIRST when investigating a memory image.
    Returns structured JSON with pid, name, ppid, and suspicious flag.
    Suspicious flag is True if process name doesn't match known Windows baselines.
    """
    # Run volatility
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path, "windows.pslist"],
        capture_output=True, text=True
    )
    # Parse raw output into structured data
    processes = parse_pslist(result.stdout)
    # Compare against known-normal baseline
    for proc in processes:
        proc["suspicious"] = is_suspicious_process(proc)
    return json.dumps(processes)

@mcp.tool()
def find_injected_code(image_path: str) -> str:
    """
    Finds processes with injected malicious code in memory.
    Use when get_process_list reveals suspicious processes.
    Returns structured JSON with process name, pid, address, and injection type.
    """
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path, "windows.malfind"],
        capture_output=True, text=True
    )
    return json.dumps(parse_malfind(result.stdout))

@mcp.tool()
def get_network_connections(image_path: str) -> str:
    """
    Lists all active and recently closed network connections from memory.
    Use to identify C2 communication or data exfiltration.
    Returns structured JSON with protocol, local/foreign addresses, state, and pid.
    """
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path, "windows.netscan"],
        capture_output=True, text=True
    )
    return json.dumps(parse_netscan(result.stdout))

@mcp.tool()
def get_registry_hives(image_path: str) -> str:
    """
    Lists registry hives loaded in memory.
    Use to find persistence mechanisms and user activity.
    """
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path, "windows.registry.hivelist"],
        capture_output=True, text=True
    )
    return json.dumps(parse_hivelist(result.stdout))

@mcp.tool()
def get_loaded_dlls(image_path: str, pid: int) -> str:
    """
    Lists DLLs loaded by a specific process.
    Use after finding a suspicious process to check for malicious DLLs.
    pid: Process ID from get_process_list results.
    """
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path,
         "windows.dlllist", "--pid", str(pid)],
        capture_output=True, text=True
    )
    return json.dumps(parse_dlllist(result.stdout))

@mcp.tool()
def get_command_history(image_path: str) -> str:
    """
    Extracts command line history from memory (conhost/console).
    Use to find commands run by an attacker.
    """
    result = subprocess.run(
        ["python3", "-m", "volatility3", "-f", image_path, "windows.cmdline"],
        capture_output=True, text=True
    )
    return json.dumps(parse_cmdline(result.stdout))

@mcp.tool()
def finish_analysis(
    summary: str,
    suspicious_processes: list,
    network_iocs: list,
    mitre_techniques: list,
    timeline: list,
    confidence: str
) -> str:
    """
    Call this when you have enough evidence to write a final report.
    Do not keep investigating if you have identified the key findings.
    summary: Plain English description of what happened.
    suspicious_processes: List of suspicious process names found.
    network_iocs: List of suspicious IPs, domains, or ports.
    mitre_techniques: List of MITRE ATT&CK technique IDs (e.g. T1055).
    timeline: List of events in chronological order.
    confidence: Your confidence level - "high", "medium", or "low".
    """
    findings = {
        "summary": summary,
        "suspicious_processes": suspicious_processes,
        "network_iocs": network_iocs,
        "mitre_techniques": mitre_techniques,
        "timeline": timeline,
        "confidence": confidence
    }
    # Save findings to analysis directory
    with open("./analysis/findings.json", "w") as f:
        json.dump(findings, f, indent=2)
    return json.dumps(findings)
```

### Parser Functions (The Middleware Magic)

These parsers are the core of what makes our system better than Protocol SIFT.
Raw tool output never reaches the LLM — Python parses it first.

```python
# parsers/pslist_parser.py

# Known normal Windows processes baseline
# Source: SANS Hunt Evil poster (FOR508)
KNOWN_NORMAL = {
    "System": {
        "expected_ppid": 0,
        "expected_path": None,
        "max_instances": 1,
        "expected_user": "SYSTEM"
    },
    "smss.exe": {
        "expected_ppid": 4,  # System
        "expected_path": "\\Windows\\System32\\smss.exe",
        "max_instances": 3,
        "expected_user": "SYSTEM"
    },
    "csrss.exe": {
        "expected_ppid": None,  # created by smss which exits
        "expected_path": "\\Windows\\System32\\csrss.exe",
        "max_instances": 99,
        "expected_user": "SYSTEM"
    },
    "wininit.exe": {
        "expected_ppid": None,
        "expected_path": "\\Windows\\System32\\wininit.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM"
    },
    "services.exe": {
        "expected_ppid": "wininit.exe",
        "expected_path": "\\Windows\\System32\\services.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM"
    },
    "lsass.exe": {
        "expected_ppid": "wininit.exe",
        "expected_path": "\\Windows\\System32\\lsass.exe",
        "max_instances": 1,
        "expected_user": "SYSTEM"
    },
    "svchost.exe": {
        "expected_ppid": "services.exe",
        "expected_path": "\\Windows\\System32\\svchost.exe",
        "max_instances": 99,
        "expected_user": "SYSTEM"
    },
    "explorer.exe": {
        "expected_ppid": None,  # userinit.exe which exits
        "expected_path": "\\Windows\\explorer.exe",
        "max_instances": 5,
        "expected_user": None  # logged on user
    },
    "winlogon.exe": {
        "expected_ppid": None,
        "expected_path": "\\Windows\\System32\\winlogon.exe",
        "max_instances": 99,
        "expected_user": "SYSTEM"
    },
    "RuntimeBroker.exe": {
        "expected_ppid": "svchost.exe",
        "expected_path": "\\Windows\\System32\\RuntimeBroker.exe",
        "max_instances": 99,
        "expected_user": None
    },
    "taskhostw.exe": {
        "expected_ppid": "svchost.exe",
        "expected_path": "\\Windows\\System32\\taskhostw.exe",
        "max_instances": 99,
        "expected_user": None
    },
}

def parse_pslist(raw_output: str) -> list:
    """Parse volatility pslist raw output into structured list."""
    processes = []
    lines = raw_output.strip().split('\n')
    
    # Skip header lines
    data_started = False
    for line in lines:
        if 'PID' in line and 'PPID' in line:
            data_started = True
            continue
        if not data_started or not line.strip():
            continue
            
        parts = line.split()
        if len(parts) >= 4:
            try:
                proc = {
                    "pid": int(parts[0]) if parts[0].isdigit() else 0,
                    "name": parts[1],
                    "ppid": int(parts[2]) if parts[2].isdigit() else 0,
                    "threads": parts[3] if len(parts) > 3 else "0",
                    "create_time": parts[6] if len(parts) > 6 else "unknown",
                    "suspicious": False,
                    "anomalies": []
                }
                processes.append(proc)
            except (ValueError, IndexError):
                continue
    
    return processes

def is_suspicious_process(proc: dict, all_processes: list) -> bool:
    """
    Compare process against known-normal baseline.
    Returns True if process shows anomalous behavior.
    """
    name = proc["name"]
    anomalies = []
    
    if name not in KNOWN_NORMAL:
        # Unknown process — flag for investigation
        anomalies.append(f"Unknown process not in Windows baseline")
        proc["anomalies"] = anomalies
        return True
    
    baseline = KNOWN_NORMAL[name]
    
    # Check parent process
    if baseline["expected_ppid"] and isinstance(baseline["expected_ppid"], str):
        parent_name = get_process_name(proc["ppid"], all_processes)
        if parent_name and parent_name != baseline["expected_ppid"]:
            anomalies.append(
                f"Wrong parent: expected {baseline['expected_ppid']}, got {parent_name}"
            )
    
    # Check instance count
    instance_count = sum(1 for p in all_processes if p["name"] == name)
    if instance_count > baseline["max_instances"]:
        anomalies.append(
            f"Too many instances: {instance_count} (max {baseline['max_instances']})"
        )
    
    proc["anomalies"] = anomalies
    return len(anomalies) > 0

def get_process_name(pid: int, processes: list) -> str:
    """Get process name by PID."""
    for proc in processes:
        if proc["pid"] == pid:
            return proc["name"]
    return None
```

---

## Phase 2: RAG Pipeline

### Goal
Build a semantic search system that retrieves relevant threat intelligence before
Claude analyzes any forensic finding.

### Knowledge Base Sources
1. MITRE ATT&CK framework (all techniques as documents)
2. Hunt Evil baseline (normal Windows processes from SANS FOR508 poster)
3. Previous case findings (grows over time)
4. AbuseIPDB / VirusTotal API lookups for live threat intel

### Implementation

```python
# rag/knowledge_base.py
import chromadb
from sentence_transformers import SentenceTransformer
import json

class ForensicKnowledgeBase:
    def __init__(self):
        self.client = chromadb.PersistentClient(path="./rag/db")
        self.embed_model = SentenceTransformer('all-MiniLM-L6-v2')
        self.collection = self.client.get_or_create_collection("forensic_knowledge")
    
    def ingest_mitre_attack(self, mitre_json_path: str):
        """Load MITRE ATT&CK techniques into knowledge base."""
        with open(mitre_json_path) as f:
            data = json.load(f)
        
        documents = []
        ids = []
        for technique in data["objects"]:
            if technique.get("type") == "attack-pattern":
                doc = f"{technique['name']}: {technique.get('description', '')}"
                documents.append(doc)
                ids.append(technique["id"])
        
        embeddings = self.embed_model.encode(documents).tolist()
        self.collection.add(
            documents=documents,
            embeddings=embeddings,
            ids=ids
        )
    
    def query(self, finding: str, n_results: int = 3) -> str:
        """
        Semantic search for threat intelligence relevant to a finding.
        Returns formatted context string for injection into Claude's prompt.
        """
        query_embedding = self.embed_model.encode([finding]).tolist()
        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=n_results
        )
        
        context = "Relevant threat intelligence:\n"
        for i, doc in enumerate(results['documents'][0]):
            context += f"[{i+1}] {doc}\n"
        return context
    
    def add_case_finding(self, case_id: str, finding: str):
        """Add a finding from a completed investigation to knowledge base."""
        embedding = self.embed_model.encode([finding]).tolist()
        self.collection.add(
            documents=[finding],
            embeddings=embedding,
            ids=[f"case_{case_id}_{hash(finding)}"]
        )
```

---

## Phase 3: Benchmark Framework

### Goal
Prove our system reduces hallucinations compared to baseline Protocol SIFT.
This is the most important component for hackathon judges.

### ROCBA Case Ground Truth

```json
{
  "case_id": "ROCBA-2020",
  "case_name": "Fred Rocba Break-In and IP Theft",
  "incident_date": "2020-11-13",
  "system": "Windows 10 Surface Laptop",
  "timezone": "EST5EDT",
  "victim": "Fred Rocba, Stark Research Labs engineer",
  
  "known_facts": {
    "fred_left_for_vacation": "2020-11-10",
    "break_in_occurred": "2020-11-13 evening",
    "system_was_logged_in": true,
    "target": "SRL intellectual property"
  },
  
  "key_questions": [
    "What SRL projects did Fred have access to?",
    "What was stolen?",
    "Where was it transferred?",
    "How was it stolen?",
    "When did the activity occur?"
  ],
  
  "accounts_on_system": [
    "fred.rocba@gmail.com",
    "fred.rocba@outlook.com",
    "frocba@stark-research-labs.com"
  ],
  
  "cloud_services": [
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "iCloud",
    "Office 365"
  ],
  
  "expected_findings": {
    "suspicious_activity_window": "2020-11-13 evening EST",
    "activity_type": "unauthorized_access",
    "exfiltration_likely": true,
    "browsers_installed": ["Edge", "Firefox", "Chrome"]
  }
}
```

### Benchmark Runner

```python
# benchmark/runner.py
import json
import subprocess
import time
from datetime import datetime

class BenchmarkRunner:
    def __init__(self, ground_truth_path: str):
        with open(ground_truth_path) as f:
            self.ground_truth = json.load(f)
    
    def run_protocol_sift_baseline(self, image_path: str, case_dir: str) -> dict:
        """
        Run original Protocol SIFT against image and capture findings.
        Records: hallucinations, false positives, missed artifacts, time taken.
        """
        start_time = time.time()
        # Protocol SIFT runs via Claude Code CLI
        # Capture output and parse findings
        result = {
            "system": "protocol_sift_baseline",
            "timestamp": datetime.utcnow().isoformat(),
            "image": image_path,
            "duration_seconds": 0,
            "findings": [],
            "hallucinations": [],
            "false_positives": [],
            "missed_artifacts": []
        }
        # ... run and capture
        result["duration_seconds"] = time.time() - start_time
        return result
    
    def run_our_system(self, image_path: str, case_dir: str) -> dict:
        """Run our MCP server + RAG system and capture findings."""
        start_time = time.time()
        result = {
            "system": "find_evil_mcp_rag",
            "timestamp": datetime.utcnow().isoformat(),
            "image": image_path,
            "duration_seconds": 0,
            "findings": [],
            "hallucinations": [],
            "false_positives": [],
            "missed_artifacts": []
        }
        # ... run and capture
        result["duration_seconds"] = time.time() - start_time
        return result
    
    def score(self, results: dict) -> dict:
        """Score findings against ground truth."""
        # Count true positives, false positives, missed findings
        # A hallucination = finding with no evidence in tool output
        score = {
            "true_positives": 0,
            "false_positives": 0,
            "missed_artifacts": 0,
            "hallucinations": 0,
            "accuracy_score": 0.0,
            "hallucination_rate": 0.0
        }
        return score
    
    def generate_comparison_report(self, baseline: dict, ours: dict) -> str:
        """Generate markdown comparison report for submission."""
        baseline_score = self.score(baseline)
        our_score = self.score(ours)
        
        report = f"""
# Accuracy Comparison Report

## Protocol SIFT Baseline vs Find Evil! MCP Server

| Metric | Protocol SIFT | Our System | Improvement |
|--------|--------------|------------|-------------|
| True Positives | {baseline_score['true_positives']} | {our_score['true_positives']} | {our_score['true_positives'] - baseline_score['true_positives']} |
| False Positives | {baseline_score['false_positives']} | {our_score['false_positives']} | {baseline_score['false_positives'] - our_score['false_positives']} |
| Hallucinations | {baseline_score['hallucinations']} | {our_score['hallucinations']} | {baseline_score['hallucinations'] - our_score['hallucinations']} |
| Analysis Time | {baseline['duration_seconds']:.1f}s | {ours['duration_seconds']:.1f}s | {baseline['duration_seconds'] - ours['duration_seconds']:.1f}s |

## Why Our System Reduces Hallucinations

1. **Structured parsing** — Raw volatility output parsed into JSON before LLM sees it
2. **Typed functions** — Agent cannot call invalid plugin names (no guessing)
3. **RAG context** — Threat intelligence injected before every analysis step
4. **Known-normal baseline** — Process anomalies detected in Python, not by LLM
"""
        return report
```

---

## Phase 4: Multi-Agent Orchestration (LangGraph)

### Goal
Fan-out parallel analysis with specialized agents, each with their own state.

```python
# agents/orchestrator.py
from langgraph.graph import StateGraph, END
from typing import TypedDict, Annotated
import operator

class OrchestratorState(TypedDict):
    image_path: str
    memory_findings: dict
    disk_findings: dict
    network_findings: dict
    synthesis: dict
    iterations: int
    status: str

class ForensicOrchestrator:
    def __init__(self, mcp_server_url: str, rag_pipeline):
        self.mcp_url = mcp_server_url
        self.rag = rag_pipeline
        self.graph = self._build_graph()
    
    def _build_graph(self):
        workflow = StateGraph(OrchestratorState)
        
        workflow.add_node("memory_agent", self.run_memory_agent)
        workflow.add_node("disk_agent", self.run_disk_agent)
        workflow.add_node("network_agent", self.run_network_agent)
        workflow.add_node("synthesis_agent", self.run_synthesis_agent)
        workflow.add_node("report_agent", self.run_report_agent)
        
        # Fan-out: memory, disk, network run in parallel
        workflow.set_entry_point("memory_agent")
        workflow.add_edge("memory_agent", "synthesis_agent")
        workflow.add_edge("disk_agent", "synthesis_agent")
        workflow.add_edge("network_agent", "synthesis_agent")
        workflow.add_edge("synthesis_agent", "report_agent")
        workflow.add_edge("report_agent", END)
        
        return workflow.compile()
    
    def run_memory_agent(self, state: OrchestratorState) -> OrchestratorState:
        """Specialist agent for memory forensics."""
        # Calls get_process_list, find_injected_code, get_command_history
        # Returns structured findings
        pass
    
    def run_disk_agent(self, state: OrchestratorState) -> OrchestratorState:
        """Specialist agent for disk forensics."""
        # Calls log2timeline, sleuthkit functions
        pass
    
    def run_network_agent(self, state: OrchestratorState) -> OrchestratorState:
        """Specialist agent for network forensics."""
        # Calls get_network_connections, checks IPs against threat intel
        pass
    
    def run_synthesis_agent(self, state: OrchestratorState) -> OrchestratorState:
        """Correlates findings from all three agents."""
        # Cross-references memory + disk + network findings
        # Flags discrepancies (e.g. disk says X, memory says Y)
        pass
    
    def run_report_agent(self, state: OrchestratorState) -> OrchestratorState:
        """Generates final PDF report."""
        # Uses generate_pdf_report.py from Protocol SIFT
        pass
    
    def investigate(self, image_path: str) -> dict:
        """Run full investigation against a forensic image."""
        initial_state = {
            "image_path": image_path,
            "memory_findings": {},
            "disk_findings": {},
            "network_findings": {},
            "synthesis": {},
            "iterations": 0,
            "status": "running"
        }
        return self.graph.invoke(initial_state)
```

---

## ROCBA Case Testing Plan

### Step 1 — Establish Protocol SIFT Baseline (Beta's job)

```bash
# On SIFT Workstation VM
export CASE=ROCBA-BASELINE
mkdir -p /cases/${CASE}/{analysis,exports,reports}
cp ~/.claude/case-templates/CLAUDE.md /cases/${CASE}/CLAUDE.md
cp ~/.claude/analysis-scripts/generate_pdf_report.py /cases/${CASE}/analysis/

# Edit case template with ROCBA details
nano /cases/${CASE}/CLAUDE.md

# Place memory image
cp /path/to/Rocba-Memory.raw /cases/${CASE}/

# Run Protocol SIFT
cd /cases/${CASE}
claude

# Ask Protocol SIFT:
# "Investigate Rocba-Memory.raw for signs of unauthorized access 
#  on or after November 13 2020. What processes were running? 
#  What network connections existed? Was any data exfiltrated?"

# Document ALL outputs including hallucinations
# Save the full conversation log
```

### Step 2 — Document Hallucinations

Look specifically for:
- Process names that don't exist in the memory image
- Timestamps that are wrong or impossible
- Network connections that don't exist in the data
- File names or paths that are fabricated
- Attribution claims with no evidence

### Step 3 — Run Our System Against Same Image

```bash
# Start our MCP server
python3 mcp_server/server.py

# Run our agent loop against same image
python3 agents/orchestrator.py --image /cases/ROCBA-BASELINE/Rocba-Memory.raw
```

### Step 4 — Generate Comparison Report

```bash
python3 benchmark/runner.py \
  --baseline /cases/ROCBA-BASELINE/analysis/ \
  --ours /cases/ROCBA-OURS/analysis/ \
  --ground-truth benchmark/ground_truth/rocba_ground_truth.json \
  --output docs/accuracy_report.md
```

---

## SIFT Workstation Tool Paths

These are the actual paths on the SANS SIFT Ubuntu VM:

```
Volatility 3:     python3 -m volatility3
log2timeline:     log2timeline.py
psort:            psort.py
Sleuth Kit fls:   fls
Sleuth Kit mmls:  mmls
EZ Tools:         /opt/zimmermantools/
ewfmount:         ewfmount
bulk_extractor:   bulk_extractor
YARA:             yara
```

---

## Self-Correction Mechanism

The agent must self-correct when:

1. **Tool returns error** — retry with corrected parameters
2. **Finding seems inconsistent** — re-investigate with different tool
3. **Confidence is low** — run additional verification steps
4. **Max iterations reached** — force termination, report partial findings

```python
MAX_ITERATIONS = 10  # Hard cap — never exceed this

def route_after_llm(state):
    if state["iterations"] >= MAX_ITERATIONS:
        return "force_stop"
    if state["last_tool_call"] == "finish_analysis":
        return "complete"
    if state["last_tool_error"]:
        return "self_correct"
    return "continue"
```

---

## Evidence Integrity Rules

These must be enforced architecturally (not just in prompts):

1. **MCP server never exposes write operations to evidence directories**
   - No `dd`, `rm`, `mv` on `/cases/`, `/mnt/`, `/media/`
   - Only read operations on evidence files

2. **All tool outputs saved to `./exports/` automatically**
   - Preserves raw output for audit trail

3. **Findings always traceable to specific tool execution**
   - Every finding includes: tool name, command run, timestamp, raw output hash

4. **Chain of custody log** — append to `./analysis/forensic_audit.log` after every step

---

## Hackathon Submission Checklist

All 8 required components:

```
[ ] 1. GitHub repo — public, MIT license
[ ] 2. Demo video — 5 min max, shows self-correction sequence
[ ] 3. Architecture diagram — shows MCP server, RAG, agents, trust boundaries
[ ] 4. Written project description — Devpost format
[ ] 5. Dataset documentation — ROCBA case, source, what was found
[ ] 6. Accuracy report — Protocol SIFT baseline vs our system comparison
[ ] 7. Try-it-out instructions — README with setup steps for SIFT VM
[ ] 8. Agent execution logs — full traces with timestamps
```

---

## Demo Video Plan (Beta's job)

```
0:00-0:30  Problem statement
           "Protocol SIFT hallucinates because it dumps 
            10,000 lines of raw output directly into Claude"
           Show a real Protocol SIFT hallucination example

0:30-1:30  Architecture walkthrough
           Show the diagram
           "Our MCP server parses raw output before Claude sees it"
           "RAG injects threat intelligence context"

1:30-3:00  Live demo — ROCBA case
           Show our system running against Rocba-Memory.raw
           Show it finding the November 13 intrusion
           Show self-correction when a tool fails

3:00-3:30  Benchmark comparison
           Show the comparison table
           "X fewer hallucinations, Y% more accurate"

3:30-4:00  Architecture security boundaries
           Show evidence integrity enforcement
           Show audit log

4:00-4:30  What's next
           More SIFT tools wrapped
           Live endpoint triage
           SIEM integration
```

---

## Python Dependencies

```
# requirements.txt
mcp>=1.0.0
langgraph>=0.1.0
chromadb>=0.4.0
sentence-transformers>=2.2.0
anthropic>=0.25.0
langchain>=0.1.0
python-dotenv>=1.0.0
weasyprint>=60.0
pytest>=7.0.0
```

---

## Environment Variables

```bash
# .env file (never commit to GitHub)
ANTHROPIC_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

---

## Key Constraints

1. **Open source** — MIT or Apache 2.0 license required
2. **Must run on SIFT Workstation** — Ubuntu x86-64
3. **Evidence read-only** — never modify original forensic images
4. **Max iterations cap** — always include `MAX_ITERATIONS = 10`
5. **Structured logs** — every tool execution logged with timestamp + token usage
6. **Reproducible** — judges must be able to run it locally on SIFT VM

---

## Development Priority Order

```
Day 1-2:  Setup + SIFT installation + Protocol SIFT baseline testing
Day 3-4:  MCP Server core (3 volatility tools + parsers + known-normal baseline)
Day 5-6:  RAG pipeline (ChromaDB + MITRE ATT&CK + threat intel)
Day 7:    Multi-agent LangGraph orchestration
Day 8:    Benchmark framework + comparison report generation
Day 9:    Demo video + submission polish + README
```

---

## Contact and Resources

- Hackathon Devpost: https://devpost.com/software/find-evil
- Protocol SIFT GitHub: https://github.com/teamdfir/protocol-sift
- MITRE ATT&CK: https://attack.mitre.org/
- CyberDefenders CTF: https://cyberdefenders.org
- SIFT Workstation: https://sans.org/tools/sift-workstation
- Hackathon Slack: Protocol SIFT Slack (join for mentors + sample data)

