# DeepSIFT — Testing Instructions
## Full End-to-End Comparison: Protocol SIFT Baseline vs DeepSIFT

This guide walks you through everything from downloading the SIFT VM to generating the
final benchmark comparison report. Follow the steps in order.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Set Up SIFT Workstation VM](#2-set-up-sift-workstation-vm)
3. [Get the ROCBA Forensic Image](#3-get-the-rocba-forensic-image)
4. [Clone DeepSIFT on the VM](#4-clone-deepsift-on-the-vm)
5. [Install Dependencies](#5-install-dependencies)
6. [Configure Environment](#6-configure-environment)
7. [Verify SIFT Tools](#7-verify-sift-tools)
8. [Seed the RAG Knowledge Base](#8-seed-the-rag-knowledge-base)
9. [Run Tests (32/32 sanity check)](#9-run-tests-3232-sanity-check)
10. [Run Protocol SIFT Baseline Investigation](#10-run-protocol-sift-baseline-investigation)
11. [Run DeepSIFT Investigation](#11-run-deepsift-investigation)
12. [Generate the Benchmark Comparison Report](#12-generate-the-benchmark-comparison-report)
13. [Review and Interpret Results](#13-review-and-interpret-results)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Prerequisites

You need the following before starting:

| Item | Notes |
|------|-------|
| Host machine | 16 GB RAM minimum (18 GB for the ROCBA memory image alone), 100 GB free disk |
| VirtualBox 7.x **or** VMware Workstation/Fusion | Either works — SIFT ships OVA + VMDK |
| Python 3.10+ | Already on SIFT VM |
| Anthropic API key | Get from https://console.anthropic.com |
| Git | Already on SIFT VM |
| Internet access from VM | Required for first-run RAG seeding |

---

## 2. Set Up SIFT Workstation VM

### 2.1 Download SIFT Workstation

SIFT Workstation is a free Ubuntu forensics VM from SANS.

```bash
# Download from the official SANS page:
# https://www.sans.org/tools/sift-workstation/
#
# Direct download (registration required — free account):
#   https://www.sans.org/tools/sift-workstation/
#
# You will get one of:
#   sift-workstation-<version>.ova     (VirtualBox / VMware)
#   sift-workstation-<version>.vmwarevm  (VMware)
```

### 2.2 Import into VirtualBox

```
1. Open VirtualBox → File → Import Appliance
2. Select the downloaded .ova file
3. Set RAM to at least 16 GB (Settings → System → Base Memory)
4. Set CPU to at least 4 cores
5. Click Import (takes 3-10 min)
6. Start the VM
```

### 2.3 Import into VMware

```
1. Open VMware → File → Open
2. Select the .ova or .vmwarevm file
3. Edit VM settings: RAM → 16 GB, CPU → 4 cores
4. Power on
```

### 2.4 SIFT VM Login

```
Username: sansforensics
Password: forensics
```

Open a terminal inside the VM for all remaining steps.

---

## 3. Get the ROCBA Forensic Image

The ROCBA case (`Rocba-Memory.raw`) is the SANS FOR508 practice memory image.

### Option A — SANS FOR508 Course (if enrolled)
Download from your SANS course materials portal. The image is named `Rocba-Memory.raw`
(~18 GB memory image).

### Option B — Hackathon Dataset
If you received the image as part of the "Find Evil!" hackathon challenge:
```bash
# The challenge dataset link was provided in your Devpost invitation email.
# Download to /cases/ROCBA/ on the SIFT VM.
```

### Option C — Manual Transfer from Host
```bash
# On your host machine, copy the image into the VM's shared folder,
# or use scp if SSH is enabled on the VM:
scp Rocba-Memory.raw sansforensics@<vm-ip>:/tmp/
```

### Place the image in the correct location
```bash
sudo mkdir -p /cases/ROCBA
sudo cp /tmp/Rocba-Memory.raw /cases/ROCBA/
sudo chown -R sansforensics:sansforensics /cases/ROCBA
ls -lh /cases/ROCBA/
# Expected: Rocba-Memory.raw  ~18G
```

---

## 4. Clone DeepSIFT on the VM

```bash
cd ~
git clone https://github.com/ahammadshawki8/DeepSIFT.git
cd DeepSIFT
```

---

## 5. Install Dependencies

```bash
# Make sure pip is up to date
python3 -m pip install --upgrade pip

# Install all DeepSIFT Python dependencies
pip3 install -r requirements.txt
```

The key packages installed are:
- `mcp`, `fastmcp` — MCP server framework
- `chromadb`, `sentence-transformers` — RAG knowledge base
- `langgraph` — multi-agent orchestrator
- `python-dotenv` — .env config loading
- `yara-python` — YARA rule scanning
- `pytest` — test runner

**Note:** The first run of `sentence-transformers` will download the `all-MiniLM-L6-v2`
embedding model (~90 MB) from Hugging Face. This requires internet access.

---

## 6. Configure Environment

```bash
cd ~/DeepSIFT
cp .env.example .env
nano .env
```

Fill in these values:

```env
# Required
ANTHROPIC_API_KEY=sk-ant-...your-key-here...

# Optional but recommended
VIRUSTOTAL_API_KEY=your-vt-key-here     # free at virustotal.com
ABUSEIPDB_API_KEY=your-abuseipdb-key   # free at abuseipdb.com

# Paths — these defaults work on SIFT Workstation as-is
CASE_DIR=/cases
EXPORTS_DIR=./exports
ANALYSIS_DIR=./analysis
EZ_TOOLS_DIR=/opt/zimmermantools
HAYABUSA_CMD=hayabusa
```

Save and exit (`Ctrl+X`, `Y`, `Enter` in nano).

### Verify EZ Tools are present

```bash
ls /opt/zimmermantools/
# You should see: EvtxECmd.exe, AppCompatCacheParser.exe, MFTECmd.exe,
#                 AmcacheParser.exe, PECmd.exe, RBCmd.exe, LECmd.exe, etc.

# If not present, install them:
sudo apt-get update && sudo apt-get install -y zimmerman-tools
# OR follow: https://www.sans.org/tools/ez-tools/
```

### Verify dotnet runtime (required for EZ Tools)

```bash
dotnet --version
# Expected: 6.0.x or higher
# If not installed:
sudo apt-get install -y dotnet-sdk-6.0
```

---

## 7. Verify SIFT Tools

Run this quick check to confirm all underlying forensic tools are available:

```bash
# Volatility 3
python3 -m volatility3 --help | head -5
# Expected: "Volatility 3 Framework ..."

# log2timeline
log2timeline.py --version
# Expected: "log2timeline.py 20XX..."

# Sleuth Kit
fls --version
# Expected: "The Sleuth Kit version ..."

# YARA
yara --version
# Expected: "4.x.x"

# Hayabusa (optional but recommended)
hayabusa --version || echo "Hayabusa not found — Sigma rules will be skipped"
```

If Volatility is missing:
```bash
pip3 install volatility3
```

---

## 8. Seed the RAG Knowledge Base

This downloads MITRE ATT&CK and indexes it into ChromaDB. Run once — subsequent runs
are idempotent (they skip already-indexed content).

```bash
cd ~/DeepSIFT
python3 rag/ingest/run_all.py
```

**Expected output:**
```
[RAG] Seeding MITRE ATT&CK techniques...
[RAG] Ingested 700+ techniques into chromadb
[RAG] Seeding threat intelligence IOCs...
[RAG] Seeding ROCBA case-specific IOCs...
[RAG] Knowledge base ready: 800+ documents indexed
```

This takes 3–8 minutes on first run. If it fails due to network issues:
```bash
# Retry just the MITRE ingest
python3 rag/ingest/mitre_attack.py

# Then retry threat intel
python3 rag/ingest/threat_intel.py

# Then ROCBA IOCs
python3 rag/ingest/rocba_iocs.py
```

---

## 9. Run Tests (32/32 Sanity Check)

Confirm all parsers and middleware are working before touching real evidence:

```bash
cd ~/DeepSIFT
pytest tests/ -v
```

**Expected output:**
```
tests/test_parsers.py::test_pslist_known_normal PASSED
tests/test_parsers.py::test_pslist_masquerade_detection PASSED
tests/test_parsers.py::test_netscan_external_ip_flagging PASSED
tests/test_parsers.py::test_malfind_pe_header_detection PASSED
...
32 passed in X.XXs
```

If any test fails, stop here and fix it before running against real evidence.

---

## 10. Run Protocol SIFT Baseline Investigation

Protocol SIFT is the "vanilla" approach: Claude Code connected directly to SIFT tools
via a generic shell command, with raw output dumped into the LLM context.

**DeepSIFT already ships a pre-run Protocol SIFT baseline** for the ROCBA case:
```
benchmark/baselines/protocol_sift_rocba_findings.json
benchmark/baselines/protocol_sift_memory_baseline.md
```

You can use this directly for the comparison (skip to Step 12), **or** re-run it yourself:

### 10.1 Set Up Protocol SIFT (optional — for independent re-run)

```bash
cd ~
# Protocol SIFT is Claude Code with raw SIFT tool access.
# Clone the SANS reference implementation from the hackathon page, or use
# Claude Code directly with an execute_shell_cmd MCP tool configured.

# Install Claude Code CLI (if not already installed)
npm install -g @anthropic-ai/claude-code

# Create a minimal MCP config that exposes raw shell access
mkdir -p ~/.config/claude
cat > ~/.config/claude/claude.json << 'EOF'
{
  "mcpServers": {
    "sift_shell": {
      "command": "python3",
      "args": ["-c", "import sys,subprocess; [print(subprocess.run(l,shell=True,capture_output=True,text=True).stdout) for l in sys.stdin]"]
    }
  }
}
EOF
```

### 10.2 Run Protocol SIFT Investigation

```bash
cd ~
mkdir -p /cases/ROCBA-BASELINE
claude --dangerously-skip-permissions << 'EOF'
You are a DFIR analyst. Investigate the memory image at /cases/ROCBA/Rocba-Memory.raw
for signs of unauthorized access on or after November 13, 2020.

Use volatility to run:
1. windows.pslist
2. windows.malfind
3. windows.netscan
4. windows.cmdline
5. windows.svcscan

Run each plugin and report your findings. Save a summary to
/cases/ROCBA-BASELINE/findings.json with keys: suspicious_processes,
network_iocs, mitre_techniques, confidence.
EOF
```

### 10.3 Save the baseline findings

```bash
# If the LLM wrote findings.json:
cp /cases/ROCBA-BASELINE/findings.json \
   ~/DeepSIFT/benchmark/baselines/protocol_sift_rocba_findings_new.json

# OR simply use the pre-shipped baseline:
# benchmark/baselines/protocol_sift_rocba_findings.json  ← already there
```

---

## 11. Run DeepSIFT Investigation

This is the main event. Two ways to run — pick one:

### Option A: Via Claude Code + MCP Server (full interactive investigation)

This is the intended usage: Claude Code calls typed MCP functions, never raw shell.

**Terminal 1 — Start the MCP server:**
```bash
cd ~/DeepSIFT
python3 mcp_server/server.py
# Expected: "DeepSIFT MCP server started — 148 tools registered"
# Leave this terminal running.
```

**Terminal 2 — Configure Claude Code to use DeepSIFT:**
```bash
mkdir -p ~/.config/claude
cat > ~/.config/claude/claude.json << 'EOF'
{
  "mcpServers": {
    "deepsift": {
      "command": "python3",
      "args": ["/home/sansforensics/DeepSIFT/mcp_server/server.py"]
    }
  }
}
EOF
```

**Terminal 2 — Run the investigation:**
```bash
cd ~/DeepSIFT
claude << 'EOF'
Investigate /cases/ROCBA/Rocba-Memory.raw for signs of unauthorized access
on or after November 13, 2020.

Use DeepSIFT tools only. Follow the Memory Image Investigation workflow:
1. get_process_list
2. scan_hidden_processes
3. find_injected_code
4. get_network_connections
5. get_command_history
6. lookup_ip_reputation for each external IP
7. finish_analysis with your complete findings

Save results to /home/sansforensics/DeepSIFT/analysis/findings.json
EOF
```

**What to expect:**
- Claude will call each typed function in sequence
- Each response is structured JSON — no raw terminal output visible
- `analysis/forensic_audit.log` is updated after every tool call
- `exports/` accumulates raw output with SHA-256 hashes
- Final `analysis/findings.json` is written when `finish_analysis` is called

---

### Option B: Via demo.py (automated, no interactive Claude session)

This runs the LangGraph multi-agent orchestrator directly — no Claude Code session needed.
Use this for reproducible, scriptable benchmark runs.

```bash
cd ~/DeepSIFT

# Memory-only investigation:
python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw

# Full investigation with disk image (if available):
python3 demo.py \
    --image /cases/ROCBA/Rocba-Memory.raw \
    --disk-image /cases/ROCBA/Rocba-Disk.E01 \
    --evidence-mount /mnt/evidence

# With comparison against Protocol SIFT baseline:
python3 demo.py \
    --image /cases/ROCBA/Rocba-Memory.raw \
    --baseline benchmark/baselines/protocol_sift_rocba_findings.json \
    --ground-truth benchmark/ground_truth/rocba_ground_truth.json
```

**Expected output:**
```
╔══════════════════════════════════════════════════════════╗
║           DeepSIFT — Zero-Hallucination Forensics        ║
╚══════════════════════════════════════════════════════════╝

[RAG] Knowledge base ready (800+ documents)
[memory_agent] Starting memory analysis...
[memory_agent] Done: 47 processes, 3 suspicious, 1 high-risk injection, 2 suspicious cmdlines
[disk_agent] No disk image provided — skipping disk analysis
[network_agent] Starting network analysis...
[network_agent] Done: 12 connections, 2 external IPs, 1 suspicious
[browser_agent] No browser profile dir provided — skipping
[synthesis_agent] Correlating findings...
[report_agent] Report saved to analysis/findings.json

✅ Investigation complete
   Findings: analysis/findings.json
   Audit log: analysis/forensic_audit.log
   Raw exports: exports/
```

---

## 12. Generate the Benchmark Comparison Report

After both Protocol SIFT and DeepSIFT have produced `findings.json`, run the scorer:

```bash
cd ~/DeepSIFT

python3 -c "
from benchmark.runner import BenchmarkRunner
runner = BenchmarkRunner('benchmark/ground_truth/rocba_ground_truth.json')

# Score Protocol SIFT baseline
psift_score = runner.scorer.score_findings(
    'benchmark/baselines/protocol_sift_rocba_findings.json'
)
print('=== Protocol SIFT ===')
print(f'  Accuracy:          {psift_score[\"accuracy_score\"]:.1f}%')
print(f'  True Positives:    {psift_score[\"true_positives\"]}')
print(f'  False Positives:   {psift_score[\"false_positives\"]}')
print(f'  Missed Artifacts:  {psift_score[\"missed_artifacts\"]}')
print(f'  Hallucinations:    {psift_score[\"hallucinations\"]}')
print(f'  Hallucination Rate:{psift_score[\"hallucination_rate\"]:.1f}%')

# Score DeepSIFT
dsift_score = runner.scorer.score_findings('analysis/findings.json')
print()
print('=== DeepSIFT ===')
print(f'  Accuracy:          {dsift_score[\"accuracy_score\"]:.1f}%')
print(f'  True Positives:    {dsift_score[\"true_positives\"]}')
print(f'  False Positives:   {dsift_score[\"false_positives\"]}')
print(f'  Missed Artifacts:  {dsift_score[\"missed_artifacts\"]}')
print(f'  Hallucinations:    {dsift_score[\"hallucinations\"]}')
print(f'  Hallucination Rate:{dsift_score[\"hallucination_rate\"]:.1f}%')
"
```

### Generate the Full HTML Visual Report

```bash
python3 -c "
from benchmark.reports.html_report import generate_html_report
generate_html_report(
    protocol_sift_path='benchmark/baselines/protocol_sift_rocba_findings.json',
    deepsift_path='analysis/findings.json',
    ground_truth_path='benchmark/ground_truth/rocba_ground_truth.json',
    output_path='docs/accuracy_report.html'
)
print('Report written to docs/accuracy_report.html')
"

# Open the report in the VM browser
xdg-open docs/accuracy_report.html
```

The HTML report shows:
- Side-by-side findings comparison (color-coded: green = correct, red = hallucinated, yellow = missed)
- MITRE ATT&CK technique badges per finding
- Accuracy and hallucination rate chart
- Per-finding source tool traceability

### Run the Full vigia-cases Benchmark (optional)

If you want the standardized comparison used by competing teams:

```bash
python3 -c "
from benchmark.vigia_runner import VigiaRunner
runner = VigiaRunner()
runner.run_case(
    case_id='ROCBA',
    image_path='/cases/ROCBA/Rocba-Memory.raw',
    deepsift_findings='analysis/findings.json',
    protocol_sift_findings='benchmark/baselines/protocol_sift_rocba_findings.json',
    ground_truth='benchmark/ground_truth/rocba_ground_truth.json',
)
runner.print_summary()
runner.save_report('benchmark/reports/vigia_comparison.md')
"
```

---

## 13. Review and Interpret Results

### What to look for in findings.json

```bash
cat analysis/findings.json | python3 -m json.tool | less
```

Key fields to verify:
- `suspicious_processes` — must name real processes from the image (check PIDs exist)
- `network_iocs` — external IPs must have appeared in netscan output
- `mitre_techniques` — each TID should be traced to a specific finding
- `confidence` — should be "high" or "medium" for a clear compromise
- `high_risk_injections` — count of malfind PE-header injections

### Check the audit log

```bash
cat analysis/forensic_audit.log
# Shows: timestamp | tool name | SHA-256 of raw output | export path
# Every finding must be traceable to an entry here
```

### Check the exports directory

```bash
ls -lh exports/
# Each file is raw tool output, SHA-256 named
# These are the ground truth — findings.json must not claim anything not in these files
```

### Spot-check for hallucinations manually

```bash
# Take a suspicious process name from findings.json, e.g. "MRC.exe"
# Verify it appears in the actual volatility output:
grep -i "MRC.exe" exports/pslist_*.txt

# Take an external IP from network_iocs, e.g. "185.220.101.45"
# Verify it appears in netscan output:
grep "185.220.101.45" exports/netscan_*.txt
```

If a finding is in `findings.json` but NOT in `exports/`, that is a hallucination.

---

## 14. Troubleshooting

### "RAG knowledge base empty" after run_all.py
```bash
# Check ChromaDB path
ls -la rag/db/
# If empty, force re-ingest:
rm -rf rag/db/
python3 rag/ingest/run_all.py
```

### "Volatility plugin not found"
```bash
# Confirm Volatility 3 is installed (not Volatility 2)
python3 -m volatility3 --version
# If it says 2.x, install v3:
pip3 install volatility3
```

### "dotnet: command not found" (EZ Tools fail)
```bash
sudo apt-get install -y dotnet-sdk-6.0
# Verify:
dotnet --version
```

### MCP server "Address already in use"
```bash
# Kill existing server process
pkill -f "mcp_server/server.py"
# Restart
python3 mcp_server/server.py
```

### Memory image path error
```bash
# Confirm exact path and permissions
ls -lh /cases/ROCBA/Rocba-Memory.raw
# If permission denied:
sudo chmod 644 /cases/ROCBA/Rocba-Memory.raw
```

### "ModuleNotFoundError" on any import
```bash
# Ensure you're running from the DeepSIFT root directory
cd ~/DeepSIFT
python3 -c "import mcp_server; print('OK')"
# If still failing, check PYTHONPATH:
export PYTHONPATH=/home/sansforensics/DeepSIFT:$PYTHONPATH
```

### Pytest failures
```bash
# Run a single failing test with verbose output
pytest tests/test_parsers.py::test_pslist_known_normal -v -s
```

---

## Quick Reference: Full Run Checklist

```
[ ] 1. SIFT VM running, 16 GB RAM allocated
[ ] 2. Rocba-Memory.raw placed at /cases/ROCBA/Rocba-Memory.raw
[ ] 3. git clone https://github.com/ahammadshawki8/DeepSIFT.git ~/DeepSIFT
[ ] 4. pip3 install -r requirements.txt
[ ] 5. cp .env.example .env  →  fill in ANTHROPIC_API_KEY
[ ] 6. dotnet --version  →  OK
[ ] 7. python3 rag/ingest/run_all.py  →  800+ documents indexed
[ ] 8. pytest tests/ -v  →  32/32 passed
[ ] 9. python3 demo.py --image /cases/ROCBA/Rocba-Memory.raw \
            --baseline benchmark/baselines/protocol_sift_rocba_findings.json \
            --ground-truth benchmark/ground_truth/rocba_ground_truth.json
[  ] 10. Review docs/accuracy_report.html for comparison scores
[  ] 11. Copy benchmark numbers into docs/devpost_submission.md
[  ] 12. Submit on Devpost before June 15, 2026
```

---

*DeepSIFT — ahammadshawki8 — SANS DFIR "Find Evil!" Hackathon 2026*
