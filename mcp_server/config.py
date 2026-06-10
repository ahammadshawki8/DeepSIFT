import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# SIFT tool paths
VOLATILITY_CMD = os.getenv("VOLATILITY_CMD", "python3 -m volatility3").split()
LOG2TIMELINE_CMD = os.getenv("LOG2TIMELINE_CMD", "log2timeline.py")
PSORT_CMD = os.getenv("PSORT_CMD", "psort.py")
FLS_CMD = os.getenv("FLS_CMD", "fls")
MMLS_CMD = os.getenv("MMLS_CMD", "mmls")
ICAT_CMD = os.getenv("ICAT_CMD", "icat")
YARA_CMD = os.getenv("YARA_CMD", "yara")
EZ_TOOLS_DIR = Path(os.getenv("EZ_TOOLS_DIR", "/opt/zimmermantools"))

# Runtime directories
EXPORTS_DIR = Path(os.getenv("EXPORTS_DIR", "./exports"))
ANALYSIS_DIR = Path(os.getenv("ANALYSIS_DIR", "./analysis"))
YARA_RULES_DIR = Path(os.getenv("YARA_RULES_DIR", "./yara_rules"))

# RAG
RAG_DB_PATH = os.getenv("RAG_DB_PATH", "./rag/db")
EMBED_MODEL = os.getenv("EMBED_MODEL", "all-MiniLM-L6-v2")

# Execution limits
MAX_TOOL_TIMEOUT = int(os.getenv("MAX_TOOL_TIMEOUT", "300"))
MAX_ITERATIONS = int(os.getenv("MAX_ITERATIONS", "10"))

# API keys
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

for _d in [EXPORTS_DIR, ANALYSIS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)
