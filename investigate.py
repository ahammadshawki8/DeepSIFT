#!/usr/bin/env python3
"""
DeepSIFT — autonomous agentic investigation (LLM reasoning over typed MCP tools).

This is the agentic counterpart to demo.py: instead of a fixed pipeline, an LLM forms
hypotheses, chooses DeepSIFT MCP tools, reads the parsed/audited JSON, self-corrects, and
reconstructs the attack chain. The LLM only ever sees typed tool output and can never run
a raw shell command (the MCP tools are the sole interface; destructive binaries are blocked
in mcp_server.audit.guard_command).

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 investigate.py --image /cases/ROCBA/Rocba-Memory.raw \
        --evidence-mount /mnt/evidence [--max-iterations 25]

Outputs:
    analysis/findings_agentic.json   — final findings + hypotheses + attack chain
    analysis/agent_transcript.json   — every reasoning step + tool call (chain of custody)
"""
import argparse
import logging
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description="DeepSIFT agentic investigation")
    ap.add_argument("--image", required=True, help="Path to memory image")
    ap.add_argument("--evidence-mount", default="", help="Mounted disk evidence (read-only)")
    ap.add_argument("--case-dir", default="./analysis")
    ap.add_argument("--max-iterations", type=int, default=25)
    ap.add_argument("--no-rag", action="store_true")
    ap.add_argument("--all-tools", action="store_true",
                    help="Expose all 148 tools to the agent (default: curated ~25 core set)")
    ap.add_argument("--model", default=None, help="Anthropic model id (overrides ANTHROPIC_MODEL)")
    args = ap.parse_args()

    Path(args.case_dir).mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                        handlers=[logging.StreamHandler(sys.stdout),
                                  logging.FileHandler(str(Path(args.case_dir) / "investigate.log"), mode="w")])

    if not Path(args.image).exists():
        print(f"ERROR: image not found: {args.image}"); sys.exit(1)

    from agents.reasoning_agent import ReasoningAgent, AnthropicLLM, build_mcp_tool_runner
    from mcp_server.audit import begin_case_audit

    begin_case_audit()   # fresh, verifiable chain of custody for this case
    print("Building MCP tool interface...")
    schemas, runner = build_mcp_tool_runner(core_only=not args.all_tools)
    print(f"  {len(schemas)} typed tools available to the agent")

    rag = None
    if not args.no_rag:
        try:
            from rag.knowledge_base import ForensicKnowledgeBase
            rag = ForensicKnowledgeBase()
        except Exception as e:
            print(f"  RAG unavailable ({e}); continuing without it")

    try:
        llm = AnthropicLLM(model=args.model) if args.model else AnthropicLLM()
    except RuntimeError as e:
        print(f"\nERROR: {e}\n"
              "The agentic loop is LLM-driven (like every Find Evil! submission). "
              "Set a real ANTHROPIC_API_KEY and re-run. (Unit tests use a mock LLM and "
              "need no key: pytest tests/test_reasoning_agent.py)")
        sys.exit(2)

    agent = ReasoningAgent(llm=llm, tool_runner=runner, tools=schemas, rag=rag,
                           max_iterations=args.max_iterations)
    print(f"Investigating {args.image} ...\n")
    findings = agent.investigate(args.image, case_dir=args.case_dir,
                                 evidence_mount=args.evidence_mount)

    print("\n" + "=" * 60)
    print(f"Summary:    {findings.get('summary','')}")
    print(f"Confidence: {findings.get('confidence')}")
    print(f"Attack chain ({len(findings.get('attack_chain',[]))} steps):")
    for step in findings.get("attack_chain", []):
        print(f"  - {step}")
    print(f"Hypotheses tested: {len(findings.get('hypotheses',[]))}")
    print(f"Findings: {Path(args.case_dir) / 'findings_agentic.json'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
