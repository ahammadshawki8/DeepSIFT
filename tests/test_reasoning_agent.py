"""Tests for the agentic reasoning loop — verified with a deterministic mock LLM
(no API key required), proving the control flow is real: tool dispatch, self-correction
on tool failure, hypothesis tracking, and structured finish."""
import json
from pathlib import Path

from agents.reasoning_agent import ReasoningAgent, FINISH_TOOL


class MockLLM:
    """Scripts a senior-analyst investigation: triage -> a failing tool (forces
    self-correction) -> a successful pivot -> finish."""

    def __init__(self):
        self.calls = 0
        self.saw_tool_error = False

    def create_message(self, system, messages, tools):
        self.calls += 1
        # Detect that a previous tool result reported an error (self-correction signal).
        last = messages[-1]["content"] if messages else ""
        if isinstance(last, list):
            for blk in last:
                if isinstance(blk, dict) and "error" in str(blk.get("content", "")).lower():
                    self.saw_tool_error = True

        if self.calls == 1:
            return {"stop_reason": "tool_use", "content": [
                {"type": "text", "text": "Hypothesis 1: unauthorized RDP access. Listing processes."},
                {"type": "tool_use", "id": "t1", "name": "get_process_list",
                 "input": {"image_path": "/x.raw"}}]}
        if self.calls == 2:
            # Intentionally call a tool the runner will fail, to exercise self-correction.
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t2", "name": "get_network_connections",
                 "input": {"image_path": "/x.raw"}}]}
        if self.calls == 3:
            # The runner returned an error; pivot to a different tool (self-correct).
            return {"stop_reason": "tool_use", "content": [
                {"type": "text", "text": "netscan failed; pivoting to event logs on disk."},
                {"type": "tool_use", "id": "t3", "name": "parse_event_logs",
                 "input": {"evtx_dir": "/mnt/evidence/Windows/System32/winevt/Logs"}}]}
        return {"stop_reason": "tool_use", "content": [
            {"type": "tool_use", "id": "t4", "name": "finish_investigation",
             "input": {"summary": "Unauthorized access via RDP confirmed.",
                       "attack_chain": ["Failed logons", "Successful RDP", "File access"],
                       "suspicious_processes": ["MRC.exe (PID 29440)"],
                       "network_iocs": ["81.30.144.115"],
                       "mitre_techniques": ["T1110", "T1021.001"],
                       "confidence": "high"}}]}


def _fake_runner(name, args):
    if name == "get_network_connections":
        raise RuntimeError("netscan plugin failed on this image")
    if name == "get_process_list":
        return json.dumps({"total_processes": 42, "suspicious_processes": ["MRC.exe"]})
    if name == "parse_event_logs":
        return json.dumps({"total_events": 100, "summary": {"failed_logons": [{"event_id": "4625"}]}})
    return json.dumps({"ok": True})


def test_agentic_loop_self_corrects_and_finishes(tmp_path):
    tools = [{"name": "get_process_list", "description": "list procs",
              "input_schema": {"type": "object", "properties": {"image_path": {"type": "string"}}}},
             {"name": "get_network_connections", "description": "netscan",
              "input_schema": {"type": "object", "properties": {"image_path": {"type": "string"}}}},
             {"name": "parse_event_logs", "description": "evtx",
              "input_schema": {"type": "object", "properties": {"evtx_dir": {"type": "string"}}}}]
    llm = MockLLM()
    agent = ReasoningAgent(llm=llm, tool_runner=_fake_runner, tools=tools, max_iterations=10)
    findings = agent.investigate("/x.raw", case_dir=str(tmp_path),
                                 evidence_mount="/mnt/evidence")

    assert findings["status"] == "complete"
    assert findings["mode"] == "agentic-reasoning"
    assert findings["confidence"] == "high"
    assert "81.30.144.115" in findings["network_iocs"]
    assert findings["attack_chain"]                       # narrative produced
    assert llm.saw_tool_error                              # self-correction path exercised
    # tool failure was fed back and the agent pivoted (>=3 tool calls before finish)
    tool_calls = [t for t in agent.transcript if t["event"] == "tool_call"]
    assert len(tool_calls) >= 3
    # artifacts written
    assert (tmp_path / "findings_agentic.json").exists()
    assert (tmp_path / "agent_transcript.json").exists()


def test_finish_tool_schema_present():
    assert FINISH_TOOL["name"] == "finish_investigation"
    assert "confidence" in FINISH_TOOL["input_schema"]["properties"]


def test_iteration_cap_returns_partial(tmp_path):
    class NeverFinish:
        def create_message(self, system, messages, tools):
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "x", "name": "get_process_list",
                 "input": {"image_path": "/x.raw"}}]}
    agent = ReasoningAgent(llm=NeverFinish(), tool_runner=_fake_runner,
                           tools=[{"name": "get_process_list", "description": "p",
                                   "input_schema": {"type": "object"}}], max_iterations=3)
    findings = agent.investigate("/x.raw", case_dir=str(tmp_path))
    assert findings["partial"] is True
    assert findings["status"] == "partial"
