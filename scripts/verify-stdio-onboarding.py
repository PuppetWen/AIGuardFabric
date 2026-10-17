#!/usr/bin/env python3
"""实际 Agent 的离线接入验收；只启动回环 Mock，所有数据位于本场临时根。

模拟平台独立持有测试 HMAC 密钥并先落盘再 ACK；不替代正式 SQL/HMAC 验收，
不向 Agent 下发签名密钥，不跳过真实 Agent journal、身份/链/ACK 校验。
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MCP_SERVER = r'''import json, os, pathlib, sys
handled = pathlib.Path(sys.argv[1])
for line in sys.stdin:
    frame = json.loads(line)
    with handled.open("a", encoding="utf-8") as record:
        record.write(json.dumps({"id": frame.get("id"), "method": frame.get("method")}) + "\n")
    if "id" in frame:
        response = {"jsonrpc": "2.0", "id": frame["id"], "result": {
            "content": [{"type": "text", "text": "local-mcp-ok"}],
            "token_visible": "AGF_AGENT_TOKEN" in os.environ}}
        print(json.dumps(response), flush=True)
'''


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def millis(value):
    # 对齐 Timestamp::to_rfc3339：只在哈希载荷中截断到毫秒，原记录字节仍保留。
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def entry_hash(entry):
    actor, target = entry["actor"], entry["target"]
    # 工作区启用 serde_json preserve_order；顺序须与 AuditLog::compute_hash 的 json! 完全一致。
    payload = {"tenant_id": entry["tenant_id"], "sequence": entry["sequence"],
               "action": entry["action"], "outcome": entry["outcome"],
               "actor_kind": actor["kind"], "actor_name": actor["name"],
               "actor_source_ip": actor.get("source_ip"), "target_kind": target["kind"],
               "target_id": target.get("id"), "before": entry.get("before"), "after": entry.get("after"),
               "changed_fields": entry.get("changed_fields", []), "error": entry.get("error"),
               "note": entry.get("note"), "request_id": entry.get("request_id"),
               "at": millis(entry["at"]), "prev_hash": entry["prev_hash"]}
    wire = json.dumps(payload, ensure_ascii=False, sort_keys=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(wire).hexdigest()


def signing_payload(checkpoint):
    # 对齐 SignedAuditAnchor：内部 Timestamp 为毫秒Z，外层 Chrono AutoSi 为+00:00。
    anchor = checkpoint["anchor"]
    created = millis(anchor["created_at"])
    outer = created.replace(".000Z", "Z").replace("Z", "+00:00")
    inner = "|".join(str(value) for value in (
        anchor["tenant_id"], anchor["up_to_sequence"], anchor["tail_hash"], anchor["entry_count"], created))
    return "|".join(("agf.audit-anchor.v1", checkpoint["kind"], checkpoint["chain_id"],
                     checkpoint["agent_id"], anchor["id"], checkpoint["previous_anchor_id"] or "-",
                     checkpoint["previous_anchor_hash"] or "-", inner, outer))


def witness_hash(checkpoint):
    return hashlib.sha256((signing_payload(checkpoint) + "|" + checkpoint["anchor"]["signature"]).encode()).hexdigest()


class MockAuditPlatform:
    """有界本地模拟平台；durable 指本场 fsync ledger，绝不宣称实际 PostgreSQL。"""

    def __init__(self, root):
        root.mkdir()
        self.path = root / "ledger.json"
        self.key = secrets.token_bytes(32)  # 仅模拟服务端持有，绝不进入 Agent 环境/配置。
        self.lock = threading.Lock()
        self.fault = None
        self.replays = 0
        self.persist({"tenant": str(uuid.uuid4()), "agent": str(uuid.uuid4()), "chains": {}})

    def persist(self, value):
        temporary = self.path.with_name(f".pending-{uuid.uuid4().hex}")
        with temporary.open("xb") as stream:
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)
        if os.name != "nt":
            descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def snapshot(self):
        return json.loads(self.path.read_bytes())

    def signature(self, checkpoint):
        return hmac.new(self.key, signing_payload(checkpoint).encode(), hashlib.sha256).hexdigest()

    def verify_checkpoint(self, checkpoint, state, chain):
        anchor = checkpoint["anchor"]
        assert checkpoint["kind"] == "agent-runtime" and checkpoint["chain_id"] == chain
        assert checkpoint["agent_id"] == state["agent"] and anchor["tenant_id"] == state["tenant"]
        assert anchor["entry_count"] == anchor["up_to_sequence"] >= 0
        assert hmac.compare_digest(anchor["signature"], self.signature(checkpoint))

    def append(self, batch):
        with self.lock:
            assert set(batch) == {"chain_id", "previous", "entries"}
            chain = batch["chain_id"]
            assert str(uuid.UUID(chain)) == chain and uuid.UUID(chain).int != 0
            entries, previous = batch["entries"], batch["previous"]
            assert isinstance(entries, list) and len(entries) <= 256 and len(canonical(batch)) <= 64 * 1024
            state = self.snapshot()
            ledger = state["chains"].get(chain)
            digest = hashlib.sha256(canonical(batch)).hexdigest()
            if ledger and digest in ledger["requests"]:
                saved = ledger["requests"][digest]
                assert canonical(saved["batch"]) == canonical(batch), "same request hash with different bytes"
                self.verify_checkpoint(saved["checkpoint"], state, chain)
                self.replays += 1
                return {"checkpoint": saved["checkpoint"], "durable": True, "replayed": True}
            if ledger is None:
                assert previous is None and not entries, "bootstrap must be empty"
                ledger = {"entries": [], "requests": {}, "latest": None}
                sequence, tail = 0, "0" * 64
            else:
                assert previous is not None and entries, "append must advance the acknowledged prefix"
                self.verify_checkpoint(previous, state, chain)
                assert canonical(previous) == canonical(ledger["latest"]), "stale or foreign checkpoint"
                sequence, tail = previous["anchor"]["up_to_sequence"], previous["anchor"]["tail_hash"]
            ids = {entry["id"] for entry in ledger["entries"]}
            for entry in entries:
                sequence += 1
                assert str(uuid.UUID(entry["id"])) == entry["id"] and uuid.UUID(entry["id"]).int != 0
                assert entry["id"] not in ids and len(canonical(entry)) <= 16 * 1024
                assert entry["tenant_id"] == state["tenant"] and entry["actor"]["id"] == state["agent"]
                assert entry["actor"]["kind"] == "agent" and entry["sequence"] == sequence
                assert entry["prev_hash"] == tail and re.fullmatch(r"[0-9a-f]{64}", entry["entry_hash"])
                assert hmac.compare_digest(entry["entry_hash"], entry_hash(entry)), "record hash differs"
                ids.add(entry["id"])
                tail = entry["entry_hash"]
            checkpoint = {"kind": "agent-runtime", "chain_id": chain, "agent_id": state["agent"],
                          "previous_anchor_id": previous["anchor"]["id"] if previous else None,
                          "previous_anchor_hash": witness_hash(previous) if previous else None,
                          "anchor": {"id": str(uuid.uuid4()), "tenant_id": state["tenant"],
                                     "up_to_sequence": sequence, "tail_hash": tail, "entry_count": sequence,
                                     "created_at": millis(datetime.now(timezone.utc).isoformat()).replace(".000Z", "Z"),
                                     "signature": ""}}
            checkpoint["anchor"]["signature"] = self.signature(checkpoint)
            ledger["entries"].extend(entries)
            ledger["latest"] = checkpoint
            ledger["requests"][digest] = {"batch": batch, "checkpoint": checkpoint}
            state["chains"][chain] = ledger
            self.persist(state)  # 先持久提交，再允许 HTTP 返回 ACK；丢 ACK 重试不能增加记录。
            return {"checkpoint": checkpoint, "durable": True, "replayed": False}


class LocalPolicy(BaseHTTPRequestHandler):
    calls = []
    active = {}
    mcp_key = "local-mcp-test-key"
    model_key = "local-model-test-key"
    audit = None

    def log_message(self, _format, *_args):
        pass

    def send_json(self, status, value, headers=None):
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, content in (headers or {}).items():
            self.send_header(name, content)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/v1/models" or self.headers.get("Authorization") != "Bearer " + self.model_key:
            return self.send_json(404, {"error": "unknown request"})
        self.send_json(200, {"object": "list", "data": [{"id": "local-mock-model", "object": "model"}]})

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if size > 1024 * 1024:
            return self.send_json(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(size))
        except (ValueError, UnicodeError):
            return self.send_json(400, {"error": "invalid json"})
        if self.path == "/api/v1/runtime/audit/anchors":
            if self.headers.get("X-AGF-Key") != self.mcp_key:
                return self.send_json(401, {"error": "bad MCP key"})
            try:
                ack = self.audit.append(body)
            except (AssertionError, KeyError, TypeError, ValueError):
                return self.send_json(409, {"error": "invalid or conflicting mock audit batch"})
            if body["entries"] and self.audit.fault:
                fault, self.audit.fault = self.audit.fault, None
                if fault == "lost-ack":
                    return self.send_json(503, {"error": "synthetic ACK unavailable after ledger commit"})
                assert fault == "wrong-tail"
                ack = json.loads(json.dumps(ack))
                ack["checkpoint"]["anchor"]["tail_hash"] = "f" * 64
            return self.send_json(200, ack)
        if self.path == "/v1/chat/completions":
            if self.headers.get("Authorization") != "Bearer " + self.model_key:
                return self.send_json(401, {"error": "bad model key"})
            self.calls.append({"kind": "model", "body": body})
            return self.send_json(200, {"object": "chat.completion", "model": body.get("model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "local-model-ok"}}]},
                {"X-AGF-Mocked": "true"})
        if self.path != "/api/v1/runtime/mcp/check":
            return self.send_json(404, {"error": "unknown path"})
        if self.headers.get("X-AGF-Key") != self.mcp_key:
            return self.send_json(401, {"error": "bad MCP key"})
        frame = body.get("frame")
        if body.get("finished"):
            self.active.pop(body.get("lease_id"), None)
            self.calls.append({"kind": "finish", "body": body})
            return self.send_json(200, {"allowed": True})
        self.calls.append({"kind": "mcp", "body": body})
        if body.get("response") and isinstance(frame, dict) and "method" not in frame:
            lease = body.get("lease_id")
            if lease and self.active.pop(lease, None) is None:
                return self.send_json(400, {"error": "unknown lease"})
        if isinstance(frame, dict) and frame.get("method") == "tools/call":
            name = frame.get("params", {}).get("name")
            if name == "dangerous":
                return self.send_json(200, {"allowed": False, "reason": "local policy denied"})
            if name == "bad-frame":
                lease = str(uuid.uuid4())
                self.active[lease] = frame["id"]
                return self.send_json(200, {"allowed": True, "frame": None, "lease_id": lease})
            lease = str(uuid.uuid4())
            self.active[lease] = frame["id"]
            return self.send_json(200, {"allowed": True, "frame": frame, "lease_id": lease})
        self.send_json(200, {"allowed": True, "frame": frame})


def run_agent(binary, args, env, payload=None):
    proc = subprocess.run([str(binary), *args], input=payload, text=True, encoding="utf-8", capture_output=True,
                          env=env, cwd=Path(env["AGF_DATA_DIR"]).parent, timeout=30, check=False)
    if proc.returncode:
        raise AssertionError(f"agf-agent exited {proc.returncode}: {proc.stderr[-1200:]}")
    return proc.stdout, proc.stderr


def mcp_frames(binary, config, env, frames):
    settings = config["mcpServers"]["guarded-tools"]
    child_env = {**env, **settings["env"]}
    content = "".join(json.dumps(frame) + "\n" for frame in frames)
    stdout, stderr = run_agent(binary, settings["args"], child_env, content)
    return {frame["id"]: frame for frame in map(json.loads, stdout.splitlines())}, stderr


def assert_model_mock(base_url):
    headers = {"Authorization": "Bearer " + LocalPolicy.model_key}
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request(base_url + "/v1/models", headers=headers), timeout=5) as reply:
        assert json.load(reply)["data"][0]["id"] == "local-mock-model"
    body = {"model": "local-mock-model", "messages": [{"role": "user", "content": "hello"}]}
    request = urllib.request.Request(base_url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                     headers={**headers, "Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as reply:
        assert reply.headers["X-AGF-Mocked"] == "true"
        assert json.load(reply)["choices"][0]["message"]["content"] == "local-model-ok"


def journal(env):
    paths = list((Path(env["AGF_DATA_DIR"]) / "mcp-audit-journals-v1").glob("*.json"))
    assert len(paths) == 1 and paths[0].stat().st_size <= 64 * 1024
    return json.loads(paths[0].read_bytes())


def verify_ack_retry(binary, config, env, marker, fault, frame_id):
    before = marker.read_bytes()
    calls = len([item for item in LocalPolicy.calls if item["kind"] == "mcp"])
    LocalPolicy.audit.fault = fault
    output, _ = mcp_frames(binary, config, env,
                           [{"jsonrpc": "2.0", "id": frame_id, "method": "tools/call", "params": {"name": "safe"}}])
    assert "error" in output[frame_id] and marker.read_bytes() == before, "unacknowledged frame was forwarded"
    pending = journal(env)
    assert len(pending["pending"]) == 1 and not LocalPolicy.active
    ledger = LocalPolicy.audit.snapshot()["chains"][pending["chain"]]
    assert ledger["entries"][-1] == pending["pending"][0]
    replays = LocalPolicy.audit.replays
    output, _ = mcp_frames(binary, config, env, [])  # 真正重启 Agent，只重放原审计，不重试业务帧。
    resumed = journal(env)
    assert not output and not resumed["pending"] and resumed["ack"] == ledger["latest"]
    assert LocalPolicy.audit.replays == replays + 1 and marker.read_bytes() == before
    assert len([item for item in LocalPolicy.calls if item["kind"] == "mcp"]) == calls + 1


def verify(binary, work_dir):
    project_root = Path(__file__).resolve().parents[1]
    if os.path.commonpath([project_root, binary]) != str(project_root):
        raise ValueError("--agent-bin must be built inside the project")
    if not binary.is_file():
        raise ValueError(f"agf-agent binary missing: {binary}")
    if os.path.commonpath([project_root, work_dir.resolve()]) != str(project_root):
        raise ValueError("--work-dir must be inside the project")
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="stdio-onboarding-", dir=work_dir) as temporary:
        root = Path(temporary)
        project = root / "claude-project"
        home = root / "home"
        project.mkdir()
        home.mkdir()
        agent_data = root / "agent-data"
        agent_data.mkdir()
        temporary_env = root / "temporary"
        temporary_env.mkdir()
        LocalPolicy.calls, LocalPolicy.active = [], {}
        LocalPolicy.audit = MockAuditPlatform(root / "mock-platform")
        marker = root / "handled.jsonl"
        mock_script = root / "mcp-server.py"
        mock_script.write_text(MCP_SERVER, encoding="utf-8")
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalPolicy)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"
        try:
            config = {"mcpServers": {"guarded-tools": {
                "command": str(binary),
                "args": ["mcp-proxy", "--", sys.executable, "-u", str(mock_script), str(marker)],
                "env": {"AGF_AGENT_SERVER_URL": base_url}}}}
            config_path = project / ".mcp.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            assert LocalPolicy.mcp_key not in config_path.read_text(encoding="utf-8")
            # 仅继承启动系统运行时所需变量，不继承正式 AGF/云凭据/代理/配置环境。
            allowed = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PROCESSOR_ARCHITECTURE"}
            env = {name: value for name, value in os.environ.items() if name.upper() in allowed}
            env.update(AGF_AGENT_TOKEN=LocalPolicy.mcp_key, AGF_AGENT_PROJECT_ROOTS=str(project),
                       AGF_DATA_DIR=str(agent_data), OPENAI_BASE_URL=base_url + "/v1",
                       HOME=str(home), USERPROFILE=str(home), TEMP=str(temporary_env), TMP=str(temporary_env),
                       NO_PROXY="127.0.0.1,localhost", PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1")
            stdout, _ = run_agent(binary, ["collect", "--home", str(home), "--data-dir",
                                           str(root / "agent-data"), "--no-system-probes", "--json"], env)
            snapshot = json.loads(stdout)["payload"]
            servers = snapshot["report"]["mcp_configs"]
            assert any(item["server_name"] == "guarded-tools" and not item["has_plaintext_secret"]
                       for item in servers), servers
            endpoints = snapshot["extras"]["model_endpoints"]
            assert any(item["url"] == base_url + "/v1" for item in endpoints), endpoints
            assert_model_mock(base_url)
            frames = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "safe"}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "dangerous"}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "bad-frame"}},
            ]
            outputs, stderr = mcp_frames(binary, config, env, frames)
            assert set(outputs) == {1, 2, 3, 4}, (outputs, stderr)
            assert outputs[1]["result"]["token_visible"] is False
            assert outputs[2]["result"]["content"][0]["text"] == "local-mcp-ok"
            assert "local policy denied" in outputs[3]["error"]["message"]
            assert "有效 JSON-RPC 帧" in outputs[4]["error"]["message"]
            handled = [json.loads(line)["id"] for line in marker.read_text(encoding="utf-8").splitlines()]
            assert handled == [1, 2], handled
            calls = [item["body"] for item in LocalPolicy.calls if item["kind"] == "mcp"]
            request = next(item for item in calls if item.get("frame", {}).get("id") == 2 and not item.get("response"))
            response = next(item for item in calls if item.get("frame", {}).get("id") == 2 and item.get("response"))
            assert response["lease_id"] and request["session_id"] == response["session_id"]
            assert any(item["kind"] == "finish" for item in LocalPolicy.calls), LocalPolicy.calls
            assert not LocalPolicy.active, LocalPolicy.active
            saved = journal(env)
            ledger = LocalPolicy.audit.snapshot()["chains"][saved["chain"]]
            assert not saved["pending"] and saved["ack"] == ledger["latest"]
            assert len(ledger["entries"]) == len(calls), "every actual decision must have one committed audit"
            assert LocalPolicy.mcp_key not in json.dumps(ledger) and LocalPolicy.model_key not in json.dumps(ledger)
            verify_ack_retry(binary, config, env, marker, "lost-ack", 6)
            verify_ack_retry(binary, config, env, marker, "wrong-tail", 7)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        marker.unlink()
        fail_closed, _ = mcp_frames(binary, config, env,
            [{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "safe"}}])
        assert "error" in fail_closed[5] and not marker.exists(), fail_closed
    print("PASS: discovery/model/stdin allow-deny/lease/token isolation; persistent audit ACK and exact restart replay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-bin", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()
    verify(args.agent_bin.resolve(), args.work_dir.resolve())


if __name__ == "__main__":
    main()
