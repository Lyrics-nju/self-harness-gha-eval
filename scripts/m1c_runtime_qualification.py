"""Isolated no-model runtime controller, usable with a separately bound transport.

No container creation/pull, Harbor trial or model bootstrap is implemented here.
The future setup must independently bind a real Harbor 0.21.0 container and its
original resource envelope. Missing frozen setup identity is a hard blocker.
"""
from __future__ import annotations

import base64
import gzip
import importlib.metadata
import json
import re
import subprocess
import tempfile
from pathlib import Path

from scripts import m1c_runtime_artifact as a
from scripts import gha_m1c1_runtime_fingerprint as rf

ROOT = Path(__file__).resolve().parents[1]
TASK = "terminal-bench/configure-git-webserver"
TASK_CONFIG_SHA256 = json.loads((ROOT / "configs/m1c_runtime_task_binding_v1.json").read_bytes())["task_config_sha256"]
RESOURCE_ENVELOPE = "UNRESOLVED"
ENVELOPE_FIELDS = {"memory_bytes", "nano_cpus", "storage_options", "memory_swap", "cpu_quota", "cpu_period",
                   "cpuset_cpus", "cpu_shares", "memory_reservation", "pids_limit"}
PROBE = ROOT / "scripts/m1c_runtime_no_model_probe.mjs"
PROGRAM = "/installed-agent/deepseek-harness"
SCRATCH = "/logs/artifacts/runtime-no-model"


def fixed_image(root: Path = ROOT) -> dict:
    encoded = (root / "splits/stable_task_pool_v3.json.gz.b64").read_bytes()
    with tempfile.TemporaryDirectory() as tmp:
        pool = Path(tmp) / "pool.json"
        pool.write_bytes(gzip.decompress(base64.b64decode(encoded)))
        ids = rf.load_stable_pool(pool)
    mapping = rf.load_historical_task_image_map(
        root / "evidence/m1c/runtime_fingerprint/historical_task_image_map_run_34972344189_v1.json", ids)
    selection = json.loads((root / "configs/m1c_integration_task_v3.json").read_bytes())
    a.require(selection["selected_task_id"] == TASK and selection["source_stable_pool_sha"] == rf.STABLE_POOL_SHA256,
              "INTEGRATION_TASK_DRIFT")
    a.require(TASK in ids, "TASK_NOT_IN_FROZEN_POOL")
    a.require(a.file_hash(root / "evaluation/agents/dsh_harbor_adapter/adapter.py") == a.ADAPTER_SHA,
              "PRODUCTION_ADAPTER_DRIFT")
    return dict(mapping[TASK])


def validate_container(actual: dict, selected: dict, envelope: dict, task_config_sha: str) -> None:
    """Read-back facts, not a caller's boolean 'identity_pass' declaration."""
    a.require(bool(a.HEX.fullmatch(task_config_sha)), "ORIGINAL_TASK_CONFIG_UNRESOLVED")
    a.require(set(envelope) == ENVELOPE_FIELDS,
              "RESOURCE_ENVELOPE_UNRESOLVED")
    a.require(actual["task_config_sha256"] == task_config_sha and actual["task_id"] == TASK
              and actual["harbor_version"] == "0.21.0", "CONTAINER_SETUP_IDENTITY_DRIFT")
    a.require(actual["platform"] == "linux/amd64" and
              actual["platform_digest"] == selected["historical_platform_digest"] and
              actual["image_reference"] == selected["authoritative_image_ref"], "TASK_IMAGE_IDENTITY_DRIFT")
    a.require(actual["resource_envelope"] == envelope, "FORMAL_RESOURCE_DRIFT")
    a.require(actual["network_mode"] == "none" and actual["credential_environment_names"] == []
              and actual["program_read_only"] is True and actual["program_mount"] == PROGRAM,
              "NO_MODEL_DEPLOYMENT_BOUNDARY_UNPROVEN")
    a.require(actual["program_archive_sha256"] == actual["mounted_archive_sha256"], "MOUNT_IDENTITY_DRIFT")


def probe_commands() -> list[list[str]]:
    # Absolute artifact Node only; no PATH/LD_LIBRARY_PATH/NODE_OPTIONS export.
    node = PROGRAM + "/" + a.NODE
    cli = PROGRAM + "/" + a.ENTRY
    return [[node, cli, "--help"], [node, cli, "--version"],
            [node, SCRATCH + "/probe.mjs", PROGRAM, SCRATCH + "/scratch"]]


class DockerTransport:
    """Read-back/exec only, for an already-created Harbor diagnostic container.

    This cannot pull/start/build a container. Its caller must first safely
    materialize the archive and bind the program read-only at Harbor setup.
    """

    def __init__(self, container_id: str, task_config: Path, bundle: Path, receipt_sha256: str,
                 reports: Path, runner=subprocess.run):
        a.require(bool(re.fullmatch(r"[0-9a-f]{64}", container_id)), "CONTAINER_ID_INVALID")
        self.container_id, self.task_config, self.reports, self.runner = container_id, task_config, reports, runner
        self.manifest, self.receipt = a.load_bundle(bundle, receipt_sha256)

    def call(self, args: list[str]) -> dict:
        result = self.runner(["docker", *args], capture_output=True, text=True, check=False, timeout=60)
        return {"exit": result.returncode, "stdout": result.stdout, "stderr": result.stderr}

    def read_json(self, args: list[str]) -> dict:
        result = self.call(args)
        a.require(result["exit"] == 0, "DOCKER_INSPECT_FAILED")
        rows = json.loads(result["stdout"])
        a.require(isinstance(rows, list) and len(rows) == 1, "DOCKER_INSPECT_AMBIGUOUS")
        return rows[0]

    def inspect(self) -> dict:
        state = self.read_json(["inspect", self.container_id])
        a.require(state["Id"] == self.container_id and state["State"]["Running"] is True,
                  "HARBOR_CONTAINER_NOT_RUNNING")
        config = state["Config"]
        labels = config.get("Labels") or {}
        a.require(labels.get("com.docker.compose.service") == "main"
                  and bool(labels.get("com.docker.compose.project")), "HARBOR_COMPOSE_IDENTITY_MISSING")
        selected = fixed_image()
        immutable_ref = selected["authoritative_image_ref"].split("@", 1)[0].rsplit(":", 1)[0] + "@" + selected["historical_platform_digest"]
        a.require(config["Image"] == immutable_ref, "MUTABLE_TASK_IMAGE_SUBSTITUTION")
        image = self.read_json(["image", "inspect", state["Image"]])
        a.require(immutable_ref in (image.get("RepoDigests") or []) and image["Id"] == state["Image"],
                  "IMMUTABLE_IMAGE_BINDING_UNPROVEN")
        env_names = [item.split("=", 1)[0] for item in config.get("Env", [])]
        a.require(not any(name in ("NODE_OPTIONS", "LD_LIBRARY_PATH", "NODE_PATH") for name in env_names),
                  "RUNTIME_ENVIRONMENT_DRIFT")
        credential_names = [name for name in env_names if re.search(r"KEY|TOKEN|SECRET|AUTH|PASSWORD|COOKIE", name, re.I)]
        mounts = state.get("Mounts", [])
        program_mounts = [m for m in mounts if m["Destination"] in (PROGRAM, "/installed-agent")]
        a.require(len(program_mounts) == 1 and program_mounts[0]["Type"] == "bind" and
                  program_mounts[0]["RW"] is False and
                  not any(m["Destination"].startswith(PROGRAM + "/") for m in mounts), "READ_ONLY_PROGRAM_MOUNT_UNPROVEN")
        mount = program_mounts[0]
        host_program = Path(mount["Source"]) if mount["Destination"] == PROGRAM else Path(mount["Source"]) / "deepseek-harness"
        a.verify_tree(host_program, self.manifest)
        host = state["HostConfig"]
        a.require(host.get("Privileged") is False and not any(
                      name in ("ALL", "SYS_ADMIN", "CAP_SYS_ADMIN") for name in (host.get("CapAdd") or [])),
                  "IMMUTABLE_DEPLOYMENT_PRIVILEGE_DRIFT")
        return {"task_config_sha256": a.file_hash(self.task_config), "task_id": TASK,
                "harbor_version": importlib.metadata.version("harbor"),
                "platform": image["Os"] + "/" + image["Architecture"],
                "platform_digest": selected["historical_platform_digest"],
                "image_reference": selected["authoritative_image_ref"],
                "resource_envelope": {"memory_bytes": host["Memory"], "nano_cpus": host["NanoCpus"],
                                      "storage_options": host.get("StorageOpt") or {}, "memory_swap": host["MemorySwap"],
                                      "cpu_quota": host["CpuQuota"], "cpu_period": host["CpuPeriod"],
                                      "cpuset_cpus": host["CpusetCpus"], "cpu_shares": host["CpuShares"],
                                      "memory_reservation": host["MemoryReservation"], "pids_limit": host["PidsLimit"]},
                "network_mode": host["NetworkMode"], "credential_environment_names": credential_names,
                "program_read_only": True, "program_mount": PROGRAM,
                "program_archive_sha256": self.receipt["archive_sha256"],
                "mounted_archive_sha256": self.receipt["archive_sha256"]}

    def verify_program(self, manifest: dict) -> bool:
        # Copy out the actual container-visible tree, rather than trusting only
        # a host source path or container label. No execution/network is needed.
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "program"
            result = self.call(["cp", self.container_id + ":" + PROGRAM, str(target)])
            a.require(result["exit"] == 0, "REMOTE_PROGRAM_CAPTURE_FAILED")
            a.verify_tree(target, manifest)
        return True

    def prepare_scratch(self, probe: Path, scratch: str) -> None:
        a.require(probe == PROBE and scratch == SCRATCH, "PROBE_INPUT_DRIFT")
        result = self.call(["exec", self.container_id, "/bin/mkdir", scratch])
        a.require(result["exit"] == 0, "SCRATCH_ALREADY_EXISTS_OR_UNAVAILABLE")
        result = self.call(["exec", self.container_id, "/bin/mkdir", scratch + "/scratch"])
        a.require(result["exit"] == 0, "SCRATCH_SETUP_FAILED")
        result = self.call(["cp", str(probe), self.container_id + ":" + scratch + "/probe.mjs"])
        a.require(result["exit"] == 0, "FIXED_PROBE_TRANSFER_FAILED")

    def exec_argv(self, argv: list[str], cwd: str, environment: dict) -> dict:
        a.require(argv in probe_commands() and cwd == SCRATCH + "/scratch" and environment == {}, "PROBE_COMMAND_DRIFT")
        return self.call(["exec", "-w", cwd, self.container_id, "/usr/bin/env", "-i", *argv])

    def preserve_evidence(self, results: list[dict], *, failure: str | None, program_unchanged: bool) -> None:
        a.require(not self.reports.exists(), "EVIDENCE_DESTINATION_EXISTS")
        summary = {"schema_version": "m1c_runtime_probe_evidence_v1", "task_id": TASK,
                   "stage": "NO_MODEL_RUNTIME_PROBE", "child_exits": [r["exit"] for r in results],
                   "failure_type": failure, "program_unchanged": program_unchanged,
                   "provider_status": "NOT_REACHED", "bulk_status": "NOT_AVAILABLE"}
        with tempfile.TemporaryDirectory() as tmp:
            raw = Path(tmp) / "bulk"; raw.mkdir()
            for index, result in enumerate(results):
                for channel in ("stdout", "stderr"):
                    (raw / f"{index}.{channel}").write_text(result[channel])
            safe = Path(tmp) / "safe-core"; safe.mkdir()
            summary["bulk_status"] = "BLOCKED" if a.scan_tree(raw, artifact_mode=True) else "SCANNED_PASS"
            (safe / "summary.json").write_bytes(a.canonical(summary))
            a.require(not a.scan_tree(safe, artifact_mode=True), "SAFE_CORE_SCAN_REJECTED")
            self.reports.mkdir(parents=True)
            import shutil
            shutil.copytree(safe, self.reports / "safe-core")
            if summary["bulk_status"] == "SCANNED_PASS":
                shutil.copytree(raw, self.reports / "bulk")
            for lane in self.reports.iterdir():
                entries = sorted(p for p in lane.iterdir() if p.is_file())
                (lane / "SHA256SUMS").write_text("".join(a.file_hash(p) + "  " + p.name + "\n" for p in entries))
            a.require(summary["bulk_status"] != "BLOCKED", "BULK_SECRET_SCAN_REJECTED")


def qualify(transport, bundle: Path, receipt_sha256: str, root: Path = ROOT, *, baseline: dict | None = None) -> dict:
    """Transport is a no-model setup integration seam, never a generic shell API.

    It must inspect the actual container/mount, verify the remote tree before and
    after, copy this fixed probe outside the program tree, and exec argv in an
    empty credential environment from scratch. No production Adapter is called.
    """
    manifest, receipt = a.load_bundle(bundle, receipt_sha256)
    selected = fixed_image(root)
    # Deliberately not supplied by a workflow-dispatch input or caller override.
    if baseline is not None:
        from scripts import m1c_runtime_resources as resources
        resources.resource_gate(baseline)
        envelope = baseline["resource_envelope"]
    else:
        envelope = RESOURCE_ENVELOPE
    a.require(isinstance(envelope, dict) and bool(a.HEX.fullmatch(TASK_CONFIG_SHA256)),
              "ORIGINAL_HARBOR_SETUP_BINDING_UNRESOLVED")
    actual = transport.inspect()
    validate_container(actual, selected, envelope, TASK_CONFIG_SHA256)
    a.require(actual["program_archive_sha256"] == receipt["archive_sha256"], "MOUNT_IDENTITY_DRIFT")
    a.require(transport.verify_program(manifest) is True, "REMOTE_PROGRAM_VERIFY_FAILED")
    results = []
    failure = None
    try:
        transport.prepare_scratch(PROBE, SCRATCH)
        for argv in probe_commands():
            result = transport.exec_argv(argv, cwd=SCRATCH + "/scratch", environment={})
            results.append(result)
            a.require(result["exit"] == 0, "NO_MODEL_RUNTIME_PROBE_FAILED")
        evidence = json.loads(results[-1]["stdout"])
        for field in ("profile_resolution", "plugin_resolution", "native_load", "pty", "filesystem", "sandbox", "isolation"):
            a.require(evidence.get(field) == "PASS", "RUNTIME_EVIDENCE_INCOMPLETE")
        a.require(evidence.get("resolved_plugin_count", 0) > 0 and evidence.get("provider_path_reached") is False
                  and evidence.get("provider_requests") == 0 and evidence.get("model_sessions") == 0,
                  "NO_MODEL_EVIDENCE_INVALID")
    except Exception as error:
        failure = type(error).__name__
        raise
    finally:
        # Mutation verification runs on failures too. Raw exception text is not
        # serialized; diagnostic lanes must be scanned before external upload.
        try:
            unchanged = transport.verify_program(manifest)
        except Exception:
            unchanged = False
            failure = failure or "PROGRAM_POSTVERIFY_FAILED"
        transport.preserve_evidence(results, failure=failure, program_unchanged=unchanged)
        a.require(unchanged is True, "PROGRAM_TREE_MUTATION")
    after = transport.inspect()
    validate_container(after, selected, envelope, TASK_CONFIG_SHA256)
    a.require(after == actual, "CONTAINER_OR_MOUNT_DRIFT")
    return {"schema_version": "m1c_no_model_artifact_qualification_v1", "task_id": TASK,
            "status": "NO_MODEL_RUNTIME_CHECKS_PASS", "provider_requests": 0,
            "deepseek_requests": 0, "compatibility_classes": "NOT_QUALIFIED",
            "model_sessions": 0, "adapter_frozen": False}
