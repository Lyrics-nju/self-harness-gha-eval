"""Fixed, single-shot Artifact V1 orchestrator. Importing this runs nothing.

Only the dedicated future manually authorized GHA workflow invokes real mode.
Local tests inject a fixture backend; its result can never qualify real runtime.
"""
from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import zipfile

from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_builder as b
from scripts import m1c_runtime_identity as i
from scripts import m1c_runtime_qualification as q
from scripts import m1c_runtime_resources as r

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = "M1C.1 Artifact V1 No-Model Qualification"
STAGES = ("BUILDER_SETUP_FAILURE", "BUILDER_IDENTITY_FAILURE", "BUILDER_CAPACITY_BLOCKER",
          "DSH_BUILD_FAILURE", "ARTIFACT_INTEGRITY_FAILURE", "TASK_RESOURCE_BINDING_FAILURE",
          "DSH_NATIVE_RUNTIME_QUALIFICATION_FAILURE")


def checkout_gate(actual: str, expected: str, tracked_dirty: bool, untracked: list[str]) -> None:
    # Exactly the two workflow-created preflight files, never arbitrary changes.
    allowed = {"reports/artifact-harbor.json", "work/census.zip"}
    a.require(bool(re.fullmatch(r"[0-9a-f]{40}", expected)) and actual == expected and
              not tracked_dirty and set(untracked) <= allowed, "CHECKOUT_IDENTITY_DRIFT")


def orchestrate(backend) -> dict:
    """Every handoff is verified before the next action. No retry path."""
    summary = {"schema": "m1c_runtime_orchestration_v1", "task_id": q.TASK,
               "status": "EVIDENCE_INDETERMINATE", "completed_stages": [],
               "provider_requests": 0, "deepseek_requests": 0, "live_sessions": 0,
               "universal_compatibility": False, "adapter_frozen": False}
    stage = STAGES[0]
    try:
        backend.prepare()
        backend.create_builder()
        summary["completed_stages"].append("BUILDER_IMAGE_CREATED")
        stage = STAGES[1]
        image = backend.builder_identity()
        i.verify_image(image, i.policy())
        summary["completed_stages"].append("BUILDER_IMAGE_IDENTITY_VERIFIED")
        stage = STAGES[2]
        resources = backend.builder_capacity(image)
        i.capacity_gate(resources, i.policy(), image)
        backend.build_gate(image, resources)
        summary["completed_stages"].append("BUILDER_CAPACITY_PREFLIGHT_PASS")
        stage = STAGES[3]
        backend.compile_dsh(image, resources)
        summary["completed_stages"].append("DSH_BUILD_COMPLETED")
        stage = STAGES[4]
        backend.pack_and_verify()
        summary["completed_stages"].append("ARTIFACT_IDENTITY_VERIFIED")
        stage = STAGES[5]
        backend.create_task()
        before = backend.task_readback()
        summary["resources"] = r.resource_gate(before)
        summary["completed_stages"].append(summary["resources"]["status"])
        # No materialization method is reachable before task resource_gate.
        backend.materialize(before)
        stage = STAGES[6]
        backend.native_probe(before)
        after = backend.task_readback()
        r.preserved(before, after)
        summary["completed_stages"].append("NO_MODEL_NATIVE_CHECKS_COMPLETED")
        summary["status"] = "NO_MODEL_RUNTIME_QUALIFIED" if type(backend) is RealBackend else "MOCK_EXECUTION_ONLY"
    except Exception as error:
        summary.update(status=stage, error_type=type(error).__name__)
        try:
            backend.capture_failure(error)
        except Exception:
            summary["evidence_capture_status"] = "INDETERMINATE"
            summary["status"] = "EVIDENCE_INDETERMINATE"
        # Only audited symbolic error codes may enter SAFE CORE, never raw text.
        code = str(error)
        summary["error_code"] = code if isinstance(error, a.ArtifactError) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,120}", code) else "SEE_SCANNED_BULK"
    finally:
        try:
            backend.cleanup()
        except Exception as error:
            summary.update(status="EVIDENCE_INDETERMINATE", cleanup_error_type=type(error).__name__)
        backend.save_summary(summary)
    return summary


def export_evidence(work: Path, destination: Path, identity: dict) -> dict:
    """Independent safe/core and bulk scans. Failed bulk is NEVER published."""
    a.require(not destination.exists(), "EVIDENCE_STAGE_EXISTS")
    destination.mkdir()
    summary_path = work / "summary.json"
    summary = json.loads(summary_path.read_bytes()) if summary_path.exists() else {
        "status": "EVIDENCE_INDETERMINATE", "completed_stages": [], "provider_status": "NOT_REACHED"}
    raw = work / "raw"
    bulk_ok = raw.is_dir() and not a.scan_tree(raw, artifact_mode=True)
    # Program archives are published only if they verified AND passed scanning.
    bundle = work / "output/bundle"
    program_ok = False
    if bulk_ok and summary.get("status") == "NO_MODEL_RUNTIME_QUALIFIED":
        try:
            handoff = json.loads((raw / "artifact-handoff.json").read_bytes())
            receipt_sha = handoff["receipt_sha256"]
            a.load_bundle(bundle, receipt_sha)
            a.require(a.file_hash(bundle / "native-evidence.json") == handoff["native_evidence_sha256"],
                      "NATIVE_EVIDENCE_HANDOFF_DRIFT")
            a.require(not a.scan_tree(bundle, artifact_mode=True), "PROGRAM_BUNDLE_SCAN_REJECTED")
            shutil.copytree(bundle, destination / "program")
            program_ok = True
        except Exception:
            summary = dict(summary, status="ARTIFACT_INTEGRITY_FAILURE")
    if not bulk_ok:
        summary = dict(summary, status="EVIDENCE_INDETERMINATE")
    safe = destination / "safe-core"; safe.mkdir()
    core = {"run": identity, "summary": summary, "bulk_status": "SCANNED_PASS" if bulk_ok else "BLOCKED_OR_MISSING",
            "program_published": program_ok}
    (safe / "summary.json").write_bytes(a.canonical(core))
    a.require(not a.scan_tree(safe, artifact_mode=True), "SAFE_CORE_SCAN_REJECTED")
    if bulk_ok:
        shutil.copytree(raw, destination / "bulk")
    for lane in destination.iterdir():
        files = sorted(f for f in lane.rglob("*") if f.is_file())
        (lane / "SHA256SUMS").write_text("".join(a.file_hash(f) + "  " + f.relative_to(lane).as_posix() + "\n" for f in files))
    return {"safe": True, "bulk": bulk_ok, "program": program_ok}


class RealBackend:
    real = True

    def __init__(self, root: Path, work: Path):
        self.root, self.work, self.p = root, work, i.policy()
        a.require(not work.exists(), "RUN_STATE_ALREADY_EXISTS")
        work.mkdir(parents=True)
        self.raw = work / "raw"; self.raw.mkdir()
        self.counter = 0
        self.image_id = self.builder = None
        self.task_environment = self.task_id = None
        self.loop = asyncio.new_event_loop()
        self.child_env = {"PATH": os.environ["PATH"], "HOME": str(work / "home"), "LANG": "C.UTF-8",
                          "PYTHONDONTWRITEBYTECODE": "1"}
        (work / "home").mkdir()
        self.source = work / "source"
        self.bundle = work / "output/bundle"
        self.program_parent = work / "deployment"
        self.program = self.program_parent / "deepseek-harness"

    def record(self, name: str, value: dict) -> None:
        (self.raw / (name + ".json")).write_bytes(a.canonical(value))

    def capture_failure(self, error: Exception) -> None:
        (self.raw / "failure-traceback.txt").write_text(traceback.format_exc())

    def call(self, argv: list[str], timeout: int = 300, check: bool = True, cwd: Path | None = None) -> str:
        index = self.counter; self.counter += 1
        self.record(f"command-{index}", {"argv": argv, "timeout_sec": timeout})
        out, err = self.raw / f"{index}.stdout", self.raw / f"{index}.stderr"
        with out.open("wb") as stdout, err.open("wb") as stderr:
            result = subprocess.run(argv, cwd=cwd, env=self.child_env, stdout=stdout, stderr=stderr,
                                    timeout=timeout, check=False)
        stderr_text = err.read_text(errors="replace")
        self.record(f"exit-{index}", {"exit": result.returncode,
                    "disk_exhaustion_text_observed": "No space left on device" in stderr_text})
        if check: a.require(result.returncode == 0, "COMMAND_NONZERO")
        return out.read_text(errors="replace").strip()

    def inspect(self, target: str, image: bool = False) -> dict:
        rows = json.loads(self.call(["docker", *( ["image"] if image else [] ), "inspect", target]))
        a.require(len(rows) == 1, "INSPECT_AMBIGUOUS")
        return rows[0]

    def builder_exec(self, argv: list[str], timeout: int = 300) -> str:
        a.require(self.builder is not None, "BUILDER_NOT_CREATED")
        return self.call(["docker", "exec", "-w", "/source", self.builder, "/usr/bin/env", "-i",
                          "PATH=/opt/pinned-node/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", *argv], timeout)

    def prepare(self) -> None:
        i.validate_inputs(self.p, self.root); q.fixed_image(self.root)
        backend, policy = r.backend_evidence(), r.backend_policy()
        a.require(backend["version"] == policy["harbor_version"] and backend["sources"] == policy["backend_sources"] and
                  backend["environment_tree_sha256"] == policy["environment_tree_sha256"], "HARBOR_BACKEND_DRIFT")
        archive = self.root / "work/census.zip"
        with zipfile.ZipFile(archive) as z:
            matches = [name for name in z.namelist() if name == "task-image-map.json"]
            a.require(len(matches) == 1, "CENSUS_ARTIFACT_MAP_MISSING")
            a.require(z.getinfo(matches[0]).file_size <= 1024 * 1024, "CENSUS_MAP_SIZE_INVALID")
            (self.work / "task-image-map.json").write_bytes(z.read(matches[0]))
        binding = json.loads((self.root / "configs/m1c_runtime_task_binding_v1.json").read_bytes())
        a.require(a.file_hash(self.work / "task-image-map.json") == binding["census_task_image_map_sha256"],
                  "QUALIFIED_CENSUS_MAP_DRIFT")
        self.docker_root = Path(self.call(["docker", "info", "--format", "{{.DockerRootDir}}"] ))
        a.require(self.docker_root.is_absolute() and self.docker_root.is_dir(), "DOCKER_STORAGE_BACKING_PATH_UNKNOWN")
        self.context = self.work / "context"; self.context.mkdir()
        for name in i.CONTEXT_FILES + ("configs/m1c_runtime_prebuild_v1.json",):
            path = self.context / name; path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.root / name, path)
        inputs = self.context / "inputs"; inputs.mkdir()
        for name, url in (("node.tar.xz", self.p["node_archive_source"]), ("corepack.tgz", self.p["corepack_source"]),
                          ("pnpm.tgz", self.p["pnpm_source"])):
            self.call(["curl", "--fail", "--location", "--proto", "=https", "--max-time", "180", "--output", str(inputs / name), url])
        i.verify_staged_context(self.context, self.p)
        self.call(["git", "clone", "--no-checkout", "https://github.com/deepseek-ai/deepseek-harness.git", str(self.source)])
        self.call(["git", "checkout", "--detach", a.DSH_COMMIT], cwd=self.source)
        commit, _ = b.source_identity(self.source, lambda argv, cwd: self.call(argv, cwd=cwd))
        a.require(commit == a.DSH_COMMIT and a.file_hash(self.source / "pnpm-lock.yaml") == self.p["lockfile_sha256"], "SOURCE_DRIFT")
        for name in ("output", "evidence"):
            (self.work / name).mkdir()

    def create_builder(self) -> None:
        argv = b.builder_plan(self.context / "inputs/node.tar.xz", a.DSH_COMMIT)
        iid = self.work / "builder.iid"
        self.call(argv[:2] + ["--iidfile", str(iid), "--label", "m1c.context=" + self.p["context_sha256"],
                             "--label", "m1c.base=" + self.p["base_image"]] + argv[2:], timeout=900)
        self.image_id = iid.read_text().strip()
        a.require(bool(a.DIGEST.fullmatch(self.image_id)), "FINAL_IMAGE_ID_MISSING")
        image = self.inspect(self.image_id, image=True)
        a.require(image["Id"] == self.image_id and image["Os"] == "linux" and image["Architecture"] == "amd64", "BUILDER_IMAGE_DRIFT")
        self._check_environment(image["Config"].get("Env", []))
        rsrc = self.p["requested_resources"]
        self.builder = self.call(["docker", "create", "--platform=linux/amd64", "--memory", str(rsrc["memory_bytes"]),
            "--memory-swap", str(rsrc["memory_bytes"]), "--cpus", str(rsrc["cpus"]),
            "--mount", f"type=bind,source={self.source},target=/source",
            "--mount", f"type=bind,source={self.work / 'output'},target=/output",
            "--mount", f"type=bind,source={self.work / 'evidence'},target=/evidence,readonly",
            self.image_id, "/bin/sleep", "infinity"])
        a.require(bool(re.fullmatch(r"[0-9a-f]{64}", self.builder)), "BUILDER_CONTAINER_ID_MISSING")
        self.call(["docker", "start", self.builder])

    @staticmethod
    def _check_environment(rows: list[str]) -> None:
        names = [row.split("=", 1)[0] for row in rows]
        a.require(not any(re.search(r"KEY|TOKEN|SECRET|AUTH|PASSWORD|COOKIE|PROXY", n, re.I) or
                          n in {"NODE_OPTIONS", "NODE_PATH", "LD_LIBRARY_PATH"} for n in names), "CREDENTIAL_OR_ENVIRONMENT_DRIFT")

    def builder_identity(self) -> dict:
        image = self.inspect(self.image_id, image=True); container = self.inspect(self.builder)
        n = json.loads(self.builder_exec(["node", "-p", "JSON.stringify({version:process.version,abi:process.versions.modules,napi:process.versions.napi})"]))
        labels = image["Config"]["Labels"]
        record = {"image_id": image["Id"], "container_image_id": container["Image"],
                  "image_config_sha256": image["Id"].split(":")[1], "platform": image["Os"] + "/" + image["Architecture"],
                  "os_release_sha256": self.builder_exec(["sha256sum", "/etc/os-release"]).split()[0],
                  "libc": self.builder_exec(["getconf", "GNU_LIBC_VERSION"]), "node_version": n["version"],
                  "node_abi": n["abi"], "node_napi": n["napi"], "corepack": self.builder_exec(["corepack", "--version"]),
                  "pnpm": self.builder_exec(["pnpm", "--version"]), "base_image": labels["m1c.base"],
                  "input_context_sha256": labels["m1c.context"]}
        self.record("builder-identity", record)
        return record

    def builder_capacity(self, image: dict) -> dict:
        host = self.inspect(self.builder)["HostConfig"]
        cg = self.builder_exec(["/bin/sh", "-c", r.CGROUP_COMMAND])
        limits = r.parse_cgroup(cg)
        a.require(limits["memory_max"] == self.p["builder_memory"] and
                  limits["cpu_quota"] == 2 * limits["cpu_period"], "BUILDER_CGROUP_DRIFT")
        events = dict(line.split() for line in self.builder_exec(["cat", "/sys/fs/cgroup/memory.events"]).splitlines())
        mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        disks = {str(path): shutil.disk_usage(path).free for path in (self.work, self.docker_root)}
        raw = {"host_cpus": len(os.sched_getaffinity(0)), "mem_available_bytes": int(mem["MemAvailable"].split()[0]) * 1024,
               "free_disk_bytes": disks, "host_config": host, "cgroup_limits": limits, "memory_events": events}
        self.record("builder-capacity-raw", raw)
        return {"host_cpus": raw["host_cpus"], "host_mem_available_bytes": raw["mem_available_bytes"],
                "host_free_disk_bytes": min(disks.values()), "container_memory_max": host["Memory"],
                "container_nano_cpus": host["NanoCpus"], "container_memory_swap": host["MemorySwap"],
                "memory_events": {k: int(v) for k,v in events.items()}, "measurement_id": a.digest(a.canonical(raw))}

    def build_gate(self, image: dict, resources: dict) -> None:
        i.dsh_build_gate(self.p, image, resources, self.source / "pnpm-lock.yaml", self.root)
        self.evidence = {"image": image, "resources": resources}
        (self.work / "evidence/builder.json").write_bytes(a.canonical(self.evidence))
        self.record("build-permission", {"status": "DSH_BUILD_PERMITTED", "image_id": image["image_id"]})

    def compile_dsh(self, image: dict, resources: dict) -> None:
        self.build_gate(image, resources)  # Recheck at the actual call boundary.
        stop = threading.Event()
        def sample():
            with (self.raw / "builder-memory-timeseries.jsonl").open("w") as out:
                while not stop.is_set():
                    row = {"timestamp": time.time(), "disk_free_bytes": shutil.disk_usage(self.work).free}
                    try:
                        child = subprocess.run(["docker", "exec", self.builder, "/usr/bin/env", "-i", "/bin/sh", "-c",
                            "cat /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events"],
                            capture_output=True, text=True, env=self.child_env, timeout=3, check=False)
                        row.update(exit=child.returncode, cgroup=child.stdout)
                    except Exception as error: row["error_type"] = type(error).__name__
                    out.write(json.dumps(row) + "\n"); out.flush(); stop.wait(1)
        sampler = threading.Thread(target=sample); sampler.start()
        try:
            self.builder_exec(["/bin/sh", "-c", "test \"${NODE_OPTIONS+x}\" != x && corepack enable && pnpm install --frozen-lockfile"], 900)
            self.build_gate(image, self.builder_capacity(image))
            self.builder_exec(["pnpm", "run", "build"], 1800)
        finally:
            stop.set(); sampler.join()
            self.record("builder-resource-after", {"cgroup": self.builder_exec(["cat", "/sys/fs/cgroup/memory.events"]),
                        "disk_free": shutil.disk_usage(self.work).free})
        receipt = {"image_id": image["image_id"], "command": "pnpm run build", "exit": 0,
                   "lockfile_sha256": self.p["lockfile_sha256"]}
        (self.work / "evidence/build.json").write_bytes(a.canonical(receipt))

    def pack_and_verify(self) -> None:
        self.call(["docker", "exec", "-w", "/tooling", self.builder, "/usr/bin/env", "-i",
            "PATH=/opt/pinned-node/bin:/usr/local/bin:/usr/bin:/bin", "HOME=/tmp", "python3", "-m", "scripts.m1c_runtime_builder",
            "/source", "/opt/pinned-node", "/output/bundle", "/evidence/builder.json", "/evidence/build.json"], timeout=900)
        self.receipt_sha = a.file_hash(self.bundle / "receipt.json")
        self.manifest, self.receipt = a.load_bundle(self.bundle, self.receipt_sha)
        native = json.loads((self.bundle / "native-evidence.json").read_bytes())
        a.require(set(native) == {row["path"] for row in self.manifest["native_inventory"]}, "NATIVE_INVENTORY_EVIDENCE_MISSING")
        for row in self.manifest["native_inventory"]:
            record = native[row["path"]]
            a.require(record["sha256"] == row["sha256"] and record["readelf_exit"] == 0 and
                      record["machine"] and isinstance(record["needed_libraries"], list), "NATIVE_DEPENDENCY_EVIDENCE_MISSING")
        a.require(not a.scan_tree(self.bundle, artifact_mode=True), "ARTIFACT_SECRET_SCAN_REJECTED")
        self.record("artifact-handoff", {"receipt_sha256": self.receipt_sha, "receipt": self.receipt,
            "native_evidence_sha256": a.file_hash(self.bundle / "native-evidence.json"),
            "native_inventory_evidence": native, "compatibility": "NOT_YET_QUALIFIED"})

    async def _create_task(self) -> None:
        from harbor.registry.client.package import PackageDatasetClient
        from harbor.tasks.client import TaskClient
        from harbor.models.task.config import TaskConfig, NetworkPolicy, NetworkMode
        from harbor.environments.docker.docker import DockerEnvironment
        from harbor.models.trial.paths import TrialPaths
        # No Task/Trial/Agent/Verifier objects or task instruction parsing.
        meta = await PackageDatasetClient().get_dataset_metadata("terminal-bench/terminal-bench-2-1@sha256:" + q.rf.DATASET_SHA256)
        a.require(meta.dataset_version_content_hash == q.rf.DATASET_SHA256 and len(meta.task_ids) == 89, "DATASET_IDENTITY_DRIFT")
        ids = [task for task in meta.task_ids if task.get_name() == q.TASK]
        a.require(len(ids) == 1, "FIXED_TASK_NOT_FOUND")
        result = await TaskClient().download_tasks(ids, output_dir=self.work / "task-source", export=True)
        a.require(len(result.paths) == 1, "TASK_DOWNLOAD_AMBIGUOUS")
        self.task_source = result.paths[0]
        self.task_config = self.task_source / "task.toml"
        binding = i.validate_task_binding(self.task_config, self.work / "task-image-map.json", self.root)
        cfg = TaskConfig.model_validate_toml(self.task_config.read_text()).environment
        a.require(not cfg.env and not list((self.task_source / "environment").glob("*compose*")), "TASK_SETUP_CONFIGURATION_CONFLICT")
        self.selected = q.fixed_image(self.root)
        immutable = self.selected["authoritative_image_ref"].rsplit(":", 1)[0] + "@" + self.selected["historical_platform_digest"]
        self.call(["docker", "pull", "--platform=linux/amd64", immutable], timeout=600)
        self.task_image = self.inspect(immutable, image=True)
        self._check_environment(self.task_image["Config"].get("Env", []))
        a.require(not self.task_image["Config"].get("Entrypoint") and not self.task_image["Config"].get("Healthcheck"),
                  "TASK_IMAGE_AUTOMATIC_COMMAND_UNSAFE")
        a.require(immutable in self.task_image.get("RepoDigests", []) and self.task_image["Os"] == "linux"
                  and self.task_image["Architecture"] == "amd64", "IMMUTABLE_TASK_IMAGE_DRIFT")
        # In-memory immutable reference resolution only; task.toml unchanged.
        cfg = cfg.model_copy(update={"docker_image": immutable})
        self.program_parent.mkdir()
        (self.work / "scratch-artifacts").mkdir()
        self.task_environment = DockerEnvironment(environment_dir=self.task_source / "environment",
            environment_name="m1c-artifact-task", session_id="m1c-artifact-" + os.environ["GITHUB_RUN_ID"],
            trial_paths=TrialPaths(self.work / "harbor-setup"), task_env_config=cfg,
            network_policy=NetworkPolicy(network_mode=NetworkMode.NONE),
            mounts=[{"type": "bind", "source": str(self.program_parent), "target": "/installed-agent", "read_only": True},
                    {"type": "bind", "source": str(self.work / "scratch-artifacts"), "target": "/logs/artifacts"}])
        a.require(self.task_environment._cpu_resource_mode.value == "auto" and
                  self.task_environment._memory_resource_mode.value == "auto", "HARBOR_RESOURCE_MODE_DRIFT")
        backend = r.backend_evidence(); policy = r.backend_policy()
        a.require(backend["version"] == "0.21.0" and backend["sources"] == policy["backend_sources"] and
                  backend["environment_tree_sha256"] == policy["environment_tree_sha256"], "HARBOR_BACKEND_DRIFT")
        await self.task_environment.start(force_build=False)
        # Resolve the one container created by the exact Harbor project, not a
        # name glob or a substitute plain-Docker task environment.
        project = self.task_environment.session_id
        self.task_id = self.call(["docker", "ps", "-q", "--no-trunc", "--filter", "label=com.docker.compose.project=" + project,
                                  "--filter", "label=com.docker.compose.service=main"])
        a.require(bool(re.fullmatch(r"[0-9a-f]{64}", self.task_id)), "HARBOR_TASK_CONTAINER_AMBIGUOUS")
        self.binding = binding

    def create_task(self) -> None:
        self.loop.run_until_complete(self._create_task())

    def task_readback(self) -> dict:
        container = self.inspect(self.task_id); image = self.inspect(container["Image"], image=True)
        self._check_environment(container["Config"].get("Env", []))
        a.require(container["State"]["Running"] is True and container["HostConfig"]["Privileged"] is False
                  and not container["HostConfig"].get("CapAdd"), "TASK_ENVIRONMENT_PRIVILEGE_DRIFT")
        immutable = self.selected["authoritative_image_ref"].rsplit(":", 1)[0] + "@" + self.selected["historical_platform_digest"]
        a.require(container["Config"]["Image"] == immutable and immutable in image.get("RepoDigests", []), "TASK_IMAGE_DIGEST_DRIFT")
        host = container["HostConfig"]
        fields = {"memory_bytes": "Memory", "nano_cpus": "NanoCpus", "memory_swap": "MemorySwap", "cpu_quota": "CpuQuota",
                  "cpu_period": "CpuPeriod", "cpuset_cpus": "CpusetCpus", "cpu_shares": "CpuShares",
                  "memory_reservation": "MemoryReservation", "pids_limit": "PidsLimit"}
        envelope = {key: host[name] for key,name in fields.items()}; envelope["storage_options"] = host.get("StorageOpt") or {}
        limits = self.call(["docker", "exec", self.task_id, "/usr/bin/env", "-i", "/bin/sh", "-c", r.CGROUP_COMMAND])
        mounts = sorted([{"target": m["Destination"], "type": m["Type"], "rw": m["RW"], "source": m["Source"]}
                         for m in container["Mounts"]], key=lambda m: m["target"])
        expected = [{"target": "/installed-agent", "type": "bind", "rw": False, "source": str(self.program_parent)}]
        expected.append({"target": "/logs/artifacts", "type": "bind", "rw": True, "source": str(self.work / "scratch-artifacts")})
        expected.sort(key=lambda m: m["target"])
        # No unexplained image-declared volumes/quota mounts are accepted.
        a.require(not self.task_image["Config"].get("Volumes"), "TASK_IMAGE_STORAGE_MOUNTS_UNBOUND")
        observation = {"task_config_sha256": a.file_hash(self.task_config), "image_mapping": self.selected,
            "backend": r.backend_evidence(), "configured": {k: getattr(self.task_environment.task_env_config, k)
                for k in ("cpus", "memory_mb", "storage_mb")},
            "resource_envelope": envelope, "cgroup": r.parse_cgroup(limits),
            "resource_overrides": [k for k in ("_override_cpus", "_override_memory_mb", "_override_storage_mb")
                if getattr(self.task_environment, k) is not None],
            "network_mode": host["NetworkMode"], "storage_capability": "NOT_ENFORCED_BY_CURRENT_BACKEND",
            "storage_quota_verified": False, "mounts": mounts, "expected_mounts": expected,
            "image_id": image["Id"], "container_image_id": container["Image"]}
        self.record("task-readback-" + str(self.counter), observation)
        self.call(["docker", "exec", self.task_id, "/usr/bin/env", "-i", "/bin/df", "-B1", "/"])
        self.record("task-disk-diagnostic-" + str(self.counter), {"status": "DIAGNOSTIC_ONLY_NOT_QUOTA_PROOF",
                    "host_free_bytes": shutil.disk_usage(self.work).free,
                    "artifact_bytes": (self.bundle / "program.tar").stat().st_size,
                    "staging_bytes": sum(p.stat().st_size for p in self.program_parent.rglob("*")
                                         if p.is_file() and not p.is_symlink())})
        return observation

    def materialize(self, before: dict) -> None:
        r.resource_gate(before)
        a.materialize(self.bundle / "program.tar", self.manifest, self.receipt, self.program)
        a.verify_tree(self.program, self.manifest)

    def native_probe(self, before: dict) -> None:
        self.transport = q.DockerTransport(self.task_id, self.task_config, self.bundle, self.receipt_sha,
                                          self.work / "probe-evidence")
        try:
            result = q.qualify(self.transport, self.bundle, self.receipt_sha, baseline=before)
        finally:
            evidence = self.work / "probe-evidence"
            if evidence.is_dir():
                shutil.copytree(evidence, self.raw / "native-probe-evidence")
        self.record("no-model-probe", result)
        a.require(result["status"] == "NO_MODEL_RUNTIME_CHECKS_PASS", "NATIVE_PROBE_INCOMPLETE")

    def cleanup(self) -> None:
        failures = []
        actions = []
        if self.task_environment is not None:
            actions.append(lambda: self.loop.run_until_complete(self.task_environment.stop(delete=True)))
        if self.builder is not None:
            actions.append(lambda: self.call(["docker", "rm", "--force", self.builder]))
        if self.image_id is not None:
            actions.append(lambda: self.call(["docker", "image", "rm", self.image_id]))
        for action in actions:
            try: action()
            except Exception as error: failures.append(type(error).__name__)
        self.loop.close()
        self.record("cleanup", {"failures": failures})
        a.require(not failures, "OWNED_CONTAINER_CLEANUP_INCOMPLETE")

    def save_summary(self, summary: dict) -> None:
        (self.work / "summary.json").write_bytes(a.canonical(summary))
        self.record("summary", summary)


def main() -> int:
    a.require(sys.argv[1:] in (["run"], ["publish"]), "FIXED_ENTRYPOINT_ARGUMENTS")
    a.require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("GITHUB_WORKFLOW") == WORKFLOW
              and os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "EXTERNAL_WORKFLOW_BOUNDARY_REQUIRED")
    a.require(re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", "")) is not None, "RUN_ID_INVALID")
    work = ROOT / "work/artifact-v1"
    run_identity = {k: os.environ.get(k, "NOT_AVAILABLE") for k in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")}
    if sys.argv[1] == "publish":
        result = export_evidence(work, ROOT / "artifact-v1-evidence", run_identity)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as f:
            for key,value in result.items(): f.write(key + "=" + str(value).lower() + "\n")
        return 0
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    tracked = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT)
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=ROOT, text=True).splitlines()
    checkout_gate(actual, os.environ["GITHUB_SHA"], bool(tracked), untracked)
    # Clear inherited credentials/proxies before registry, builder or task work.
    backend = RealBackend(ROOT, work)
    os.environ.clear(); os.environ.update(backend.child_env)
    os.environ["GITHUB_RUN_ID"] = run_identity["GITHUB_RUN_ID"]
    result = orchestrate(backend)
    return 0 if result["status"] == "NO_MODEL_RUNTIME_QUALIFIED" else 1


if __name__ == "__main__": raise SystemExit(main())
