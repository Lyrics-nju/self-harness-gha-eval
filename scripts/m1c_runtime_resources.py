"""Backend-aware read-back validation; config values are not enforcement proof."""
from __future__ import annotations
import json
from pathlib import Path
from scripts import m1c_runtime_artifact as a
from scripts import m1c_runtime_identity as identity
from scripts import m1c_runtime_qualification as q

ROOT = Path(__file__).resolve().parents[1]


def backend_policy() -> dict:
    return json.loads((ROOT / "configs/m1c_runtime_backend_v1.json").read_bytes())


def backend_evidence() -> dict:
    import importlib.metadata
    import harbor
    import inspect
    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.environments.docker import write_resources_compose_file
    root = Path(harbor.__file__).parent
    files = sorted(p for p in (root / "environments").rglob("*") if p.is_file() and p.suffix in (".py", ".yaml"))
    tree = {p.relative_to(root).as_posix(): a.file_hash(p) for p in files}
    return {"version": importlib.metadata.version("harbor"),
            "sources": {name: a.file_hash(root / name) for name in backend_policy()["backend_sources"]},
            "environment_tree_sha256": a.digest(a.canonical(tree)),
            "capabilities": DockerEnvironment.resource_capabilities().model_dump(),
            "storage_quota_parameter": any("storage" in name for name in inspect.signature(write_resources_compose_file).parameters)}


def resource_gate(observation: dict) -> dict:
    binding = json.loads((ROOT / "configs/m1c_runtime_task_binding_v1.json").read_bytes())
    p = backend_policy()
    selected = q.fixed_image()
    a.require(observation["task_config_sha256"] == binding["task_config_sha256"], "TASK_CONFIG_DRIFT")
    a.require(observation["image_mapping"] == selected, "TASK_IMAGE_DIGEST_DRIFT")
    backend = observation["backend"]
    a.require(backend["version"] == p["harbor_version"] and backend["sources"] == p["backend_sources"] and
              backend["environment_tree_sha256"] == p["environment_tree_sha256"],
              "HARBOR_BACKEND_DRIFT")
    a.require(backend["capabilities"] == {"cpu_limit": True, "cpu_request": False,
              "memory_limit": True, "memory_request": False} and
              backend["storage_quota_parameter"] is False, "STORAGE_CAPABILITY_UNKNOWN_OR_DRIFT")
    a.require(observation["configured"] == binding["task_requested_resources"] and
              observation["configured"]["storage_mb"] == 10240, "TASK_RESOURCE_CONFIG_DRIFT")
    a.require(observation["resource_overrides"] == [] and observation["network_mode"] == "none",
              "TASK_SETUP_OVERRIDE_OR_NETWORK_DRIFT")
    host = observation["resource_envelope"]
    a.require(set(host) == q.ENVELOPE_FIELDS and host["nano_cpus"] == 10**9 and
              host["memory_bytes"] == 2048 * 1024**2 and host["cpu_quota"] == host["cpu_period"] == 0 and
              host["cpuset_cpus"] == "" and host["cpu_shares"] == host["memory_reservation"] == 0,
              "DOCKER_CPU_MEMORY_DRIFT")
    # Swap/pids are observed defaults, not inferred from task.toml. Preserve the
    # same values on subsequent read-back; no setter/override exists here.
    a.require(type(host["memory_swap"]) is int and host["memory_swap"] >= 0 and
              (host["pids_limit"] is None or type(host["pids_limit"]) is int), "RESOURCE_DEFAULTS_UNKNOWN")
    cg = observation["cgroup"]
    a.require(cg["version"] == 2 and cg["memory_max"] == 2048 * 1024**2 and
              type(cg["cpu_quota"]) is int and type(cg["cpu_period"]) is int and
              cg["cpu_quota"] > 0 and cg["cpu_quota"] == cg["cpu_period"], "EFFECTIVE_CPU_MEMORY_UNPROVEN")
    a.require(host["storage_options"] == {} and observation["storage_capability"] == "NOT_ENFORCED_BY_CURRENT_BACKEND"
              and observation["storage_quota_verified"] is False, "STORAGE_POLICY_UNKNOWN_OR_CONFLICT")
    a.require(observation["mounts"] == observation["expected_mounts"], "UNEXPLAINED_MOUNT_OR_QUOTA_CHANGE")
    a.require(observation["image_id"] == observation["container_image_id"] and
              bool(a.DIGEST.fullmatch(observation["image_id"])), "CONTAINER_IMAGE_BINDING_DRIFT")
    return {"status": "TASK_RESOURCE_BASELINE_PRESERVED_WITH_STORAGE_GAP",
            "cpu": {"configured": 1, "docker_nano_cpus": host["nano_cpus"], "effective": "CGROUP_VERIFIED"},
            "memory": {"configured_mb": 2048, "docker_bytes": host["memory_bytes"], "effective_bytes": cg["memory_max"]},
            "storage": {"configured_mb": 10240, "backend_enforcement_capability": False,
                        "observed": {"storage_options": host["storage_options"], "mounts": observation["mounts"]},
                        "enforcement_status": "NOT_ENFORCED_BY_CURRENT_BACKEND", "hard_quota_verified": False},
            "all_resource_limits_enforced": False}


def preserved(before: dict, after: dict) -> None:
    resource_gate(before); resource_gate(after)
    # Usage/free disk may change; identity, limits, quota/mount semantics may not.
    keys = ("task_config_sha256", "image_mapping", "backend", "configured", "resource_envelope", "cgroup",
            "resource_overrides", "network_mode", "storage_capability", "storage_quota_verified",
            "mounts", "expected_mounts", "image_id", "container_image_id")
    a.require(all(before[k] == after[k] for k in keys), "TASK_RESOURCE_BASELINE_DRIFT")


def parse_cgroup(text: str) -> dict:
    rows = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    quota, period = rows["cpu.max"].split()
    return {"version": 2, "memory_max": int(rows["memory.max"]), "cpu_quota": int(quota), "cpu_period": int(period)}


CGROUP_COMMAND = "printf 'memory.max='; cat /sys/fs/cgroup/memory.max; printf 'cpu.max='; cat /sys/fs/cgroup/cpu.max"
