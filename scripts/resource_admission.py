"""Predeclared second-build budgets derived from retained first-build evidence.

These records are engineering admission evidence, not signed provenance. The
operator supplies the approved policy outside the captured source before build one.
"""
import json
import hashlib

GIB = 1024 ** 3
FILESYSTEMS = ("docker", "temporary")


def load_policy(path, source, source_digest, docker_driver):
    if path is None or not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("external absolute regular second-build policy required")
    if path.resolve().is_relative_to(source.resolve()):
        raise ValueError("second-build approval policy must be outside captured source")
    raw = path.read_bytes()
    value = json.loads(raw)
    expected = {"schema_version": 1, "kind": "measured-second-build-v1",
                "source_input_sha256": source_digest, "docker_driver": docker_driver,
                "minimum_estimated_peak_additional_bytes": 8 * GIB,
                "safety_margin_bytes": 2 * GIB, "reserve_bytes": 2 * GIB}
    if not isinstance(value, dict) or set(value) != set(expected) | {"approval"}:
        raise ValueError("unsupported second-build admission policy")
    for name, required in expected.items():
        if type(value[name]) is not type(required) or value[name] != required:
            raise ValueError("second-build policy source, driver or reviewed formula differs")
    approval = value["approval"]
    if (not isinstance(approval, dict) or set(approval) != {"authority", "decision", "record"}
            or approval["authority"] != "root" or approval["decision"] != "approved"
            or not isinstance(approval["record"], str) or not 1 <= len(approval["record"].strip()) <= 512):
        raise ValueError("explicit root approval record required before first build")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "record": value}


def free_values(value):
    keys = {filesystem + "_free" for filesystem in FILESYSTEMS}
    if not isinstance(value, dict) or set(value) != keys or any(type(number) is not int or number < 0 for number in value.values()):
        raise ValueError("complete nonnegative filesystem measurements required")
    return value


def summarize_measurements(initial, commands, final):
    initial, final = free_values(initial), free_values(final)
    if not commands:
        raise ValueError("completed measured command history required")
    minima = {key: min(initial[key], final[key]) for key in initial}
    for command in commands:
        if command.get("exit_code") != 0 or command.get("timed_out") or command.get("interrupted") or command.get("resource_sampling_failed"):
            raise ValueError("failed or incomplete first-build command metrics")
        values = free_values(command.get("observed_minimum_free"))
        start = free_values(command.get("observed_initial_free"))
        end = free_values(command.get("observed_final_free"))
        if any(values[key] > min(start[key], end[key]) for key in values):
            raise ValueError("first-build command minima contradict start/end observations")
        for key in minima:
            minima[key] = min(minima[key], values[key])
    return {"schema_version": 1, "complete": True, "sampling_interval_seconds": 1,
            "sampling_scope": "initial, every command start/end and one-second command samples, final retained state",
            "initial_free": initial, "final_retained_free": final, "observed_minimum_free": minima,
            "measured_peak_additional": {filesystem: initial[filesystem + "_free"] - minima[filesystem + "_free"] for filesystem in FILESYSTEMS}}


def second_admission(candidate, first, first_digest, policy, current_docker):
    binding = candidate.get("builds", {}).get("one", {})
    if binding != {"path": "builds/one/manifest.json", "sha256": first_digest}:
        raise ValueError("completed first-build manifest is not candidate-bound")
    if (first.get("source") != candidate["source"] or first.get("run_id") != candidate["run_id"]
            or first.get("build_id") != "one" or first.get("status") != "built"
            or first.get("build_mode") != "canonical-container"
            or first.get("packaging_reconciliation_required")
            or first.get("compilation_scratch_discarded") is not True):
        raise ValueError("completed coherent canonical first build required")
    budget = first.get("resource_budget", {})
    if budget.get("second_admission_policy") != policy:
        raise ValueError("second-build policy differs from predeclared first-build approval")
    if budget.get("docker", {}).get("driver") != current_docker["driver"] or budget.get("docker", {}).get("data_root") != current_docker["data_root"]:
        raise ValueError("first-build Docker driver or filesystem identity differs")
    measurement = budget.get("measurements", {})
    actual = summarize_measurements(measurement.get("initial_free"), first.get("commands"), measurement.get("final_retained_free"))
    if measurement != actual or min(actual["observed_minimum_free"].values()) < 2 * GIB:
        raise ValueError("first-build measurements incomplete, inconsistent or reserve breached")
    estimates = {filesystem: max(8 * GIB, actual["measured_peak_additional"][filesystem] + 2 * GIB) for filesystem in FILESYSTEMS}
    return {"schema_version": 1, "policy": policy, "first_build_manifest_sha256": first_digest,
            "source_input_sha256": candidate["source"]["inputs"]["sha256"],
            "first_build_measurements": actual, "reserve_bytes": 2 * GIB,
            "estimated_peak_additional": estimates,
            "minimum_free": {filesystem: estimate + 2 * GIB for filesystem, estimate in estimates.items()}}


def phase_settings(plan):
    roles = {'control', 'guard', 'fixtures', 'workspace', 'postgres'}
    budgets = plan.get('packaging_image_estimated_peak_additional', {})
    evictions = plan.get('compiler_cache_evictions', [])
    if not isinstance(budgets, dict) or set(budgets) - roles or any(type(value) is not int or value < 4 * GIB for value in budgets.values()):
        raise ValueError('reviewed per-image forecasts must be at least 4 GiB')
    if not isinstance(evictions, list) or any(not isinstance(value, dict) or set(value) != {'after', 'requested', 'image_id'} for value in evictions):
        raise ValueError('exact compiler eviction whitelist required')
    return {'packaging_image_estimated_peak_additional': dict(budgets),
            'compiler_cache_evictions': [dict(value) for value in evictions]}


def phase_record_digest(record):
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def inherit_phase_settings(candidate, first, first_digest, docker):
    if (candidate.get('builds', {}).get('one') != {'path': 'builds/one/manifest.json', 'sha256': first_digest}
            or first.get('source') != candidate['source'] or first.get('run_id') != candidate['run_id']
            or first.get('build_id') != 'one' or first.get('status') != 'built'):
        raise ValueError('completed source-bound first build required for phase inheritance')
    budget = first.get('resource_budget', {})
    if budget.get('docker', {}).get('driver') != docker['driver'] or budget.get('docker', {}).get('data_root') != docker['data_root']:
        raise ValueError('phase inheritance Docker identity differs')
    original = budget.get('reviewed_plan')
    if original is None:
        if budget.get('phase_settings') != phase_settings({}) or budget.get('inherited_phase_settings'):
            raise ValueError('missing first plan cannot supply inherited phase settings')
        return None
    plan = original.get('record', {})
    raw_digest = original.get('sha256')
    if (not isinstance(raw_digest, str) or len(raw_digest) != 64 or any(value not in '0123456789abcdef' for value in raw_digest)
            or original.get('record_sha256') != phase_record_digest(plan)
            or plan.get('schema_version') != 1 or plan.get('strategy') != 'pinned-containers-bind-outputs'
            or plan.get('lead_review') != 'approved' or plan.get('source_input_sha256') != candidate['source']['inputs']['sha256']
            or plan.get('docker_driver') != docker['driver']):
        raise ValueError('first reviewed phase policy binding missing or substituted')
    settings = phase_settings(plan)
    if budget.get('phase_settings') != settings:
        raise ValueError('first phase settings differ from reviewed policy')
    return {'schema_version': 1, 'first_build_manifest_sha256': first_digest,
            'source_input_sha256': candidate['source']['inputs']['sha256'], 'docker_driver': docker['driver'],
            'original_plan_sha256': raw_digest, 'original_plan_record_sha256': original['record_sha256'],
            'settings': settings, 'whole_build_floors_inherited': False}
