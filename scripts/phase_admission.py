"""Fixed post-build disk admission; no cleanup, policy override or runtime launch."""
import datetime
from pathlib import Path
import shutil

from source_record import atomic_json

GIB = 1024 ** 3
RESERVE = 2 * GIB
QUALIFICATION_FORECAST = 6 * GIB


def admit(candidate, phase, locations, details, record_path):
    """locations maps roles to (actual path, whole-phase growth on that FS).

    When roles share a filesystem their forecasts describe the same phase;
    take the maximum, never claim the same free bytes as separate capacity.
    """
    record = {"schema_version": 1, "phase": phase, "run_id": candidate["run_id"],
              "source_input_sha256": candidate["source"]["inputs"]["sha256"],
              "source_revision": candidate["source"]["revision"],
              "builds": candidate.get("builds", {}), "reserve_bytes": RESERVE,
              "measured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "details": details, "filesystems": {}, "status": "blocked"}
    try:
        for role, (path, forecast) in locations.items():
            path = Path(path).resolve(strict=True)
            if not path.is_dir() or type(forecast) is not int or forecast < 0:
                raise ValueError("existing directory and nonnegative phase forecast required")
            device = str(path.stat().st_dev)
            free = shutil.disk_usage(path).free
            group = record["filesystems"].setdefault(device, {"paths": {}, "observed_free_bytes": free,
                                                            "forecast_additional_bytes": 0})
            group["paths"][role] = str(path)
            group["observed_free_bytes"] = min(group["observed_free_bytes"], free)
            group["forecast_additional_bytes"] = max(group["forecast_additional_bytes"], forecast)
            group["minimum_free_bytes"] = group["forecast_additional_bytes"] + RESERVE
        if any(group["observed_free_bytes"] < group["minimum_free_bytes"] for group in record["filesystems"].values()):
            raise ValueError("phase resource admission failed; retain artifacts and review capacity")
        record["status"] = "admitted"
    except (OSError, ValueError) as error:
        record["reason"] = str(error)
        atomic_json(record_path, record)
        raise ValueError(str(error)) from error
    atomic_json(record_path, record)
    return record


def gzip_bound(tar_bytes):
    # Python gzip uses zlib's default window/memory parameters. zlib's
    # compressBound formula covers deflate expansion; 1 MiB additionally covers
    # the gzip wrapper/filename and admission metadata writes, conservatively.
    return tar_bytes + (tar_bytes >> 12) + (tar_bytes >> 14) + (tar_bytes >> 25) + 13 + 1024 ** 2
