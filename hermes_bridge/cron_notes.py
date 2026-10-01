"""Read Hermes's notepad in the explicitly selected job's storage context."""
import importlib

from .operation_dispatch import _RpcError


def read_notes(profile: str, job_id: str, *, capabilities: bool = False):
    try:
        profiles = importlib.import_module("hermes_cli.profiles")
        jobs = importlib.import_module("cron.jobs")
        notepad = importlib.import_module("cron.notepad")
        homes = importlib.import_module("hermes_constants")
        required = (
            (profiles, "validate_profile_name"), (profiles, "profile_exists"),
            (profiles, "get_profile_dir"), (jobs, "use_cron_store"), (jobs, "get_job"),
            (notepad, "list_notes"), (notepad, "_current_notepad_file"), (homes, "set_hermes_home_override"),
            (homes, "reset_hermes_home_override"),
        )
        if any(not callable(getattr(module, name, None)) for module, name in required):
            return {"available": False, "reason": "notes_unsupported"}
    except Exception:
        return {"available": False, "reason": "notes_unsupported"}

    try:
        profiles.validate_profile_name(profile)
        if not profiles.profile_exists(profile):
            return {"available": False, "reason": "profile_missing"}
        home = profiles.get_profile_dir(profile)
        token = homes.set_hermes_home_override(home)
        try:
            with jobs.use_cron_store(home):
                job = jobs.get_job(job_id)
                if job is None:
                    return {"available": False, "reason": "job_missing"}
                # Older notepads pin their path at import time. Do not serve
                # those versions under a different selected core-profile.
                if notepad._current_notepad_file().resolve() != home.resolve() / "cron" / "notepad.db":
                    return {"available": False, "reason": "notes_unsupported"}
                result = {
                    "available": True, "profile": profile,
                    "job": {"id": job_id, "name": job.get("name")},
                }
                if not capabilities:
                    result["notes"] = [
                        {"key": row["key"], "value": row["value"]}
                        for row in notepad.list_notes(job_id)
                    ]
                return result
        finally:
            homes.reset_hermes_home_override(token)
    except Exception as exc:
        # Never let upstream exception text (which may contain values) reach
        # dispatcher logs or error payloads.
        raise _RpcError("cron_notes_unavailable") from exc
