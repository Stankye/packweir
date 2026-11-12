"""Generate wire compatibility examples with the pinned upstream ODM.

This is a maintenance tool, not part of cargo test. See README.md for provenance
and the distinction between schema compatibility and qualification on a live AL.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
BASE_COMMIT = "abb23625186247802c1f0376a5c79a567120f78d"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base_checkout", type=Path)
    args = parser.parse_args()
    revision = subprocess.check_output(
        ["git", "-C", str(args.base_checkout), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != BASE_COMMIT:
        raise SystemExit(f"expected base {BASE_COMMIT}, got {revision}")
    sys.path.insert(0, str(args.base_checkout))

    from assemblyline.common.caching import generate_conf_key
    from assemblyline.common.forge import get_classification
    from assemblyline.odm.messages.submission import Submission as SubmitResponse
    from assemblyline.odm.models.error import Error
    from assemblyline.odm.models.file import File
    from assemblyline.odm.models.result import Result
    from assemblyline.odm.models.submission import Submission, SubmissionParams

    classification = get_classification().UNRESTRICTED
    submitted = "2026-11-11T19:00:00.000000Z"
    started = "2026-11-11T19:00:01.000000Z"
    completed = "2026-11-11T19:00:02.000000Z"
    now = "2026-11-11T19:01:00.000000Z"
    expiry = "2026-11-18T19:00:00.000000Z"
    sid = "00000000-0000-4000-8000-000000000001"
    run_id = "00000000-0000-4000-8000-000000000002"
    service_version = "4.8.0.stable0"
    root_data = b"Packweir Assemblyline schema compatibility root\n"
    child_data = b"Packweir Assemblyline schema compatibility extracted child\n"
    root_sha = hashlib.sha256(root_data).hexdigest()
    child_sha = hashlib.sha256(child_data).hexdigest()
    params = SubmissionParams({
        "classification": classification,
        "description": "Packweir upstream ODM compatibility example",
        "submitter": "packweir-fixture",
        "ttl": 7,
        "ignore_cache": False,
        "max_extracted": 256,
        "max_supplementary": 64,
        "services": {"selected": ["Extract"], "excluded": [], "rescan": [], "resubmit": []},
        "service_spec": {"Extract": {}},
    }).as_primitives()
    request_digest = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()
    metadata = {"packweir_run_id": run_id, "packweir_request_digest": request_digest}
    task = SimpleNamespace(
        service_config={"fixture_schema_only": True}, deep_scan=False,
        max_files=256, min_classification=SimpleNamespace(value=classification),
        ignore_filtering=False, ignore_cache=False,
    )
    configuration_key = "c" + generate_conf_key(task=task)

    def envelope(data, status=200, error=""):
        return {"api_response": data, "api_error_message": error,
                "api_server_version": "4.7.4.stable11", "api_status_code": status}

    def file_info(data, sha):
        return File({
            "ascii": data.decode().strip(), "classification": classification,
            "entropy": 4.0, "expiry_ts": expiry, "hex": data[:64].hex(),
            "md5": hashlib.md5(data).hexdigest(), "magic": "ASCII text",
            "mime": "text/plain", "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": sha, "size": len(data), "ssdeep": "3::", "type": "text/plain",
            "seen": {"first": submitted, "last": submitted},
        }).as_primitives()

    infos = {root_sha: file_info(root_data, root_sha), child_sha: file_info(child_data, child_sha)}

    def section():
        return {"classification": classification, "body_format": "TEXT", "depth": 0,
                "title_text": "Schema compatibility example", "body": "Observation recorded."}

    def result(sha, extracted):
        obj = Result({
            "classification": classification, "created": completed, "expiry_ts": expiry,
            "sha256": sha,
            "response": {"service_name": "Extract", "service_version": service_version,
                         "milestones": {"service_started": started, "service_completed": completed},
                         "extracted": extracted},
            "result": {"score": 0, "sections": [section()]},
        })
        key = obj.build_key(task=task)
        assert key.split(".")[3] == configuration_key
        return key, obj.as_primitives()

    child_ref = {"name": "child.txt", "sha256": child_sha,
                 "description": "Extracted schema example", "classification": classification,
                 "parent_relation": "EXTRACTED"}
    root_key, root_result = result(root_sha, [child_ref])
    child_key, child_result = result(child_sha, [])

    def node(sha, name, children):
        info = infos[sha]
        return {"name": [name], "type": info["type"], "sha256": sha, "size": info["size"],
                "children": children, "truncated": False, "score": 0}

    tree = {root_sha: node(root_sha, "root.txt", {child_sha: node(child_sha, "child.txt", {})})}
    tree_response = {"tree": tree, "classification": classification, "filtered": False,
                     "partial": False, "supplementary": []}
    submitted_files = [{"name": "root.txt", "sha256": root_sha, "size": len(root_data)}]
    submission = Submission({
        "sid": sid, "classification": classification, "error_count": 0, "errors": [],
        "file_count": 2, "files": submitted_files, "max_score": 0, "metadata": metadata,
        "params": params, "results": [root_key, child_key], "state": "completed",
        "times": {"submitted": submitted, "completed": completed}, "expiry_ts": expiry,
    }).as_primitives()
    full = copy.deepcopy(submission)
    full.update({"results": {root_key: root_result, child_key: child_result}, "errors": {},
                 "file_tree": tree, "file_infos": infos, "missing_result_keys": [],
                 "missing_error_keys": [], "missing_file_keys": []})
    accepted = SubmitResponse({"sid": sid, "time": submitted, "files": submitted_files,
                               "metadata": metadata, "params": params}).as_primitives()
    failure = Error({
        "created": completed, "expiry_ts": expiry, "sha256": child_sha,
        "type": "MAX RETRY REACHED", "severity": "error",
        "response": {"message": "Service execution did not complete after retries.",
                     "service_name": "Extract", "service_version": service_version,
                     "status": "FAIL_RECOVERABLE"},
    })
    failure_key = failure.build_key(task=task)
    partial = copy.deepcopy(full)
    partial["results"].pop(child_key)
    partial["errors"] = {failure_key: failure.as_primitives()}
    partial["error_count"] = 1
    empty_key = Result.help_build_key(child_sha, "Extract", service_version, True, task=task)
    # Datastore.create_empty_result_from_key intentionally leaves underscores in
    # the version and creates current timestamps. Keep deterministic values here
    # while preserving that upstream reconstruction, rather than pretending this
    # document preserves the original execution/tool-version evidence.
    synthetic_empty = Result({
        "classification": classification, "created": now, "expiry_ts": expiry,
        "sha256": child_sha,
        "response": {"service_name": "Extract", "service_version": service_version.replace(".", "_"),
                     "milestones": {"service_started": now, "service_completed": now}},
    }).as_primitives()
    empty = copy.deepcopy(full)
    empty["results"].pop(child_key)
    empty["results"][empty_key] = synthetic_empty
    outputs = {
        "submit.accepted.json": envelope(accepted),
        "submission.completed.json": envelope(submission),
        "submission.is_completed.json": envelope(True),
        "submission.full.completed.json": envelope(full),
        "submission.tree.completed.json": envelope(tree_response),
        "submission.full.service_error.json": envelope(partial),
        "submission.full.synthetic_empty.json": envelope(empty),
        "manifest.json": {"fixture_kind": "generated_upstream_odm_compatibility_not_live_capture",
                          "base_commit": BASE_COMMIT, "subject_sha256": root_sha,
                          "child_sha256": child_sha, "submission_id": sid, "now": now,
                          "run_id": run_id, "request_digest": request_digest,
                          "service": "Extract", "service_version": service_version,
                          "service_tool_version": None, "configuration_key": configuration_key,
                          "warning": "Service/configuration values are schema test inputs, not a qualified deployment."},
    }
    fixtures = HERE / "fixtures"
    fixtures.mkdir(exist_ok=True)
    for name, value in outputs.items():
        (fixtures / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(f"Validated upstream ODMs and wrote {len(outputs)} deterministic compatibility fixtures.")


if __name__ == "__main__":
    main()
