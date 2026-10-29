"""Synthetic controls for the live-evidence checker; these are not hook samples."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import zlib

import pytest


@pytest.fixture
def verifier(monkeypatch):
    tools = Path(__file__).resolve().parents[1] / "tools"
    monkeypatch.syspath_prepend(str(tools))
    spec = importlib.util.spec_from_file_location("live_verifier", tools / "verify_live_hook.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64(value):
    return base64.b64encode(value).decode("ascii")


@pytest.fixture
def samples(verifier):
    raw = bytes.fromhex("f8 03 03 04 ff 82 12 3f")
    return [{"schema": "whatsapp-original-node-pair-v1", "pid": 100, "sample_id": i,
             "direction": direction, "observation_kind": "live-network-node",
             "node_identity": i,
             "native_rewrite_b64": b64(raw),
             "native_rewrite_reference": {"observation_kind": "controlled-native-writer-reference-no-network",
                                          "node_snapshot_before_rewrite": True, "node_identity": i},
             "format": "raw-node", "bytes_b64": b64(raw), "frame_b64": b64(b"\0" + raw),
             "network_provenance": {**{key: True for key in verifier.PROVENANCE[direction]},
                                    **verifier.COUNTS[direction]},
             "original_node": {"tag": "node", "attributes": [
                 {"key": "key", "value": "123", "original_type": 0, "jid": None}],
                 "children": None, "data_b64": None}}
            for i, direction in enumerate(("write", "read"), 1)]


def run(verifier, samples, tmp_path, dictionary):
    path = tmp_path / "synthetic-checker-controls.jsonl"
    path.write_text("\n".join(json.dumps(x) for x in samples) + "\n")
    return verifier.verify(path, dictionary)


def test_exact_live_checks(verifier, samples, tmp_path, dictionary):
    report = run(verifier, samples, tmp_path, dictionary)
    assert report["status"] == "passed"
    assert report["passed_pairs"] == 2
    assert report["distinct_raw_encodings"] == 1
    for direction in ("read", "write"):
        assert report["directions"][direction]["write_decoded_object_exact"] == 1


@pytest.mark.parametrize("direction", [0, 1])
def test_changed_native_object_rejected(verifier, samples, tmp_path, dictionary, direction):
    samples[direction]["original_node"]["attributes"][0]["value"] = "private-secret"
    report = run(verifier, samples, tmp_path, dictionary)
    case = report["cases"][direction]
    assert not case["read_matches_original_object"]
    assert not case["write_matches_native_writer"]
    assert case["write_decoded_object_exact"]
    assert report["status"] == "incomplete-or-failed"
    assert "private-secret" not in json.dumps(report)


def test_noncanonical_wire_is_preserved_separately(verifier, samples, tmp_path, dictionary):
    # Valid noncanonical raw tag, deliberately different from native-like token form.
    raw = bytes.fromhex("f8 03 fc 04 6e6f6465 04 ff 82 12 3f")
    samples[1].update(bytes_b64=b64(raw), frame_b64=b64(b"\0" + raw))
    report = run(verifier, samples, tmp_path, dictionary)
    case = report["cases"][1]
    assert case["read_matches_original_object"]
    assert case["write_matches_native_writer"]
    assert case["write_decoded_object_exact"]
    assert not case["canonical_write_exact_network_bytes"]
    assert report["noncanonical_network_pairs"] == 1
    assert report["status"] == "passed"


def test_zlib_identity_separate_from_raw_identity(verifier, samples, tmp_path, dictionary):
    raw = base64.b64decode(samples[1]["bytes_b64"])
    samples[1]["frame_b64"] = b64(b"\2" + zlib.compress(raw, 9))
    report = run(verifier, samples, tmp_path, dictionary)
    assert report["status"] == "passed"
    assert not report["cases"][1]["plaintext_frame_write"]["equal"]
    assert report["frame_flags"] == {"0": 1, "2": 1}


@pytest.mark.parametrize("mutation", ["missing-provenance", "false-provenance", "retained",
                                     "one-direction", "duplicate", "empty", "frame-mismatch",
                                     "bad-compression", "missing-frame", "bad-json"])
def test_incomplete_evidence_cannot_pass(verifier, samples, tmp_path, dictionary, mutation):
    if mutation == "missing-provenance":
        del samples[1]["network_provenance"]["a07_returned"]
    elif mutation == "false-provenance":
        samples[0]["network_provenance"]["transport_write_succeeded"] = False
    elif mutation == "retained":
        samples[1]["observation_kind"] = "controlled-retained-node-replay"
    elif mutation == "one-direction":
        samples.pop()
    elif mutation == "duplicate":
        samples.append(copy.deepcopy(samples[1]))
    elif mutation == "empty":
        samples.clear()
    elif mutation == "frame-mismatch":
        samples[1]["frame_b64"] = b64(bytes.fromhex("00 f8 01 03"))
    elif mutation == "bad-compression":
        samples[1]["frame_b64"] = b64(b"\2not-zlib")
    elif mutation == "missing-frame":
        del samples[1]["frame_b64"]
    elif mutation == "bad-json":
        path = tmp_path / "broken.jsonl"
        path.write_text("{\n")
        assert verifier.verify(path, dictionary)["status"] == "incomplete-or-failed"
        return
    assert run(verifier, samples, tmp_path, dictionary)["status"] == "incomplete-or-failed"


@pytest.mark.parametrize("index,key,value", [
    (0, "encrypt_count", 0), (0, "encrypt_count", 2),
    (0, "encrypt_count", True), (0, "encrypt_count", 1.0),
    (0, "transport_write_count", None), (0, "transport_write_count", 2),
    (1, "decrypt_nonempty_count", 0), (1, "decrypt_nonempty_count", True),
    (1, "root_stream_remaining", False), (1, "root_stream_remaining", 0.0),
    (1, "root_stream_remaining", 1),
])
def test_provenance_counts_must_match_booleans(verifier, samples, tmp_path, dictionary, index, key, value):
    samples[index]["network_provenance"][key] = value
    assert run(verifier, samples, tmp_path, dictionary)["status"] == "incomplete-or-failed"


@pytest.mark.parametrize("mutation", ["missing", "wrong-bytes", "wrong-identity", "wrong-kind", "late-snapshot"])
def test_native_writer_reference_required(verifier, samples, tmp_path, dictionary, mutation):
    if mutation == "missing":
        del samples[1]["native_rewrite_b64"]
    elif mutation == "wrong-bytes":
        samples[1]["native_rewrite_b64"] = b64(b"not-a-node")
    elif mutation == "wrong-identity":
        samples[1]["native_rewrite_reference"]["node_identity"] = 999
    elif mutation == "wrong-kind":
        samples[1]["native_rewrite_reference"]["observation_kind"] = "unknown"
    else:
        samples[1]["native_rewrite_reference"]["node_snapshot_before_rewrite"] = False
    assert run(verifier, samples, tmp_path, dictionary)["status"] == "incomplete-or-failed"
