"""Tests for all Python scripts in the reverse-engine-recursive-run toolkit.

Covers: hotspot_merge, ownership_diff, parse_semgrep, parse_trivy,
        risk_update, scan_drift, and the CLI entry point.
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest


# ─── hotspot_merge tests ────────────────────────────────────────────

class TestHotspotMerge:
    def test_load_churn(self):
        from hotspot_merge import load_churn
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("10 src/app.py\n5 src/utils.py\n")
        result = load_churn(path)
        os.unlink(path)
        assert result == {"src/app.py": 10, "src/utils.py": 5}

    def test_load_churn_empty_lines(self):
        from hotspot_merge import load_churn
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            f.write("\n10 src/app.py\n\n")
        result = load_churn(path)
        os.unlink(path)
        assert "src/app.py" in result

    def test_load_complexity(self):
        from hotspot_merge import load_complexity
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"src/app.py": [{"complexity": 10}, {"complexity": 20}]}, f)
        result = load_complexity(path)
        os.unlink(path)
        assert result["src/app.py"] == 15.0

    def test_load_complexity_empty_blocks(self):
        from hotspot_merge import load_complexity
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"src/empty.py": []}, f)
        result = load_complexity(path)
        os.unlink(path)
        assert result["src/empty.py"] == 0

    def test_load_coverage(self):
        from hotspot_merge import load_coverage
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"files": {"src/app.py": 0.85}}, f)
        result = load_coverage(path)
        os.unlink(path)
        assert result["src/app.py"] == 0.85

    def test_load_coverage_flat_format(self):
        from hotspot_merge import load_coverage
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"src/app.py": 0.7}, f)
        result = load_coverage(path)
        os.unlink(path)
        assert result["src/app.py"] == 0.7


# ─── parse_semgrep tests ────────────────────────────────────────────

class TestParseSemgrep:
    def _run_parse(self, input_data):
        from parse_semgrep import main as semgrep_main, MAP
        fd_in, in_path = tempfile.mkstemp(suffix=".json")
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)
        with os.fdopen(fd_in, "w") as f:
            json.dump(input_data, f)
        import sys
        old_argv = sys.argv
        sys.argv = ["parse_semgrep", "--input", in_path, "--out", out_path]
        semgrep_main()
        sys.argv = old_argv
        with open(out_path) as f:
            result = json.load(f)
        os.unlink(in_path)
        os.unlink(out_path)
        return result

    def test_parse_single_finding(self):
        data = {"results": [{
            "check_id": "rule.xss",
            "path": "src/views.py",
            "extra": {"message": "XSS vulnerability", "severity": "ERROR"},
            "start": {"line": 42},
        }]}
        result = self._run_parse(data)
        assert len(result) == 1
        assert result[0]["severity"] == "HIGH"
        assert "line 42" in result[0]["desc"]

    def test_severity_mapping(self):
        data = {"results": [
            {"check_id": "r1", "path": "a.py", "extra": {"message": "m", "severity": "WARNING"}, "start": {"line": 1}},
            {"check_id": "r2", "path": "b.py", "extra": {"message": "m", "severity": "INFO"}, "start": {"line": 1}},
        ]}
        result = self._run_parse(data)
        sevs = {r["severity"] for r in result}
        assert "MEDIUM" in sevs
        assert "LOW" in sevs

    def test_empty_results(self):
        result = self._run_parse({"results": []})
        assert result == []

    def test_missing_results_key(self):
        result = self._run_parse({})
        assert result == []


# ─── parse_trivy tests ──────────────────────────────────────────────

class TestParseTrivy:
    def _run_parse(self, input_data):
        from parse_trivy import main as trivy_main
        fd_in, in_path = tempfile.mkstemp(suffix=".json")
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)
        with os.fdopen(fd_in, "w") as f:
            json.dump(input_data, f)
        import sys
        old_argv = sys.argv
        sys.argv = ["parse_trivy", "--input", in_path, "--out", out_path]
        trivy_main()
        sys.argv = old_argv
        with open(out_path) as f:
            result = json.load(f)
        os.unlink(in_path)
        os.unlink(out_path)
        return result

    def test_parse_single_vuln(self):
        data = {"Results": [{
            "Target": "requirements.txt",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-1234",
                "PkgName": "requests",
                "InstalledVersion": "2.28.0",
                "FixedVersion": "2.31.0",
                "Severity": "HIGH",
                "Title": "SSRF in requests",
            }],
        }]}
        result = self._run_parse(data)
        assert len(result) == 1
        assert result[0]["cve"] == "CVE-2024-1234"
        assert result[0]["severity"] == "HIGH"

    def test_critical_maps_to_high(self):
        data = {"Results": [{
            "Target": "go.sum",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-9999",
                "PkgName": "stdlib",
                "InstalledVersion": "1.20",
                "Severity": "CRITICAL",
            }],
        }]}
        result = self._run_parse(data)
        assert result[0]["severity"] == "HIGH"

    def test_no_vulnerabilities(self):
        data = {"Results": [{"Target": "Dockerfile", "Vulnerabilities": None}]}
        result = self._run_parse(data)
        assert result == []

    def test_empty_input(self):
        result = self._run_parse({})
        assert result == []


# ─── risk_update tests ──────────────────────────────────────────────

class TestRiskUpdate:
    def test_hotspot_severity_high(self):
        from risk_update import hotspot_sev
        assert hotspot_sev(0.80) == "HIGH"

    def test_hotspot_severity_medium(self):
        from risk_update import hotspot_sev
        assert hotspot_sev(0.60) == "MEDIUM"

    def test_hotspot_severity_low(self):
        from risk_update import hotspot_sev
        assert hotspot_sev(0.30) == "LOW"

    def test_hotspot_severity_boundary(self):
        from risk_update import hotspot_sev
        assert hotspot_sev(0.75) == "HIGH"
        assert hotspot_sev(0.50) == "MEDIUM"


# ─── scan_drift tests ───────────────────────────────────────────────

class TestScanDrift:
    def test_edge_key(self):
        from scan_drift import edge_key
        e = {"from": "A", "to": "B", "type": "import"}
        assert edge_key(e) == ("A", "B", "import")

    def test_edge_key_missing_type(self):
        from scan_drift import edge_key
        e = {"from": "A", "to": "B"}
        assert edge_key(e) == ("A", "B", "")

    def test_drift_detection(self):
        """Full integration: write two graph files and run scan_drift.main()."""
        from scan_drift import main as drift_main
        prev = {
            "nodes": [{"id": "A"}, {"id": "B"}],
            "edges": [{"from": "A", "to": "B", "type": "import"}],
            "meta": {"ref": "abc123"},
        }
        cur = {
            "nodes": [{"id": "A"}, {"id": "B"}, {"id": "C"}],
            "edges": [
                {"from": "A", "to": "B", "type": "import"},
                {"from": "A", "to": "C", "type": "import"},
            ],
            "meta": {"ref": "def456"},
        }
        fd_prev, prev_path = tempfile.mkstemp(suffix=".json")
        fd_cur, cur_path = tempfile.mkstemp(suffix=".json")
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)
        with os.fdopen(fd_prev, "w") as f:
            json.dump(prev, f)
        with os.fdopen(fd_cur, "w") as f:
            json.dump(cur, f)

        import sys
        old_argv = sys.argv
        # threshold 0.5 -> churn is 1/1=1.0, should breach
        sys.argv = ["scan_drift", "--current", cur_path, "--previous", prev_path,
                     "--threshold", "0.5", "--out", out_path]
        with pytest.raises(SystemExit) as exc_info:
            drift_main()
        sys.argv = old_argv

        assert exc_info.value.code == 2  # breach
        with open(out_path) as f:
            report = json.load(f)
        assert report["summary"]["breach"] is True
        assert report["summary"]["added_edges_count"] == 1

        os.unlink(prev_path)
        os.unlink(cur_path)
        os.unlink(out_path)


# ─── ownership_diff tests ──────────────────────────────────────────

class TestOwnershipDiff:
    def test_bucket_by_directory(self):
        from ownership_diff import bucket_by_directory
        entries = [
            "alice@example.com",
            "src/core/main.py",
            "src/core/utils.py",
            "bob@example.com",
            "src/api/handler.py",
        ]
        result = bucket_by_directory(entries, depth=2)
        assert "src/core" in result
        assert result["src/core"]["alice@example.com"] == 2
        assert "src/api" in result
        assert result["src/api"]["bob@example.com"] == 1

    def test_bucket_skips_empty_paths(self):
        from ownership_diff import bucket_by_directory
        entries = ["alice@x.com", "", "src/a.py"]
        result = bucket_by_directory(entries, depth=2)
        assert "src" in result or len(result) >= 0  # should not crash

    def test_load_criticality_reads_yaml(self):
        import yaml
        from ownership_diff import load_criticality
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            yaml.dump({"src/core": 5, "src/api": 3}, f)
        result = load_criticality(path)
        os.unlink(path)
        assert result["src/core"] == 5
        assert result["src/api"] == 3

    def test_load_criticality_none_returns_empty(self):
        from ownership_diff import load_criticality
        assert load_criticality(None) == {}

    def test_bucket_single_author_per_dir(self):
        from ownership_diff import bucket_by_directory
        entries = ["alice@x.com", "src/core/main.py", "src/core/utils.py"]
        result = bucket_by_directory(entries, depth=2)
        assert len(result["src/core"]) == 1
        assert result["src/core"]["alice@x.com"] == 2


# ─── hotspot_merge.load_criticality test ────────────────────────────

class TestHotspotMergeLoadCriticality:
    def test_load_criticality_yaml(self):
        import yaml
        from hotspot_merge import load_criticality
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            yaml.dump({"src/auth.py": 5, "src/api.py": 2}, f)
        result = load_criticality(path)
        os.unlink(path)
        assert result["src/auth.py"] == 5
        assert result["src/api.py"] == 2


# ─── hotspot_merge main() integration tests ─────────────────────────

class TestHotspotMergeMain:
    def _make_churn_file(self, data):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            for filepath, count in data.items():
                f.write(f"{count} {filepath}\n")
        return path

    def _make_json_file(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        return path

    def _run(self, churn_data, complexity_data, coverage_data=None,
             top=50, env_overrides=None):
        import sys
        from hotspot_merge import main as hm_main

        ch_path = self._make_churn_file(churn_data)
        cc_path = self._make_json_file(complexity_data)
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)

        argv = ["hotspot_merge",
                "--churn", ch_path,
                "--complexity", cc_path,
                "--out", out_path,
                "--top", str(top)]

        cov_path = None
        if coverage_data is not None:
            cov_path = self._make_json_file(coverage_data)
            argv += ["--coverage", cov_path]

        old_argv = sys.argv
        old_env = {}
        try:
            sys.argv = argv
            if env_overrides:
                for k, v in env_overrides.items():
                    old_env[k] = os.environ.get(k)
                    os.environ[k] = v
            hm_main()
        finally:
            sys.argv = old_argv
            for k, ov in old_env.items():
                if ov is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = ov

        with open(out_path) as f:
            result = json.load(f)

        for p in [ch_path, cc_path, out_path] + ([cov_path] if cov_path else []):
            os.unlink(p)
        return result

    def test_risk_score_formula(self):
        """Single max-churn, max-complexity file — verify the default weight formula."""
        result = self._run(
            churn_data={"src/app.py": 10},
            complexity_data={"src/app.py": [{"complexity": 5}]},
        )
        h = result["hotspots"][0]
        # norm_churn=1, norm_cc=1, cov_pen=0.5 (absent→0.5), norm_crit=1
        # risk = 1*0.4 + 1*0.4 + 0.5*0.1 + 1*0.1 = 0.95
        assert abs(h["risk_score"] - 0.95) < 0.01

    def test_sorted_highest_first(self):
        result = self._run(
            churn_data={"high.py": 100, "low.py": 1},
            complexity_data={
                "high.py": [{"complexity": 20}],
                "low.py": [{"complexity": 1}],
            },
        )
        spots = result["hotspots"]
        assert spots[0]["file"] == "high.py"
        assert spots[0]["risk_score"] > spots[1]["risk_score"]

    def test_top_n_limits_results(self):
        churn = {f"file{i}.py": i for i in range(1, 11)}
        complexity = {f"file{i}.py": [{"complexity": i}] for i in range(1, 11)}
        result = self._run(churn_data=churn, complexity_data=complexity, top=3)
        assert len(result["hotspots"]) == 3

    def test_coverage_reduces_risk(self):
        """Fully covered file gets lower risk than zero-covered file at same churn/complexity."""
        result = self._run(
            churn_data={"a.py": 10, "b.py": 10},
            complexity_data={
                "a.py": [{"complexity": 5}],
                "b.py": [{"complexity": 5}],
            },
            coverage_data={"files": {"a.py": 1.0, "b.py": 0.0}},
        )
        scores = {h["file"]: h["risk_score"] for h in result["hotspots"]}
        assert scores["b.py"] > scores["a.py"]

    def test_meta_weights_sum_to_one(self):
        result = self._run(
            churn_data={"a.py": 1},
            complexity_data={"a.py": [{"complexity": 1}]},
        )
        w = result["meta"]["weights"]
        assert abs(sum(w.values()) - 1.0) < 0.001

    def test_weight_normalization_via_env(self):
        """Weights that don't sum to 1 are auto-normalized."""
        result = self._run(
            churn_data={"a.py": 1},
            complexity_data={"a.py": [{"complexity": 1}]},
            env_overrides={
                "RISK_W_CHURN": "2.0",
                "RISK_W_COMPLEXITY": "2.0",
                "RISK_W_COVERAGE": "0.0",
                "RISK_W_CRITICALITY": "0.0",
            },
        )
        w = result["meta"]["weights"]
        assert abs(sum(w.values()) - 1.0) < 0.001
        assert abs(w["churn"] - 0.5) < 0.001

    def test_file_absent_from_churn_still_appears(self):
        result = self._run(
            churn_data={"a.py": 5},
            complexity_data={"b.py": [{"complexity": 3}]},
        )
        files = {h["file"] for h in result["hotspots"]}
        assert "a.py" in files
        assert "b.py" in files

    def test_components_keys_present(self):
        result = self._run(
            churn_data={"a.py": 5},
            complexity_data={"a.py": [{"complexity": 3}]},
        )
        comps = result["hotspots"][0]["components"]
        assert set(comps.keys()) == {"churn", "complexity", "coverage_penalty", "criticality_factor"}


# ─── risk_update load() and main() tests ─────────────────────────────

class TestRiskUpdateLoad:
    def test_load_none_returns_none(self):
        from risk_update import load
        assert load(None) is None

    def test_load_reads_json(self):
        from risk_update import load
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump({"x": 42}, f)
        result = load(path)
        os.unlink(path)
        assert result == {"x": 42}


class TestRiskUpdateMainFull:
    def _make_json(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        return path

    def _run(self, hotspots=None, drift=None, ownership=None, security=None):
        import sys
        from risk_update import main as ru_main

        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)
        argv = ["risk_update", "--out", out_path]
        paths = []

        for flag, data in [
            ("--hotspots", hotspots), ("--drift", drift),
            ("--ownership", ownership), ("--security", security),
        ]:
            if data is not None:
                p = self._make_json(data)
                paths.append(p)
                argv += [flag, p]

        old_argv = sys.argv
        sys.argv = argv
        try:
            ru_main()
        finally:
            sys.argv = old_argv

        with open(out_path) as f:
            result = json.load(f)
        os.unlink(out_path)
        for p in paths:
            os.unlink(p)
        return result

    def test_no_inputs_yields_empty_risks(self):
        r = self._run()
        assert r["derived_risks"] == []
        assert r["sources"]["hotspots"] is False

    def test_hotspot_high_severity(self):
        r = self._run(hotspots={"hotspots": [{"file": "auth.py", "risk_score": 0.8}]})
        risks = r["derived_risks"]
        assert len(risks) == 1
        assert risks[0]["type"] == "HOTSPOT"
        assert risks[0]["severity"] == "HIGH"
        assert risks[0]["component"] == "auth.py"

    def test_hotspot_multiple_severities(self):
        r = self._run(hotspots={"hotspots": [
            {"file": "a.py", "risk_score": 0.8},
            {"file": "b.py", "risk_score": 0.6},
            {"file": "c.py", "risk_score": 0.3},
        ]})
        by_file = {risk["component"]: risk["severity"] for risk in r["derived_risks"]}
        assert by_file["a.py"] == "HIGH"
        assert by_file["b.py"] == "MEDIUM"
        assert by_file["c.py"] == "LOW"

    def test_drift_breach_high_churn_is_high(self):
        drift = {
            "summary": {"breach": True, "churn_ratio": 0.5, "current_ref": "abc"},
            "core_boundary_flags": [],
        }
        r = self._run(drift=drift)
        arch = [x for x in r["derived_risks"] if x["type"] == "ARCH_DRIFT"]
        assert arch[0]["severity"] == "HIGH"

    def test_drift_breach_low_churn_is_medium(self):
        drift = {
            "summary": {"breach": True, "churn_ratio": 0.1, "current_ref": "abc"},
            "core_boundary_flags": [],
        }
        r = self._run(drift=drift)
        arch = [x for x in r["derived_risks"] if x["type"] == "ARCH_DRIFT"]
        assert arch[0]["severity"] == "MEDIUM"

    def test_drift_no_breach_no_arch_risk(self):
        drift = {
            "summary": {"breach": False, "churn_ratio": 0.0},
            "core_boundary_flags": [],
        }
        r = self._run(drift=drift)
        assert all(x["type"] != "ARCH_DRIFT" for x in r["derived_risks"])

    def test_drift_boundary_flags_added(self):
        drift = {
            "summary": {"breach": False, "churn_ratio": 0.0},
            "core_boundary_flags": [{"from": "X", "to": "Y"}],
        }
        r = self._run(drift=drift)
        bv = [x for x in r["derived_risks"] if x["type"] == "BOUNDARY_VIOLATION"]
        assert len(bv) == 1
        assert bv[0]["severity"] == "MEDIUM"

    def test_ownership_single_contributor_high_crit(self):
        ownership = {"directories": [
            {"path": "src/core", "flag": "SINGLE_CONTRIBUTOR", "criticality": 3}
        ]}
        r = self._run(ownership=ownership)
        kc = [x for x in r["derived_risks"] if x["type"] == "KNOWLEDGE_CONCENTRATION"]
        assert kc[0]["severity"] == "HIGH"

    def test_ownership_single_contributor_low_crit(self):
        ownership = {"directories": [
            {"path": "src/utils", "flag": "SINGLE_CONTRIBUTOR", "criticality": 2}
        ]}
        r = self._run(ownership=ownership)
        kc = [x for x in r["derived_risks"] if x["type"] == "KNOWLEDGE_CONCENTRATION"]
        assert kc[0]["severity"] == "MEDIUM"

    def test_ownership_high_concentration_high_crit(self):
        ownership = {"directories": [
            {"path": "src/api", "flag": "HIGH_CONCENTRATION", "criticality": 4}
        ]}
        r = self._run(ownership=ownership)
        kc = [x for x in r["derived_risks"] if x["type"] == "KNOWLEDGE_CONCENTRATION"]
        assert kc[0]["severity"] == "HIGH"

    def test_ownership_no_flag_skipped(self):
        ownership = {"directories": [{"path": "src/misc", "flag": None}]}
        r = self._run(ownership=ownership)
        assert all(x["type"] != "KNOWLEDGE_CONCENTRATION" for x in r["derived_risks"])

    def test_security_passthrough_with_remediation(self):
        security = [{"id": "SEC-001", "severity": "HIGH", "remediation": "Patch it."}]
        r = self._run(security=security)
        sec = [x for x in r["derived_risks"] if x["type"] == "SECURITY"]
        assert sec[0]["id"] == "SEC-001"
        assert sec[0]["severity"] == "HIGH"
        assert sec[0]["recommendation"] == "Patch it."

    def test_security_no_remediation_defaults(self):
        security = [{"severity": "LOW"}]
        r = self._run(security=security)
        sec = [x for x in r["derived_risks"] if x["type"] == "SECURITY"]
        assert sec[0]["id"] == "SEC-UNSET"
        assert sec[0]["recommendation"] == "Review & patch."

    def test_sources_flags_match_inputs(self):
        r = self._run(
            hotspots={"hotspots": []},
            security=[{"severity": "LOW"}],
        )
        assert r["sources"]["hotspots"] is True
        assert r["sources"]["security"] is True
        assert r["sources"]["drift"] is False
        assert r["sources"]["ownership"] is False

    def test_timestamp_present_and_utc(self):
        r = self._run()
        ts = r["timestamp"]
        assert "T" in ts
        assert ts.endswith("Z")


# ─── scan_drift additional coverage ──────────────────────────────────

class TestScanDriftAdditional:
    def _write_json(self, data):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        return path

    def test_no_breach_returns_normally(self):
        """Identical graphs → churn_ratio 0 → no SystemExit."""
        import sys
        from scan_drift import main as drift_main

        graph = {
            "nodes": [{"id": "A"}],
            "edges": [{"from": "A", "to": "B", "type": "import"}],
            "meta": {"ref": "x"},
        }
        prev_path = self._write_json(graph)
        cur_path = self._write_json(graph)
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)

        old_argv = sys.argv
        sys.argv = ["scan_drift", "--current", cur_path,
                    "--previous", prev_path,
                    "--threshold", "0.1", "--out", out_path]
        try:
            drift_main()
        finally:
            sys.argv = old_argv

        with open(out_path) as f:
            report = json.load(f)
        assert report["summary"]["breach"] is False

        for p in [prev_path, cur_path, out_path]:
            os.unlink(p)

    def test_removed_nodes_detected(self):
        import sys
        from scan_drift import main as drift_main

        prev = {
            "nodes": [{"id": "A"}, {"id": "B"}],
            "edges": [],
            "meta": {"ref": "p"},
        }
        cur = {
            "nodes": [{"id": "A"}],
            "edges": [],
            "meta": {"ref": "c"},
        }
        prev_path = self._write_json(prev)
        cur_path = self._write_json(cur)
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)

        old_argv = sys.argv
        sys.argv = ["scan_drift", "--current", cur_path,
                    "--previous", prev_path,
                    "--threshold", "0.5", "--out", out_path]
        try:
            drift_main()
        finally:
            sys.argv = old_argv

        with open(out_path) as f:
            report = json.load(f)
        assert "B" in report["removed_nodes"]

        for p in [prev_path, cur_path, out_path]:
            os.unlink(p)

    def test_core_boundary_flag_detected(self):
        """New edge to a zero-in-degree prev node triggers a boundary flag."""
        import sys
        from scan_drift import main as drift_main

        # A has in_degree 0 in prev (nothing points to it)
        prev = {
            "nodes": [{"id": "A"}, {"id": "B"}, {"id": "C"}],
            "edges": [{"from": "B", "to": "C", "type": "import"}],
            "meta": {"ref": "p"},
        }
        cur = {
            "nodes": [{"id": "A"}, {"id": "B"}, {"id": "C"}, {"id": "D"}],
            "edges": [
                {"from": "B", "to": "C", "type": "import"},
                {"from": "D", "to": "A", "type": "import"},
            ],
            "meta": {"ref": "c"},
        }
        prev_path = self._write_json(prev)
        cur_path = self._write_json(cur)
        fd_out, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd_out)

        old_argv = sys.argv
        sys.argv = ["scan_drift", "--current", cur_path,
                    "--previous", prev_path,
                    "--threshold", "0.5", "--out", out_path]
        try:
            with pytest.raises(SystemExit):
                drift_main()
        finally:
            sys.argv = old_argv

        with open(out_path) as f:
            report = json.load(f)
        assert any(f["to"] == "A" for f in report["core_boundary_flags"])

        for p in [prev_path, cur_path, out_path]:
            os.unlink(p)
