"""Tests for props.conf field extractions against CVE V5 sample data."""

import json
import os
import re

import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures")
PROPS_CONF = os.path.join(
    os.path.dirname(__file__), "..", "..", "TA-cveicu", "default", "props.conf"
)


@pytest.fixture
def cve_sample_raw():
    """Load the first CVE V5 sample as a raw JSON string (simulating _raw)."""
    with open(os.path.join(FIXTURES_DIR, "cve_v5_sample.json")) as f:
        samples = json.load(f)
    return json.dumps(samples[0])


@pytest.fixture
def cve_sample_dict():
    """Load the first CVE V5 sample as a dict."""
    with open(os.path.join(FIXTURES_DIR, "cve_v5_sample.json")) as f:
        samples = json.load(f)
    return samples[0]


def _spath(raw_json, path):
    """Simulate Splunk's spath() function for testing.

    Supports dotted paths and {N} array indexing.
    E.g., "containers.cna.metrics{0}.cvssV3_1.baseScore"
    """
    obj = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
    parts = re.split(r"\.|(?=\{)", path)
    for part in parts:
        if not part:
            continue
        match = re.match(r"\{(\d+)\}", part)
        if match:
            idx = int(match.group(1))
            if isinstance(obj, list) and idx < len(obj):
                obj = obj[idx]
            else:
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
            if obj is None:
                return None
        else:
            return None
    return obj


class TestCoreMetadataFields:
    """Verify core CVE metadata extractions."""

    def test_cve_id(self, cve_sample_raw):
        assert _spath(cve_sample_raw, "cveMetadata.cveId") == "CVE-2024-12345"

    def test_state(self, cve_sample_raw):
        assert _spath(cve_sample_raw, "cveMetadata.state") == "PUBLISHED"

    def test_date_published(self, cve_sample_raw):
        result = _spath(cve_sample_raw, "cveMetadata.datePublished")
        assert result == "2024-02-20T18:00:00.000Z"

    def test_date_updated(self, cve_sample_raw):
        result = _spath(cve_sample_raw, "cveMetadata.dateUpdated")
        assert result == "2024-03-01T12:00:00.000Z"

    def test_assigner(self, cve_sample_raw):
        assert _spath(cve_sample_raw, "cveMetadata.assignerShortName") == "microsoft"


class TestCNAFields:
    """Verify CNA container field extractions."""

    def test_title(self, cve_sample_raw):
        result = _spath(cve_sample_raw, "containers.cna.title")
        assert result == "Remote Code Execution in Widget Service"

    def test_description(self, cve_sample_raw):
        result = _spath(cve_sample_raw, "containers.cna.descriptions{0}.value")
        assert "remote code execution" in result.lower()

    def test_affected_vendor(self, cve_sample_raw):
        assert (
            _spath(cve_sample_raw, "containers.cna.affected{0}.vendor") == "Microsoft"
        )

    def test_affected_product(self, cve_sample_raw):
        result = _spath(cve_sample_raw, "containers.cna.affected{0}.product")
        assert result == "Widget Service"

    def test_cwe_id(self, cve_sample_raw):
        result = _spath(
            cve_sample_raw, "containers.cna.problemTypes{0}.descriptions{0}.cweId"
        )
        assert result == "CWE-79"


class TestCVSSFields:
    """Verify CVSS score extractions."""

    def test_cvss_v31_score(self, cve_sample_raw):
        assert (
            _spath(cve_sample_raw, "containers.cna.metrics{0}.cvssV3_1.baseScore")
            == 8.8
        )

    def test_cvss_v31_severity(self, cve_sample_raw):
        result = _spath(
            cve_sample_raw, "containers.cna.metrics{0}.cvssV3_1.baseSeverity"
        )
        assert result == "HIGH"

    def test_cvss_v31_vector(self, cve_sample_raw):
        result = _spath(
            cve_sample_raw, "containers.cna.metrics{0}.cvssV3_1.vectorString"
        )
        assert result.startswith("CVSS:3.1/")

    def test_computed_cvss_score_uses_best_available(self, cve_sample_raw):
        """The coalesce pattern should pick v4.0 > v3.1 > v3.0 > v2.0."""
        v40 = _spath(cve_sample_raw, "containers.cna.metrics{0}.cvssV4_0.baseScore")
        v31 = _spath(cve_sample_raw, "containers.cna.metrics{0}.cvssV3_1.baseScore")
        v30 = _spath(cve_sample_raw, "containers.cna.metrics{0}.cvssV3_0.baseScore")
        v20 = _spath(cve_sample_raw, "containers.cna.metrics{0}.cvssV2_0.baseScore")
        expected = next((s for s in [v40, v31, v30, v20] if s is not None), None)
        assert expected == 8.8


class TestADPFields:
    """Verify ADP enrichment detection."""

    def test_has_cisa_adp(self, cve_sample_raw):
        adp_title = _spath(cve_sample_raw, "containers.adp{0}.title")
        expected = "true" if adp_title is not None else "false"
        assert expected == "true"


class TestPropsConfPaths:
    """Verify that every spath() call in props.conf resolves on sample data."""

    def _extract_spath_paths(self):
        """Parse all spath() paths from props.conf EVAL fields."""
        paths = []
        with open(PROPS_CONF) as f:
            for line in f:
                for match in re.finditer(r'spath\(_raw,\s*"([^"]+)"\)', line):
                    paths.append(match.group(1))
        return list(set(paths))

    def test_all_spath_paths_are_resolvable(self, cve_sample_raw):
        """At least one sample record should resolve each spath path to non-None."""
        paths = self._extract_spath_paths()
        assert len(paths) > 0, "No spath paths found in props.conf"

        with open(os.path.join(FIXTURES_DIR, "cve_v5_sample.json")) as f:
            samples = json.load(f)

        unresolvable = []
        for path in paths:
            resolved = False
            for sample in samples:
                if _spath(json.dumps(sample), path) is not None:
                    resolved = True
                    break
            if not resolved:
                unresolvable.append(path)

        acceptable_missing = {
            "containers.cna.metrics{0}.cvssV4_0.baseScore",
            "containers.cna.metrics{0}.cvssV4_0.baseSeverity",
            "containers.cna.metrics{0}.cvssV4_0.vectorString",
            "containers.cna.metrics{0}.cvssV3_0.baseScore",
            "containers.cna.metrics{0}.cvssV3_0.baseSeverity",
            "containers.cna.metrics{0}.cvssV3_0.vectorString",
            "containers.cna.metrics{0}.cvssV2_0.baseScore",
            "containers.cna.metrics{0}.cvssV2_0.vectorString",
        }
        unexpected = set(unresolvable) - acceptable_missing
        assert not unexpected, f"Unresolvable spath paths in props.conf: {unexpected}"
