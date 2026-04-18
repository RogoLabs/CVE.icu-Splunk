"""Unit tests for EPSS/KEV custom search command."""

import gzip
import io
import json
import pytest
from unittest.mock import patch, MagicMock

try:
    from cveicu_epss_kev_command import CveicuepsskevCommand
except (ImportError, ModuleNotFoundError) as e:
    pytest.skip(f"splunklib not available: {e}", allow_module_level=True)


@pytest.fixture
def command():
    cmd = CveicuepsskevCommand.__new__(CveicuepsskevCommand)
    cmd.mode = "all"
    return cmd


class TestFetchKEV:
    def test_yields_correct_fields(self, command, kev_sample):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(kev_sample).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command._fetch_kev())

        assert len(rows) == 3
        row = rows[0]
        assert row["cve_id"] == "CVE-2024-12345"
        assert row["kev_vendor"] == "Microsoft"
        assert row["kev_product"] == "Widget Service"
        assert row["kev_vulnerability_name"] == "Microsoft Widget Service RCE"
        assert row["kev_date_added"] == "2024-02-25"
        assert row["kev_due_date"] == "2024-03-17"
        assert row["kev_required_action"] == "Apply updates per vendor instructions."
        assert row["kev_ransomware"] == "Known"
        assert row["in_kev"] == "true"

    def test_all_entries_yielded(self, command, kev_sample):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(kev_sample).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command._fetch_kev())

        cve_ids = [r["cve_id"] for r in rows]
        assert "CVE-2024-12345" in cve_ids
        assert "CVE-2023-44487" in cve_ids
        assert "CVE-2021-44228" in cve_ids


class TestFetchEPSS:
    def test_yields_correct_fields(self, command, epss_sample_gz_bytes):
        mock_response = MagicMock()
        mock_response.read.return_value = epss_sample_gz_bytes
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command._fetch_epss())

        assert len(rows) == 20
        row = next(r for r in rows if r["cve_id"] == "CVE-2024-12345")
        assert row["epss_score"] == "0.95432"
        assert row["epss_percentile"] == "0.99871"

    def test_skips_comment_lines(self, command, epss_sample_gz_bytes):
        mock_response = MagicMock()
        mock_response.read.return_value = epss_sample_gz_bytes
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command._fetch_epss())

        for row in rows:
            assert row["cve_id"].startswith("CVE-")


class TestGenerate:
    def test_mode_kev_only(self, command, kev_sample):
        command.mode = "kev"

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(kev_sample).encode("utf-8")
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command.generate())

        assert len(rows) == 3
        assert all("in_kev" in r for r in rows)

    def test_mode_epss_only(self, command, epss_sample_gz_bytes):
        command.mode = "epss"

        mock_response = MagicMock()
        mock_response.read.return_value = epss_sample_gz_bytes
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            rows = list(command.generate())

        assert len(rows) == 20
        assert all("epss_score" in r for r in rows)


@pytest.mark.live
class TestLiveFetch:
    def test_live_kev_fetch(self):
        cmd = CveicuepsskevCommand.__new__(CveicuepsskevCommand)
        cmd.mode = "kev"
        rows = list(cmd._fetch_kev())
        assert len(rows) > 100
        assert rows[0]["cve_id"].startswith("CVE-")
        assert rows[0]["in_kev"] == "true"

    def test_live_epss_fetch(self):
        cmd = CveicuepsskevCommand.__new__(CveicuepsskevCommand)
        cmd.mode = "epss"
        rows = list(cmd._fetch_epss())
        assert len(rows) > 1000
        assert rows[0]["cve_id"].startswith("CVE-")
