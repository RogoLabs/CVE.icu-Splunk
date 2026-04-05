"""Unit tests for CVE V5 record processor."""

import pytest
from cveicu_lib.cve_processor import CVEProcessor


@pytest.fixture
def processor():
    return CVEProcessor(
        input_name="test_input",
        index="main",
        include_adp=True,
        include_rejected=True,
    )


@pytest.fixture
def processor_no_rejected():
    return CVEProcessor(
        input_name="test_input",
        index="main",
        include_adp=True,
        include_rejected=False,
    )


class TestProcessCVERecord:
    def test_published_record_extracts_core_fields(self, processor, cve_v5_samples):
        record = cve_v5_samples[0]
        result = processor.process_cve_record(record)

        assert result is not None
        assert result["cve_id"] == "CVE-2024-12345"
        assert result["state"] == "PUBLISHED"
        assert result["assigner"] == "microsoft"
        assert result["date_published"] == "2024-02-20T18:00:00.000Z"
        assert result["date_updated"] == "2024-03-01T12:00:00.000Z"

    def test_published_record_extracts_cna_fields(self, processor, cve_v5_samples):
        record = cve_v5_samples[0]
        result = processor.process_cve_record(record)

        assert result["title"] == "Remote Code Execution in Widget Service"
        assert (
            result["description"]
            == "A remote code execution vulnerability exists in Widget Service."
        )
        assert "Microsoft" in result["affected_vendor"]
        assert "Widget Service" in result["affected_product"]
        assert "CWE-79" in result["cwe_id"]
        assert "https://example.com/advisory/2024-001" in result["reference_url"]

    def test_published_record_extracts_cvss(self, processor, cve_v5_samples):
        record = cve_v5_samples[0]
        result = processor.process_cve_record(record)

        assert result["cvss_v31_score"] == 8.8
        assert result["cvss_v31_severity"] == "HIGH"

    def test_published_record_extracts_adp(self, processor, cve_v5_samples):
        record = cve_v5_samples[0]
        result = processor.process_cve_record(record)

        assert result["has_cisa_adp"] is True
        assert result["ssvc_exploitation"] == "active"
        assert result["ssvc_automatable"] == "yes"
        assert result["ssvc_technical_impact"] == "total"
        assert result["cisa_kev"] is True

    def test_rejected_record_included_when_configured(self, processor, cve_v5_samples):
        record = cve_v5_samples[1]
        result = processor.process_cve_record(record)

        assert result is not None
        assert result["cve_id"] == "CVE-2024-99999"
        assert result["state"] == "REJECTED"

    def test_rejected_record_skipped_when_configured(
        self, processor_no_rejected, cve_v5_samples
    ):
        record = cve_v5_samples[1]
        result = processor_no_rejected.process_cve_record(record)

        assert result is None
        assert processor_no_rejected.skipped_count == 1

    def test_minimal_record_no_cvss_no_cwe(self, processor, cve_v5_samples):
        record = cve_v5_samples[2]
        result = processor.process_cve_record(record)

        assert result is not None
        assert result["cve_id"] == "CVE-2024-00001"
        assert "cvss_v31_score" not in result
        assert "cwe_id" not in result

    def test_non_dict_input_skipped(self, processor):
        result = processor.process_cve_record(["not", "a", "dict"])
        assert result is None
        assert processor.skipped_count == 1

    def test_missing_metadata_skipped(self, processor):
        result = processor.process_cve_record({"dataType": "CVE_RECORD"})
        assert result is None
        assert processor.skipped_count == 1

    def test_stats_tracking(self, processor, cve_v5_samples):
        for record in cve_v5_samples:
            processor.process_cve_record(record)

        stats = processor.get_stats()
        assert stats["processed"] == 3
        assert stats["errors"] == 0

    def test_max_date_updated_tracked(self, processor, cve_v5_samples):
        for record in cve_v5_samples:
            processor.process_cve_record(record)

        stats = processor.get_stats()
        assert stats["max_date_updated"] == "2024-06-01T00:00:00.000Z"

    def test_reset_stats(self, processor, cve_v5_samples):
        processor.process_cve_record(cve_v5_samples[0])
        processor.reset_stats()

        stats = processor.get_stats()
        assert stats["processed"] == 0
        assert stats["max_date_updated"] is None
