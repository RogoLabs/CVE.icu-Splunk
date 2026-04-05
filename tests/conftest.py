"""Shared test configuration and fixtures."""

import os
import sys
import json
import gzip
import pytest

# Add the TA's bin directory to sys.path so we can import cveicu_lib modules
# without needing splunklib installed (unit tests mock it)
BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "TA-cveicu", "bin")
LIB_DIR = os.path.join(BIN_DIR, "lib")
sys.path.insert(0, BIN_DIR)
sys.path.insert(0, LIB_DIR)

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def pytest_addoption(parser):
    parser.addoption(
        "--live",
        action="store_true",
        default=False,
        help="Run tests that hit live external APIs (FIRST EPSS, CISA KEV)",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "live: mark test as requiring live API access")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--live"):
        skip_live = pytest.mark.skip(reason="need --live option to run")
        for item in items:
            if "live" in item.keywords:
                item.add_marker(skip_live)


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def cve_v5_samples():
    with open(os.path.join(FIXTURES_DIR, "cve_v5_sample.json")) as f:
        return json.load(f)


@pytest.fixture
def kev_sample():
    with open(os.path.join(FIXTURES_DIR, "kev_sample.json")) as f:
        return json.load(f)


@pytest.fixture
def epss_sample_gz_bytes():
    with open(os.path.join(FIXTURES_DIR, "epss_sample.csv.gz"), "rb") as f:
        return f.read()
