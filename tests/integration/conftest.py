"""Integration test fixtures — manages Docker Splunk lifecycle."""

import os
import time
import subprocess
import pytest
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed Splunk cert
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

COMPOSE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "..", "docker-compose.test.yml"
)
SPLUNK_URL = "https://localhost:18089"
SPLUNK_USER = "admin"
SPLUNK_PASSWORD = "testpassword123"
STARTUP_TIMEOUT = 300  # 5 minutes max wait


def _splunk_is_ready():
    """Check if Splunk is ready to accept requests."""
    try:
        resp = requests.get(
            f"{SPLUNK_URL}/services/server/health",
            auth=(SPLUNK_USER, SPLUNK_PASSWORD),
            verify=False,
            timeout=5,
        )
        return resp.status_code == 200
    except (requests.ConnectionError, requests.Timeout):
        return False


def _wait_for_splunk():
    """Poll until Splunk is ready or timeout is reached."""
    start = time.time()
    while time.time() - start < STARTUP_TIMEOUT:
        if _splunk_is_ready():
            return True
        time.sleep(5)
    return False


@pytest.fixture(scope="session")
def splunk_service():
    """Start Splunk container, wait for ready, yield connection info, tear down."""
    # Start container
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "up", "-d", "--wait"],
        check=True,
        capture_output=True,
    )

    # Wait for Splunk REST API
    if not _wait_for_splunk():
        # Capture logs for debugging
        logs = subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "logs"],
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "down", "-v"],
            capture_output=True,
        )
        pytest.fail(
            f"Splunk did not start within {STARTUP_TIMEOUT}s.\nLogs:\n{logs.stdout}"
        )

    yield {
        "url": SPLUNK_URL,
        "username": SPLUNK_USER,
        "password": SPLUNK_PASSWORD,
    }

    # Tear down
    subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "down", "-v"],
        capture_output=True,
    )


@pytest.fixture
def splunk_api(splunk_service):
    """Return a helper for making Splunk REST API calls."""

    class SplunkAPI:
        def __init__(self, service_info):
            self.url = service_info["url"]
            self.auth = (service_info["username"], service_info["password"])

        def get(self, path, **kwargs):
            return requests.get(
                f"{self.url}{path}",
                auth=self.auth,
                verify=False,
                **kwargs,
            )

        def post(self, path, **kwargs):
            return requests.post(
                f"{self.url}{path}",
                auth=self.auth,
                verify=False,
                **kwargs,
            )

        def delete(self, path, **kwargs):
            return requests.delete(
                f"{self.url}{path}",
                auth=self.auth,
                verify=False,
                **kwargs,
            )

        def run_search(self, query, timeout=120):
            """Run a one-shot search and return results."""
            resp = self.post(
                "/services/search/jobs",
                data={
                    "search": query,
                    "exec_mode": "oneshot",
                    "output_mode": "json",
                    "timeout": timeout,
                },
            )
            resp.raise_for_status()
            return resp.json()

        def run_search_async(self, query, timeout=300):
            """Create a search job and wait for completion."""
            # Create job
            resp = self.post(
                "/services/search/jobs",
                data={
                    "search": query,
                    "output_mode": "json",
                },
            )
            resp.raise_for_status()
            sid = resp.json()["sid"]

            # Poll for completion
            start = time.time()
            while time.time() - start < timeout:
                status = self.get(
                    f"/services/search/jobs/{sid}",
                    params={"output_mode": "json"},
                )
                status.raise_for_status()
                entry = status.json()["entry"][0]["content"]
                if entry["dispatchState"] == "DONE":
                    # Get results
                    results = self.get(
                        f"/services/search/jobs/{sid}/results",
                        params={"output_mode": "json", "count": 0},
                    )
                    results.raise_for_status()
                    return results.json()
                elif entry["dispatchState"] == "FAILED":
                    pytest.fail(
                        f"Search failed: {entry.get('messages', 'unknown error')}"
                    )
                time.sleep(2)

            pytest.fail(f"Search did not complete within {timeout}s")

    return SplunkAPI(splunk_service)
