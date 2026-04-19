#!/usr/bin/env python3
"""Take screenshots of all TA-cveicu dashboards on Splunk 9.4."""

import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

BASE_URL = "http://localhost:18000"
USERNAME = "admin"
PASSWORD = "testpassword123"
OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "docs", "screenshots"
)

DASHBOARDS = [
    ("cve_explorer", "cve-explorer.png"),
    ("risk_priority", "risk-priority.png"),
    ("vulnerability_landscape", "vulnerability-landscape.png"),
    ("operational_health", "operational-health.png"),
]

FILTERED_SCREENSHOTS = [
    {
        "dashboard": "cve_explorer",
        "filename": "cve-explorer-filtered.png",
        "params": "form.vendor_filter=Microsoft&form.severity_filter=severity%3DCRITICAL&form.cwe_filter=*",
    },
    {
        "dashboard": "risk_priority",
        "filename": "risk-priority-kev.png",
        "params": "form.epss_filter=tonumber(epss_score)%20%3E%200.5&form.kev_filter=in_kev%3D%22true%22",
    },
]


def setup_driver():
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--window-size=1920,1200")
    opts.add_argument("--force-device-scale-factor=2")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-gpu")
    driver = webdriver.Chrome(options=opts)
    return driver


def login(driver):
    driver.get(f"{BASE_URL}/en-US/account/login")
    time.sleep(2)
    driver.find_element(By.ID, "username").send_keys(USERNAME)
    driver.find_element(By.ID, "password").send_keys(PASSWORD)
    driver.find_element(By.CSS_SELECTOR, "input[type='submit']").click()
    time.sleep(3)


def wait_for_dashboard(driver, timeout=60):
    """Wait for dashboard searches to complete."""
    time.sleep(5)
    for _ in range(timeout // 5):
        progress_bars = driver.find_elements(
            By.CSS_SELECTOR, ".search-progress, .progress-bar"
        )
        spinners = driver.find_elements(
            By.CSS_SELECTOR, ".search-loader, .wait-spinner"
        )
        active = [el for el in progress_bars + spinners if el.is_displayed()]
        if not active:
            time.sleep(3)
            return True
        time.sleep(5)
    return False


def take_screenshot(driver, url, filename):
    driver.get(url)
    wait_for_dashboard(driver)

    total_height = driver.execute_script("return document.body.scrollHeight")
    viewport_height = driver.execute_script("return window.innerHeight")
    driver.set_window_size(1920, max(total_height + 200, viewport_height))
    time.sleep(2)

    filepath = os.path.join(OUTPUT_DIR, filename)
    driver.save_screenshot(filepath)
    size_kb = os.path.getsize(filepath) / 1024
    print(f"  Saved: {filename} ({size_kb:.0f} KB)")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Starting browser...")
    driver = setup_driver()

    try:
        print("Logging in to Splunk...")
        login(driver)

        print("\nTaking default dashboard screenshots...")
        for dashboard, filename in DASHBOARDS:
            url = f"{BASE_URL}/en-US/app/TA-cveicu/{dashboard}"
            print(f"  Loading {dashboard}...")
            take_screenshot(driver, url, filename)

        print("\nTaking filtered screenshots...")
        for item in FILTERED_SCREENSHOTS:
            url = f"{BASE_URL}/en-US/app/TA-cveicu/{item['dashboard']}?{item['params']}"
            print(f"  Loading {item['dashboard']} (filtered)...")
            take_screenshot(driver, url, item["filename"])

        print("\nAll screenshots captured!")
    finally:
        driver.quit()


if __name__ == "__main__":
    main()
