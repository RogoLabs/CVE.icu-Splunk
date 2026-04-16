"""Tests for --scheme introspection and XML sync."""

import os
import sys
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import pytest

# Path to the actual cveicu.py script
CVEICU_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "..", "TA-cveicu", "bin", "cveicu.py"
)

# The bin and lib directories for imports
BIN_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "TA-cveicu", "bin")
LIB_DIR = os.path.join(BIN_DIR, "lib")


def _normalize_element(elem):
    """Recursively normalize an XML element for order-independent comparison.

    Returns a tuple of (tag, sorted_attributes, stripped_text, sorted_children)
    that can be compared with ==.
    """
    text = (elem.text or "").strip()
    attribs = tuple(sorted(elem.attrib.items()))
    children = sorted(
        [_normalize_element(child) for child in elem],
        key=lambda c: (c[0], c[1], c[2]),  # sort by tag, attribs, text
    )
    return (elem.tag, attribs, text, tuple(children))


class TestSchemeXMLSync:
    """Verify the hardcoded --scheme XML stays in sync with get_scheme()."""

    def test_hardcoded_xml_matches_get_scheme(self):
        """Parse both XML sources and compare structure, ignoring element order."""
        # Get hardcoded XML by running --scheme as a subprocess
        result = subprocess.run(
            [sys.executable, CVEICU_SCRIPT, "--scheme"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": f"{LIB_DIR}:{BIN_DIR}"},
            timeout=10,
        )
        assert result.returncode == 0, f"--scheme failed: {result.stderr}"
        hardcoded_xml = result.stdout.strip()

        # Get scheme XML from the class method
        sys.path.insert(0, LIB_DIR)
        sys.path.insert(0, BIN_DIR)
        try:
            from splunklib.modularinput import Script, Scheme, Argument

            # Import the module without triggering __main__
            # Use a unique name to avoid sys.modules cache conflicts
            import importlib.util

            mod_name = "_cveicu_scheme_test"
            spec = importlib.util.spec_from_file_location(mod_name, CVEICU_SCRIPT)
            module = importlib.util.module_from_spec(spec)
            # Don't set __name__ to __main__ so --scheme doesn't trigger
            spec.loader.exec_module(module)

            scheme_obj = module.CVEListV5Input().get_scheme()
            if scheme_obj is None:
                pytest.skip(
                    "get_scheme() returned None — splunklib Scheme not "
                    "available in this environment"
                )
            method_xml = ET.tostring(scheme_obj.to_xml(), encoding="unicode")
        finally:
            sys.modules.pop(mod_name, None)
            if LIB_DIR in sys.path:
                sys.path.remove(LIB_DIR)
            if BIN_DIR in sys.path:
                sys.path.remove(BIN_DIR)

        # Parse both into element trees
        hardcoded_tree = ET.fromstring(hardcoded_xml)
        method_tree = ET.fromstring(method_xml)

        # Compare normalized structures (order-independent)
        hardcoded_norm = _normalize_element(hardcoded_tree)
        method_norm = _normalize_element(method_tree)

        assert hardcoded_norm == method_norm, (
            f"Hardcoded --scheme XML does not match get_scheme().to_xml().\n"
            f"Hardcoded:\n{hardcoded_xml}\n\n"
            f"get_scheme():\n{method_xml}"
        )

    def test_hardcoded_xml_is_valid(self):
        """The hardcoded XML must parse without errors."""
        result = subprocess.run(
            [sys.executable, CVEICU_SCRIPT, "--scheme"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": f"{LIB_DIR}:{BIN_DIR}"},
            timeout=10,
        )
        assert result.returncode == 0
        root = ET.fromstring(result.stdout)
        assert root.tag == "scheme"

    def test_hardcoded_xml_is_ascii_only(self):
        """The scheme XML must be pure ASCII to avoid encoding issues."""
        result = subprocess.run(
            [sys.executable, CVEICU_SCRIPT, "--scheme"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": f"{LIB_DIR}:{BIN_DIR}"},
            timeout=10,
        )
        assert result.returncode == 0
        try:
            result.stdout.encode("ascii")
        except UnicodeEncodeError as e:
            pytest.fail(f"Scheme XML contains non-ASCII characters: {e}")

    def test_scheme_has_required_elements(self):
        """All required scheme elements are present."""
        result = subprocess.run(
            [sys.executable, CVEICU_SCRIPT, "--scheme"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": f"{LIB_DIR}:{BIN_DIR}"},
            timeout=10,
        )
        assert result.returncode == 0
        root = ET.fromstring(result.stdout)

        assert root.find("title").text == "cve.icu"
        assert root.find("use_external_validation").text == "false"
        assert root.find("use_single_instance").text == "false"
        assert root.find("streaming_mode").text == "xml"

        # Check all three arguments exist
        args = root.findall(".//arg")
        arg_names = {arg.get("name") for arg in args}
        assert arg_names == {"include_adp", "include_rejected", "batch_size"}


class TestSchemeImportFailure:
    """Verify --scheme works even when imports would fail."""

    def test_scheme_succeeds_with_broken_ssl(self):
        """--scheme must succeed even when ssl is poisoned."""
        # Create a sitecustomize.py that poisons ssl
        with tempfile.TemporaryDirectory() as tmpdir:
            sitecustomize = os.path.join(tmpdir, "sitecustomize.py")
            with open(sitecustomize, "w") as f:
                f.write("import sys; sys.modules['ssl'] = None\n")

            result = subprocess.run(
                [sys.executable, CVEICU_SCRIPT, "--scheme"],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PYTHONPATH": tmpdir,
                },
                timeout=10,
            )
            assert result.returncode == 0, (
                f"--scheme failed with poisoned ssl: {result.stderr}"
            )
            root = ET.fromstring(result.stdout)
            assert root.tag == "scheme"

    def test_scheme_succeeds_with_no_splunklib(self):
        """--scheme must succeed even when splunklib is not importable."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sitecustomize = os.path.join(tmpdir, "sitecustomize.py")
            with open(sitecustomize, "w") as f:
                f.write(
                    "import sys; sys.modules['splunklib'] = None; "
                    "sys.modules['splunklib.modularinput'] = None\n"
                )

            result = subprocess.run(
                [sys.executable, CVEICU_SCRIPT, "--scheme"],
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PYTHONPATH": tmpdir,
                },
                timeout=10,
            )
            assert result.returncode == 0, (
                f"--scheme failed without splunklib: {result.stderr}"
            )
            root = ET.fromstring(result.stdout)
            assert root.tag == "scheme"

    def test_runtime_without_scheme_fails_with_diagnostics_on_import_error(self):
        """When NOT using --scheme, import failures produce diagnostic messages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Poison splunklib so the import in cveicu.py fails even though
            # the script adds its own bin/lib to sys.path.  sitecustomize.py
            # runs before the script, so sys.modules entries take precedence.
            sitecustomize = os.path.join(tmpdir, "sitecustomize.py")
            with open(sitecustomize, "w") as f:
                f.write(
                    "import sys\n"
                    "# Make splunklib un-importable\n"
                    "class _Blocker:\n"
                    "    def __getattr__(self, name):\n"
                    "        raise ImportError('blocked by test')\n"
                    "sys.modules['splunklib'] = _Blocker()\n"
                    "sys.modules['splunklib.modularinput'] = _Blocker()\n"
                )

            result = subprocess.run(
                [sys.executable, CVEICU_SCRIPT],
                capture_output=True,
                text=True,
                env={
                    "PYTHONPATH": tmpdir,
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", ""),
                },
                timeout=10,
            )
            assert result.returncode == 1
            assert "ERROR TA-cveicu" in result.stderr
            assert "Failed to import" in result.stderr
