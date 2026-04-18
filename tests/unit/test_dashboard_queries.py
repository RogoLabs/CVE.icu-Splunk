"""Validate dashboard SPL queries reference correct lookup fields and exist.

These tests parse every dashboard JSON definition and every saved search,
then check that any `| lookup <file> <field>` or `| inputlookup <file>`
usage references real lookup files with real column names. This catches
bugs like the v2.0.3 fix where a dashboard tried to join on a field
that didn't exist in the target lookup.
"""

import csv
import json
import os
import re
from xml.etree import ElementTree

import pytest

ADDON_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "TA-cveicu")
VIEWS_DIR = os.path.join(ADDON_DIR, "default", "data", "ui", "views")
LOOKUPS_DIR = os.path.join(ADDON_DIR, "lookups")
SAVEDSEARCHES_CONF = os.path.join(ADDON_DIR, "default", "savedsearches.conf")


def _get_lookup_schemas():
    """Read the header row of every CSV in lookups/ to get column names."""
    schemas = {}
    for fname in os.listdir(LOOKUPS_DIR):
        if not fname.endswith(".csv"):
            continue
        path = os.path.join(LOOKUPS_DIR, fname)
        with open(path, newline="") as f:
            reader = csv.reader(f)
            try:
                headers = next(reader)
            except StopIteration:
                headers = []
        schemas[fname] = [h.strip() for h in headers]
    return schemas


def _parse_dashboard_queries(xml_path):
    """Extract all SPL queries from a Dashboard Studio v2 XML file."""
    tree = ElementTree.parse(xml_path)
    root = tree.getroot()
    definition_el = root.find(".//definition")
    if definition_el is None or not definition_el.text:
        return []

    dashboard = json.loads(definition_el.text.strip())
    queries = []
    for ds_name, ds_def in dashboard.get("dataSources", {}).items():
        query = ds_def.get("options", {}).get("query", "")
        if query:
            queries.append((ds_name, query))
    return queries


def _parse_saved_search_queries(conf_path):
    """Extract saved search names and their SPL from savedsearches.conf."""
    searches = []
    current_name = None
    current_search_lines = []

    with open(conf_path) as f:
        for line in f:
            line = line.rstrip("\n")
            stanza = re.match(r"^\[(.+)\]$", line)
            if stanza:
                if current_name and current_search_lines:
                    searches.append((current_name, " ".join(current_search_lines)))
                current_name = stanza.group(1)
                current_search_lines = []
                continue

            search_match = re.match(r"^search\s*=\s*(.*)", line)
            if search_match:
                current_search_lines = [search_match.group(1).rstrip("\\").strip()]
                continue

            if current_search_lines and line.startswith((" ", "\t")):
                current_search_lines.append(line.strip().rstrip("\\").strip())

    if current_name and current_search_lines:
        searches.append((current_name, " ".join(current_search_lines)))
    return searches


def _find_lookup_joins(spl):
    """Find `| lookup <file.csv> <field>` patterns in SPL.

    Returns list of (lookup_file, join_field) tuples.
    """
    pattern = r"\|\s*lookup\s+(\S+\.csv)\s+(\w+)"
    return re.findall(pattern, spl)


def _find_inputlookup_field_refs(spl):
    """Find fields referenced after `| inputlookup <file.csv>`.

    Extracts field names used in where/eval/stats/sort/by clauses
    that should exist in the lookup.
    Returns list of (lookup_file, [fields]) tuples.
    """
    results = []
    inputlookup_pattern = r"\|\s*inputlookup\s+(\S+\.csv)"
    for match in re.finditer(inputlookup_pattern, spl):
        lookup_file = match.group(1)
        after = spl[match.end() :]
        next_pipe = after.find("|")
        if next_pipe == -1:
            segment = after
        else:
            segment = after[:next_pipe]
        results.append((lookup_file, segment))
    return results


# --- Fixtures ---


@pytest.fixture(scope="module")
def lookup_schemas():
    return _get_lookup_schemas()


@pytest.fixture(scope="module")
def all_dashboard_queries():
    queries = {}
    if not os.path.isdir(VIEWS_DIR):
        return queries
    for fname in os.listdir(VIEWS_DIR):
        if not fname.endswith(".xml"):
            continue
        path = os.path.join(VIEWS_DIR, fname)
        dashboard_name = fname.replace(".xml", "")
        queries[dashboard_name] = _parse_dashboard_queries(path)
    return queries


@pytest.fixture(scope="module")
def all_saved_searches():
    if not os.path.isfile(SAVEDSEARCHES_CONF):
        return []
    return _parse_saved_search_queries(SAVEDSEARCHES_CONF)


# --- Tests ---


class TestLookupFilesExist:
    """Every lookup file referenced in dashboards or saved searches must exist."""

    def test_dashboard_inputlookup_files_exist(
        self, all_dashboard_queries, lookup_schemas
    ):
        missing = []
        for dashboard, queries in all_dashboard_queries.items():
            for ds_name, spl in queries:
                for match in re.finditer(r"\|\s*inputlookup\s+(\S+\.csv)", spl):
                    lookup_file = match.group(1)
                    if lookup_file not in lookup_schemas:
                        missing.append(
                            f"{dashboard}/{ds_name}: inputlookup {lookup_file}"
                        )
        assert not missing, (
            f"Dashboard queries reference non-existent lookups:\n" + "\n".join(missing)
        )

    def test_saved_search_outputlookup_files_are_known(
        self, all_saved_searches, lookup_schemas
    ):
        unknown = []
        for name, spl in all_saved_searches:
            for match in re.finditer(r"\|\s*outputlookup\s+(\S+\.csv)", spl):
                lookup_file = match.group(1)
                if lookup_file not in lookup_schemas:
                    unknown.append(f"[{name}]: outputlookup {lookup_file}")
        assert not unknown, f"Saved searches output to unknown lookups:\n" + "\n".join(
            unknown
        )


class TestLookupJoinFields:
    """When a query does `| lookup foo.csv field_name`, that field must exist in foo.csv."""

    def test_dashboard_lookup_join_fields_exist(
        self, all_dashboard_queries, lookup_schemas
    ):
        errors = []
        for dashboard, queries in all_dashboard_queries.items():
            for ds_name, spl in queries:
                for lookup_file, join_field in _find_lookup_joins(spl):
                    if lookup_file not in lookup_schemas:
                        continue
                    if join_field not in lookup_schemas[lookup_file]:
                        errors.append(
                            f"{dashboard}/{ds_name}: "
                            f"'| lookup {lookup_file} {join_field}' — "
                            f"field '{join_field}' not in {lookup_file} "
                            f"(has: {lookup_schemas[lookup_file]})"
                        )
        assert not errors, (
            "Dashboard lookup joins reference missing fields:\n" + "\n".join(errors)
        )

    def test_saved_search_lookup_join_fields_exist(
        self, all_saved_searches, lookup_schemas
    ):
        errors = []
        for name, spl in all_saved_searches:
            for lookup_file, join_field in _find_lookup_joins(spl):
                if lookup_file not in lookup_schemas:
                    continue
                if join_field not in lookup_schemas[lookup_file]:
                    errors.append(
                        f"[{name}]: "
                        f"'| lookup {lookup_file} {join_field}' — "
                        f"field '{join_field}' not in {lookup_file} "
                        f"(has: {lookup_schemas[lookup_file]})"
                    )
        assert not errors, (
            "Saved search lookup joins reference missing fields:\n" + "\n".join(errors)
        )


class TestDashboardDataSources:
    """Every visualization must reference a defined data source."""

    def test_all_viz_datasources_are_defined(self, all_dashboard_queries):
        errors = []
        for fname in os.listdir(VIEWS_DIR):
            if not fname.endswith(".xml"):
                continue
            tree = ElementTree.parse(os.path.join(VIEWS_DIR, fname))
            definition_el = tree.getroot().find(".//definition")
            if definition_el is None or not definition_el.text:
                continue
            dashboard = json.loads(definition_el.text.strip())
            ds_names = set(dashboard.get("dataSources", {}).keys())
            for viz_name, viz_def in dashboard.get("visualizations", {}).items():
                for role, ds_ref in viz_def.get("dataSources", {}).items():
                    if ds_ref not in ds_names:
                        errors.append(
                            f"{fname}/{viz_name}: references undefined dataSource '{ds_ref}'"
                        )
        assert not errors, (
            "Visualizations reference undefined data sources:\n" + "\n".join(errors)
        )


class TestSavedSearchOutputLookupSchema:
    """Saved search output fields must match lookup CSV headers.

    Verifies that the fields a saved search pipes into outputlookup
    match the expected lookup schema (from the CSV header row).
    """

    def _extract_table_fields(self, spl):
        """Extract fields from the last `| table` before `| outputlookup`."""
        table_match = re.search(r"\|\s*table\s+([^|]+)\|\s*outputlookup", spl)
        if table_match:
            return [f.strip() for f in table_match.group(1).split() if f.strip()]
        return None

    def test_output_fields_match_csv_headers(self, all_saved_searches, lookup_schemas):
        errors = []
        for name, spl in all_saved_searches:
            for match in re.finditer(r"\|\s*outputlookup\s+(\S+\.csv)", spl):
                lookup_file = match.group(1)
                if lookup_file not in lookup_schemas:
                    continue
                table_fields = self._extract_table_fields(spl)
                if table_fields is None:
                    continue
                csv_fields = set(lookup_schemas[lookup_file])
                spl_fields = set(table_fields)
                extra = spl_fields - csv_fields
                if extra:
                    errors.append(
                        f"[{name}] → {lookup_file}: "
                        f"SPL outputs fields {extra} not in CSV header {csv_fields}"
                    )
        assert not errors, (
            "Saved search output fields don't match lookup schema:\n"
            + "\n".join(errors)
        )


class TestDashboardStructure:
    """Validate dashboard JSON structure is well-formed."""

    def test_all_dashboards_parse_as_valid_json(self):
        errors = []
        for fname in os.listdir(VIEWS_DIR):
            if not fname.endswith(".xml"):
                continue
            tree = ElementTree.parse(os.path.join(VIEWS_DIR, fname))
            definition_el = tree.getroot().find(".//definition")
            if definition_el is None or not definition_el.text:
                continue
            try:
                json.loads(definition_el.text.strip())
            except json.JSONDecodeError as e:
                errors.append(f"{fname}: invalid JSON — {e}")
        assert not errors, "Dashboard JSON parse errors:\n" + "\n".join(errors)

    def test_all_layout_items_reference_defined_visualizations(self):
        errors = []
        for fname in os.listdir(VIEWS_DIR):
            if not fname.endswith(".xml"):
                continue
            tree = ElementTree.parse(os.path.join(VIEWS_DIR, fname))
            definition_el = tree.getroot().find(".//definition")
            if definition_el is None or not definition_el.text:
                continue
            dashboard = json.loads(definition_el.text.strip())
            viz_names = set(dashboard.get("visualizations", {}).keys())
            for item in dashboard.get("layout", {}).get("structure", []):
                item_name = item.get("item")
                if item_name and item_name not in viz_names:
                    errors.append(
                        f"{fname}: layout references undefined viz '{item_name}'"
                    )
        assert not errors, "Layout references undefined visualizations:\n" + "\n".join(
            errors
        )

    def test_no_queries_reference_undefined_macros(self):
        """Check that macros used in SPL (backtick syntax) are defined."""
        macros_conf = os.path.join(ADDON_DIR, "default", "macros.conf")
        defined_macros = set()
        if os.path.isfile(macros_conf):
            with open(macros_conf) as f:
                for line in f:
                    m = re.match(r"^\[(.+)\]$", line.strip())
                    if m:
                        defined_macros.add(m.group(1))

        errors = []
        for fname in os.listdir(VIEWS_DIR):
            if not fname.endswith(".xml"):
                continue
            tree = ElementTree.parse(os.path.join(VIEWS_DIR, fname))
            definition_el = tree.getroot().find(".//definition")
            if definition_el is None or not definition_el.text:
                continue
            dashboard = json.loads(definition_el.text.strip())
            for ds_name, ds_def in dashboard.get("dataSources", {}).items():
                query = ds_def.get("options", {}).get("query", "")
                for macro_match in re.finditer(r"`(\w+)`", query):
                    macro_name = macro_match.group(1)
                    if macro_name not in defined_macros:
                        errors.append(
                            f"{fname}/{ds_name}: uses undefined macro `{macro_name}`"
                        )
        assert not errors, "Dashboard queries use undefined macros:\n" + "\n".join(
            errors
        )
