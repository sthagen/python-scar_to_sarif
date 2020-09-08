# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import json
import sys

import pytest  # type: ignore

import jsonschema  # type: ignore

ENCODING = "utf-8"
SARIF_JSON_SCHEMA = 'tests/fixtures/sarif-schema-2.1.0.json'
SARIF_REPORT_SAMPLE = 'tests/fixtures/some-report.sarif.json'


def _load(file_path):
    """Create JSON object from file."""
    with open(file_path, "rt", encoding=ENCODING) as handle:
        return json.load(handle)


def _validate(document, schema, conformance=None):
    """Validate the document against the schema."""
    conformance = conformance if conformance else jsonschema.draft7_format_checker
    return jsonschema.validate(document, schema, format_checker=conformance)


def test_sarif_fixture(capsys):
    """Validate the example sarif document against local copy of the v2.1.0 schema."""
    schema = _load(SARIF_JSON_SCHEMA)
    document = _load(SARIF_REPORT_SAMPLE)

    assert _validate(document, schema) is None
    out, err = capsys.readouterr()
    assert out.strip() == ''
