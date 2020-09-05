# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import json
import pytest  # type: ignore

import scar_to_sarif.scar_to_sarif as sts


def test_parse_ok_empty_array():
    job = ['[]']
    assert sts.parse(job) == job[0]


def test_parse_ok_empty_object():
    job = ['{}']
    assert sts.parse(job) == job[0]


def test_parse_ok_direct_json_text(capsys):
    job = ['{"a": "b", "c": 42, "d": [1, true, false, null, 3.1415, -999999999999999999999]}']
    assert sts.parse(job) == job[0]


def test_scan_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    assert sts.scan(job) == job[0]


def test_detect_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    assert sts.detect(job) == "gcc"


def test_parse_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    data = {'path': '/a/path/file.ext', 'line': 42, 'column': 13, 'severity': 'error', 'message': 'The column 13 causes always trouble in line 42.', 'msg_code': 'CWE-0'}
    assert sts.parse(job) == data

