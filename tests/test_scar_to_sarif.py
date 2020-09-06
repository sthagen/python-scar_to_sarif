# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import json
import pytest  # type: ignore

import scar_to_sarif.scar_to_sarif as sts


def test_parse_ok_unknown_read_format():
    job = ['[]']
    parser = sts.parse(job)
    assert next(parser) == NotImplemented


def test_parse_nok_mismatch_as_gcc_format():
    job = ['This is not the gcc format.']
    parser = sts.parse(job, sts.GCC_FORMAT_CODE)
    assert next(parser) == {}


def test_parse_nok_direct_json_text():
    job = ['{"a": "b", "c": 42, "d": [1, true, false, null, 3.1415, -999999999999999999999]}']
    parser = sts.parse(job)
    assert next(parser) == NotImplemented


def test_scan_ok_direct_gcc_text():
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    scanner = sts.scan(job)
    assert next(scanner) == job[0]


def test_detect_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    assert sts.detect(job[0]) == sts.GCC_FORMAT_CODE
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_detect_ok_direct_non_gcc_text_default_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    assert sts.detect(job[0]) == sts.UNKNOWN_FORMAT_CODE
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_parse_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    data = {'path': '/a/path/file.ext', 'line': 42, 'column': 13, 'severity': 'error', 'message': 'The column 13 causes always trouble in line 42.', 'msg_code': 'CWE-0'}
    parser = sts.parse(job, sts.GCC_FORMAT_CODE)
    assert next(parser) == data
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_detect_nok_direct_non_gcc_text_gcc_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    parser = sts.parse(job, sts.GCC_FORMAT_CODE)
    assert next(parser) == {}
    out, err = capsys.readouterr()
    assert out.strip() == ''
