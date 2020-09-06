# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import io
import json
import pytest  # type: ignore

import scar_to_sarif.cli as cli


def test_main_ok_gcc_data(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    report_expected = (
        '{"path": "/a/path/file.ext", "line": 42, "column": 13, "severity": "error", '
        '"message": "The column 13 causes always trouble in line 42.", "msg_code": '
        '"CWE-0"}\n'
    )
    assert cli.main(job, True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_nok_direct_non_gcc_text_gcc_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    report_expected = (
        ''
    )
    assert cli.main(job, True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_ok_source_stdin_minimal(monkeypatch, capsys):
    document = '/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]'
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    job = ['--']
    report_expected = (
        '{"path": "/a/path/file.ext", "line": 42, "column": 13, "severity": "error",'
        ' "message": "The column 13 causes always trouble in line 42.",'
        ' "msg_code": "CWE-0"}'
    )
    assert cli.main(job, True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_ok_source_stdin_minimal_long_option(monkeypatch, capsys):
    document = (
        '/a/path/file.ext:42:13: Error: Message. [CWE-0]\n'
        '/a/path/file.ext:42:13: Error: Message. [CWE-0]\n'
    )
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    job = ['--stdin']
    report_expected = (
        '{"path": "/a/path/file.ext", "line": 42, "column": 13, "severity": "error", '
        '"message": "Message.", "msg_code": "CWE-0"}\n'
        '{"path": "/a/path/file.ext", "line": 42, "column": 13, "severity": "error", '
        '"message": "Message.", "msg_code": "CWE-0"}')
    assert cli.main(job, True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()
