# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import io
import json
import pytest  # type: ignore

import scar_to_sarif.cli as cli


def test_main_ok_gcc_inline_data(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-1350]']
    report_expected = (
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "RTSL!", '
        '"fullName": "Read the Source, Luke!", "version": "2020.09", "rules": [{"id": '
        '"CWE1350", "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most '
        'Dangerous Software Weaknesses", "helpUri": '
        '"https://cwe.mitre.org/data/definitions/1350.html"}]}}, "conversion": '
        '{"tool": {"driver": {"name": "scars_to_sarif"}}, "invocation": {"arguments": '
        '["--"], "executionSuccessful": true, "commandLine": "--", "endTimeUtc": '
        '"2020-09-08T12:34:56Z", "workingDirectory": {"uri": "/home/ci/transform"}}}, '
        '"invocations": [{"executionSuccessful": true, "endTimeUtc": '
        '"2020-09-08T12:34:57Z", "workingDirectory": {"uri": "/home/ci/transform"}}], '
        '"versionControlProvenance": [{"repositoryUri": '
        '"https://ci.example.com/project/repo/", "revisionId": "cafefade", "branch": '
        '"default"}], "properties": {"metrics": {"total": 1, "error": 1, "warning": '
        '0}}, "results": [{"message": {"text": "The column 13 causes always trouble '
        'in line 42."}, "level": "error", "locations": [{"physicalLocation": '
        '{"region": {"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE1350", "ruleIndex": '
        '0}]}], "$schema": '
        '"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", '
        '"inlineExternalProperties": [{"guid": '
        '"0c9fe04f-9b74-4972-a82e-2099710a0ba1", "runGuid": '
        '"dce1bdf0-358b-4898-bedf-f297160f3b37"}]}\n'
    )
    assert cli.main(argv=job, inline_mode=True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_nok_direct_non_gcc_inline_text_gcc_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    report_expected = (
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "RTSL!", '
        '"fullName": "Read the Source, Luke!", "version": "2020.09", "rules": [{"id": '
        '"CWE1350", "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most '
        'Dangerous Software Weaknesses", "helpUri": '
        '"https://cwe.mitre.org/data/definitions/1350.html"}]}}, "conversion": '
        '{"tool": {"driver": {"name": "scars_to_sarif"}}, "invocation": {"arguments": '
        '["--"], "executionSuccessful": true, "commandLine": "--", "endTimeUtc": '
        '"2020-09-08T12:34:56Z", "workingDirectory": {"uri": "/home/ci/transform"}}}, '
        '"invocations": [{"executionSuccessful": true, "endTimeUtc": '
        '"2020-09-08T12:34:57Z", "workingDirectory": {"uri": "/home/ci/transform"}}], '
        '"versionControlProvenance": [{"repositoryUri": '
        '"https://ci.example.com/project/repo/", "revisionId": "cafefade", "branch": '
        '"default"}], "properties": {"metrics": {"total": 1, "error": 1, "warning": '
        '0}}, "results": []}], "$schema": '
        '"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", '
        '"inlineExternalProperties": [{"guid": '
        '"0c9fe04f-9b74-4972-a82e-2099710a0ba1", "runGuid": '
        '"dce1bdf0-358b-4898-bedf-f297160f3b37"}]}'
    )
    assert cli.main(job, inline_mode=True) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_ok_source_stdin_minimal(monkeypatch, capsys):
    document = '/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]'
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    job = ['--']
    report_expected = (
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "RTSL!", '
        '"fullName": "Read the Source, Luke!", "version": "2020.09", "rules": [{"id": '
        '"CWE1350", "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most '
        'Dangerous Software Weaknesses", "helpUri": '
        '"https://cwe.mitre.org/data/definitions/1350.html"}]}}, "conversion": '
        '{"tool": {"driver": {"name": "scars_to_sarif"}}, "invocation": {"arguments": '
        '["--"], "executionSuccessful": true, "commandLine": "--", "endTimeUtc": '
        '"2020-09-08T12:34:56Z", "workingDirectory": {"uri": "/home/ci/transform"}}}, '
        '"invocations": [{"executionSuccessful": true, "endTimeUtc": '
        '"2020-09-08T12:34:57Z", "workingDirectory": {"uri": "/home/ci/transform"}}], '
        '"versionControlProvenance": [{"repositoryUri": '
        '"https://ci.example.com/project/repo/", "revisionId": "cafefade", "branch": '
        '"default"}], "properties": {"metrics": {"total": 1, "error": 1, "warning": '
        '0}}, "results": [{"message": {"text": "The column 13 causes always trouble '
        'in line 42."}, "level": "error", "locations": [{"physicalLocation": '
        '{"region": {"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": '
        '0}]}], "$schema": '
        '"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", '
        '"inlineExternalProperties": [{"guid": '
        '"0c9fe04f-9b74-4972-a82e-2099710a0ba1", "runGuid": '
        '"dce1bdf0-358b-4898-bedf-f297160f3b37"}]}'
    )
    assert cli.main(job, inline_mode=True) == 0
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
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "RTSL!", '
        '"fullName": "Read the Source, Luke!", "version": "2020.09", "rules": [{"id": '
        '"CWE1350", "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most '
        'Dangerous Software Weaknesses", "helpUri": '
        '"https://cwe.mitre.org/data/definitions/1350.html"}]}}, "conversion": '
        '{"tool": {"driver": {"name": "scars_to_sarif"}}, "invocation": {"arguments": '
        '["--"], "executionSuccessful": true, "commandLine": "--", "endTimeUtc": '
        '"2020-09-08T12:34:56Z", "workingDirectory": {"uri": "/home/ci/transform"}}}, '
        '"invocations": [{"executionSuccessful": true, "endTimeUtc": '
        '"2020-09-08T12:34:57Z", "workingDirectory": {"uri": "/home/ci/transform"}}], '
        '"versionControlProvenance": [{"repositoryUri": '
        '"https://ci.example.com/project/repo/", "revisionId": "cafefade", "branch": '
        '"default"}], "properties": {"metrics": {"total": 1, "error": 1, "warning": '
        '0}}, "results": [{"message": {"text": "Message."}, "level": "error", '
        '"locations": [{"physicalLocation": {"region": {"startLine": 42, '
        '"startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0}, '
        '{"message": {"text": "Message."}, "level": "error", "locations": '
        '[{"physicalLocation": {"region": {"startLine": 42, "startColumn": 13}, '
        '"artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": '
        '0}]}], "$schema": '
        '"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", '
        '"inlineExternalProperties": [{"guid": '
        '"0c9fe04f-9b74-4972-a82e-2099710a0ba1", "runGuid": '
        '"dce1bdf0-358b-4898-bedf-f297160f3b37"}]}'
    )
    assert cli.main(job, inline_mode=False) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_nok_source_stdin_minimal_long_option_unsupported_write_format(monkeypatch, capsys):
    document = (
        '/a/path/file.ext:42:13: Error: Message. [CWE-0]\n'
        '/a/path/file.ext:42:13: Error: Message. [CWE-0]\n'
    )
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    unsupported_format_option = "--xml"
    job = ['--stdin', unsupported_format_option]
    report_expected = (
        f"Found unexpected option ({unsupported_format_option}) in arguments after option processing: ({unsupported_format_option})"
    )
    assert cli.main(job, inline_mode=False) == 2
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()
