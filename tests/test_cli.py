# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import io
import json
import pytest  # type: ignore

import scar_to_sarif.cli as cli
import scar_to_sarif.scar_to_sarif as sts


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


def test_main_ok_source_stdin_minimal_streaming(monkeypatch, capsys):
    document = '/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]'
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    job = ['--']
    report_expected = (
        '{ "version": "2.1.0", "runs": [ { "versionControlProvenance": [ { '
        '"repositoryUri": "https://ci.example.com/project/repo/", "revisionId": '
        '"cafefade", "branch": "default" } ], "results": [{"message": {"text": "The '
        'column 13 causes always trouble in line 42."}, "level": "error", '
        '"locations": [{"physicalLocation": {"region": {"startLine": 42, '
        '"startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0}], '
        '"properties": { "metrics": { "total": 1, "error": 1, "warning": 0 } }, '
        '"tool": { "driver": { "name": "RTSL!", "fullName": "Read the Source, Luke!", '
        '"version": "2020.09", "rules": [ { "id": "CWE1350", "name": "CWE VIEW: '
        'Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses", '
        '"helpUri": "https://cwe.mitre.org/data/definitions/1350.html" } ] } }, '
        '"conversion": { "tool": { "driver": { "name": "scars_to_sarif" } }, '
        '"invocation": { "arguments": [ "--" ], "executionSuccessful": True, '
        '"commandLine": "--", "endTimeUtc": "2020-09-08T12:34:56Z", '
        '"workingDirectory": { "uri": "/home/ci/transform" } } }, "invocations": [ { '
        '"executionSuccessful": True, "endTimeUtc": "2020-09-08T12:34:57Z", '
        '"workingDirectory": { "uri": "/home/ci/transform" } } ] } ], "$schema": '
        '"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", '
        '"inlineExternalProperties": [ { "guid": '
        '"0c9fe04f-9b74-4972-a82e-2099710a0ba1", "runGuid": '
        '"dce1bdf0-358b-4898-bedf-f297160f3b37" } ] }'
    )
    assert cli.main(job, inline_mode=True, streaming_mode=True) == 0
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
    document = ''
    monkeypatch.setattr('sys.stdin', io.StringIO(document))
    unsupported_format_option = "--xml"
    job = ['--stdin', unsupported_format_option]
    arguments = ', '.join(f"'{arg}'" for arg in job[1:])
    report_expected = (
        f"Found unexpected option ({unsupported_format_option}) in arguments after option processing: ({arguments})"
    )
    assert cli.main(job, inline_mode=False) == 2
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_nok_source_inline_unsupported_write_format(capsys):
    document = ''
    unsupported_format_option = "--xml"
    job = [document, unsupported_format_option]
    arguments = ', '.join(f"'{arg}'" for arg in job)
    report_expected = (
        f"Found unexpected option ({unsupported_format_option}) in arguments after option processing: ({arguments})"
    )
    assert cli.main(job, inline_mode=True) == 2
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_nok_source_inline_too_many_write_formats(capsys):
    document = ''
    write_format_options = [f'--{opt}' for opt in sts.SUPPORTED_WRITE_FORMATS]
    job = [document, *write_format_options]
    arguments = ', '.join(f"'{arg}'" for arg in (document, *write_format_options[1:]))
    too_many = f'{", ".join(option for option in write_format_options[1:])}'
    report_expected = (
        f"Found unexpected options ({too_many}) in arguments after option processing: ({arguments})"
    )
    assert cli.main(job, inline_mode=True) == 2
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_report_nok_unsupported_write_format(capsys):
    data = ['some text being not processed']
    unsupported_write_format = "xml"
    report_expected = (
        f"Found unexpected write format ({unsupported_write_format}) option"
    )
    assert cli.report(data, write_format=unsupported_write_format) is None
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_report_ok_unimplemented_write_format(capsys):
    data = ['some text passing through']
    unimplemented_write_format = sts.HTML_WRITE_FORMAT
    report_expected = (
        f"Write format {unimplemented_write_format} not yet implemented."
    )
    assert cli.report(data, write_format=unimplemented_write_format) is None
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_report_ok_inline_gcc_read_unix_write_format(capsys):
    data = ['a:4:1: E: T [0]']
    report_expected = (
        f"a:4:1: E: T [0]"
    )
    assert cli.report(data, write_format=sts.UNIX_WRITE_FORMAT) is None
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_report_ok_inline_gcc_read_unix_write_format_streaming(capsys):
    data = ['a:4:1: E: T [0]']
    report_expected = (
        f"a:4:1: E: T [0]"
    )
    assert cli.report(data, write_format=sts.UNIX_WRITE_FORMAT, streaming_mode=True) is None
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()


def test_main_ok_inline_gcc_read_unix_write_format_streaming(capsys):
    data = ['a:4:1: E: T [0]', '--inline', f'--{sts.UNIX_WRITE_FORMAT}']
    report_expected = (
        f"['a:4:1: e: T [0]']"  # TODO Unwrap the lines - no list per line
    )
    assert cli.main(data, streaming_mode=False) == 0
    out, err = capsys.readouterr()
    assert out.strip() == report_expected.strip()
