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
    parser = sts.parse(job, sts.GCC_READ_FORMAT_CODE)
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
    assert sts.detect(job[0]) == sts.GCC_READ_FORMAT_CODE
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_detect_ok_direct_non_gcc_text_default_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    assert sts.detect(job[0]) == sts.UNKNOWN_READ_FORMAT_CODE
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_parse_ok_direct_empty_gcc_code():
    job = ['']
    parser = sts.parse(job, sts.GCC_READ_FORMAT_CODE)
    with pytest.raises(StopIteration):
        next(parser)


def test_parse_ok_direct_gcc_surrogate_text(capsys):
    job = ['p:1:2: E: T [0]']
    data = {'path': 'p', 'line': 1, 'column': 2, 'severity': 'e', 'message': 'T', 'msg_code': '0'}
    parser = sts.parse(job, sts.GCC_READ_FORMAT_CODE)
    assert next(parser) == data
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_parse_ok_direct_gcc_text(capsys):
    job = ['/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]']
    data = {'path': '/a/path/file.ext', 'line': 42, 'column': 13, 'severity': 'error', 'message': 'The column 13 causes always trouble in line 42.', 'msg_code': 'CWE-0'}
    parser = sts.parse(job, sts.GCC_READ_FORMAT_CODE)
    assert next(parser) == data
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_detect_nok_direct_non_gcc_text_gcc_code(capsys):
    job = ['<style> (CWE-0) <<<The column 13 causes always trouble in line 42.>>> [/a/path/file.ext:42] -> [/a/path/file.ext:222]']
    parser = sts.parse(job, sts.GCC_READ_FORMAT_CODE)
    assert next(parser) == {}
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_transform_ok_single_data_item(capsys):
    data = [{'path': '/a/path/file.ext', 'line': 42, 'column': 13, 'severity': 'error', 'message': 'The column 13 causes always trouble in line 42.', 'msg_code': 'CWE-0'}]
    serialized = (
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
    assert sts.transform(data) == serialized
    out, err = capsys.readouterr()
    assert out.strip() == ''


def test_source_ok_pure_data_minimal():
    data = ['']
    line = sts.source(data, pure_data=True)
    assert next(line) == ''


def test_source_ok_path_minimal():
    data = ['tests/fixtures/gcc.txt']
    report_line_expected = (
        '/a/path/file.ext:42:13: Error: The column 13 causes always trouble in line 42. [CWE-0]\n'
    )
    line = sts.source(data[0])
    assert next(line) == report_line_expected
    assert next(line) == report_line_expected
    assert next(line) == report_line_expected
    with pytest.raises(StopIteration):
        next(line)


def test_process_ok_path_minimal():
    data = ['tests/fixtures/gcc.txt']
    serialized = (
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
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0}, '
        '{"message": {"text": "The column 13 causes always trouble in line 42."}, '
        '"level": "error", "locations": [{"physicalLocation": {"region": '
        '{"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0}, '
        '{"message": {"text": "The column 13 causes always trouble in line 42."}, '
        '"level": "error", "locations": [{"physicalLocation": {"region": '
        '{"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
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
    sarif = sts.process(data)
    assert next(sarif) == serialized


def test_process_ok_path_minimal_streaming_mode():
    data = ['tests/fixtures/gcc.txt']
    serialized = (
        '{ "version": "2.1.0", "runs": [ { "versionControlProvenance": [ { '
        '"repositoryUri": "https://ci.example.com/project/repo/", "revisionId": '
        '"cafefade", "branch": "default" } ], "results": [ {"message": {"text": "The '
        'column 13 causes always trouble in line 42."}, "level": "error", '
        '"locations": [{"physicalLocation": {"region": {"startLine": 42, '
        '"startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0} '
        '{"message": {"text": "The column 13 causes always trouble in line 42."}, '
        '"level": "error", "locations": [{"physicalLocation": {"region": '
        '{"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0} '
        '{"message": {"text": "The column 13 causes always trouble in line 42."}, '
        '"level": "error", "locations": [{"physicalLocation": {"region": '
        '{"startLine": 42, "startColumn": 13}, "artifactLocation": {"uri": '
        '"https://ci.example.com/project/repo/browse$path$#$line$?at=default"}, '
        '"contextRegion": {"endLine": 42, "startLine": 42}}}], "properties": '
        '{"issue_confidence": "LOW", "issue_severity": "HIGH"}, "hostedViewerUri": '
        '"https://sarifviewer.azurewebsites.net", "ruleId": "CWE0", "ruleIndex": 0} '
        '], "properties": { "metrics": { "total": 1, "error": 1, "warning": 0 } }, '
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
    sarif = sts.process(data, streaming_mode=True)
    collate = ' '.join([chunk for chunk in next(sarif)])
    assert collate == serialized


def test_process_ok_path_minimal_unix_write_format_streaming_mode():
    data = ['tests/fixtures/gcc.txt']
    serialized = (
        '/a/path/file.ext:42:13: error: The column 13 causes always trouble in line '
        '42. [CWE-0] /a/path/file.ext:42:13: error: The column 13 causes always '
        'trouble in line 42. [CWE-0] /a/path/file.ext:42:13: error: The column 13 '
        'causes always trouble in line 42. [CWE-0]'
    )
    unix = sts.process(data, write_format=sts.UNIX_WRITE_FORMAT, streaming_mode=True)
    collate = ' '.join([chunk for chunk in next(unix)])
    assert collate == serialized


def test_process_ok_path_minimal_unix_write_format_memory_mode():
    data = ['tests/fixtures/gcc.txt']
    serialized = [
        '/a/path/file.ext:42:13: error: The column 13 causes always trouble in line 42. [CWE-0]',
        '/a/path/file.ext:42:13: error: The column 13 causes always trouble in line 42. [CWE-0]',
        '/a/path/file.ext:42:13: error: The column 13 causes always trouble in line 42. [CWE-0]',
    ]
    unix = sts.process(data, write_format=sts.UNIX_WRITE_FORMAT, streaming_mode=False)
    collate = list(unix)[0]  # TODO provide unwrapped line list in implementation do not unwrap in application
    assert collate == serialized


def test_aggregate_dummy():
    assert sts.aggregate('whatever') == NotImplemented
