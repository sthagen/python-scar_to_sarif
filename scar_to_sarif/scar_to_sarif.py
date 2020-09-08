# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
from copy import deepcopy
import json
import re
import sys
ENCODING = 'utf-8'
GCC_RECORD_PATTERN = re.compile(r'^([^:]+):([^:]+):([^:]+):\s+([^:]+):\s+(.+)\s+\[([^]]+)\]\s*$')
GCC_READ_FORMAT_CODE = "gcc"
UNKNOWN_READ_FORMAT_CODE = "unknown"
SUPPORTED_READ_FORMATS = (GCC_READ_FORMAT_CODE,)
PARSER = {
    GCC_READ_FORMAT_CODE: GCC_RECORD_PATTERN,
}

SUPPORTED_WRITE_FORMATS = (
    "json",
    "unix",
    "html",
)
DEFAULT_WRITE_FORMAT = SUPPORTED_WRITE_FORMATS[0]
STREAMING_JSON_PREFIX_TEMPLATE = """\
{
  "version": "2.1.0",
  "runs": [
    {
      "versionControlProvenance": [
        {
          "repositoryUri": "https://ci.example.com/project/repo/",
          "revisionId": "cafefade",
          "branch": "default"
        }
      ],
      "results": [
"""

STREAMING_JSON_POSTFIX_TEMPLATE = """
      ],
      "properties": {
        "metrics": {
          "total": 1,
          "error": 1,
          "warning": 0
        }
      },
      "tool": {
        "driver": {
          "name": "RTSL!",
          "fullName": "Read the Source, Luke!",
          "version": "2020.09",
          "rules": [
            {
              "id": "CWE1350",
              "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses",
              "helpUri": "https://cwe.mitre.org/data/definitions/1350.html"
            }
          ]
        }
      },
      "conversion": {
        "tool": {
          "driver": {
            "name": "scars_to_sarif"
          }
        },
        "invocation": {
          "arguments": [
            "--"
          ],
          "executionSuccessful": True,
          "commandLine": "--",
          "endTimeUtc": "2020-09-08T12:34:56Z",
          "workingDirectory": {
            "uri": "/home/ci/transform"
          }
        }
      },
      "invocations": [
        {
          "executionSuccessful": True,
          "endTimeUtc": "2020-09-08T12:34:57Z",
          "workingDirectory": {
            "uri": "/home/ci/transform"
          }
        }
      ]
    }
  ],
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "inlineExternalProperties": [
    {
      "guid": "0c9fe04f-9b74-4972-a82e-2099710a0ba1",
      "runGuid": "dce1bdf0-358b-4898-bedf-f297160f3b37"
    }
  ]
}

"""

CLONE_ME = {
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "RTSL!",
          "fullName": "Read the Source, Luke!",
          "version": "2020.09",
          "rules": [
            {
              "id": "CWE1350",
              "name": "CWE VIEW: Weaknesses in the 2020 CWE Top 25 Most Dangerous Software Weaknesses",
              "helpUri": "https://cwe.mitre.org/data/definitions/1350.html"
            }
          ]
        }
      },
      "conversion": {
        "tool": {
          "driver": {
            "name": "scars_to_sarif"
          }
        },
        "invocation": {
          "arguments": [
            "--"
          ],
          "executionSuccessful": True,
          "commandLine": "--",
          "endTimeUtc": "2020-09-08T12:34:56Z",
          "workingDirectory": {
            "uri": "/home/ci/transform"
          }
        }
      },
      "invocations": [
        {
          "executionSuccessful": True,
          "endTimeUtc": "2020-09-08T12:34:57Z",
          "workingDirectory": {
            "uri": "/home/ci/transform"
          }
        }
      ],
      "versionControlProvenance": [
        {
          "repositoryUri": "https://ci.example.com/project/repo/",
          "revisionId": "cafefade",
          "branch": "default"
        }
      ],
      "properties": {
        "metrics": {
          "total": 1,
          "error": 1,
          "warning": 0
        }
      },
      "results": [  # Append result objects here
      ]
    }
  ],
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "inlineExternalProperties": [
    {
      "guid": "0c9fe04f-9b74-4972-a82e-2099710a0ba1",
      "runGuid": "dce1bdf0-358b-4898-bedf-f297160f3b37"
    }
  ]
}

RESULT_TEMPLATE = {
    "message": {
        "text": "$text$"
    },
    "level": "$level$",
    "locations": [
        {
            "physicalLocation": {
                "region": {
                    "startLine": "$line$",
                    "startColumn": "$column$"
                },
                "artifactLocation": {
                    "uri": "https://ci.example.com/project/repo/browse$path$#$line$?at=default"
                },
                "contextRegion": {
                    "endLine": "$line$",
                    "startLine": "$line$"
                }
            }
        }
    ],
    "properties": {
        "issue_confidence": "LOW",
        "issue_severity": "HIGH"
    },
    "hostedViewerUri": "https://sarifviewer.azurewebsites.net",
    "ruleId": "$msg_code$",
    "ruleIndex": 0
}


def source(path_or_data, pure_data=False):
    """Encapsulate the file entry point."""
    if pure_data:
        for line in path_or_data:
            yield line
    else:
        with open(path_or_data, "rt", encoding=ENCODING) as handle:
            for line in handle:
                yield line


def source_stdin():
    """Encapsulate the stdin entry point."""  # TODO avoid duplication of functions for this special case
    for line in sys.stdin.readlines():
        yield line


def _strip(line):
    """Line endings variety shall not complicate the parser."""
    return line.strip().rstrip('\r')


def detect(text):
    """Detect the source format."""
    m = GCC_RECORD_PATTERN.match(_strip(text))
    if m:
        return GCC_READ_FORMAT_CODE
    return UNKNOWN_READ_FORMAT_CODE


def scan(lines):
    """Scan the source lines and yield records."""
    for line in lines:
        record = _strip(line)
        yield record


def parse(records, read_format=UNKNOWN_READ_FORMAT_CODE):
    """Parse the source records and yield parsed result."""
    for record in records:
        if not record:
            continue
        if read_format not in SUPPORTED_READ_FORMATS:
            yield NotImplemented
        m = PARSER[read_format].match(record)
        if m:
            yield {
                'path': m.group(1),
                'line': int(m.group(2)),
                'column': int(m.group(3)),
                'severity': m.group(4).lower(),
                'message': m.group(5),
                'msg_code': m.group(6),
            }

        yield {}


def aggregate(data):
    """Aggregate the data."""
    return NotImplemented


def _result_to_sarif(model_item):
    """DRY expecting model item with content."""
    entry = deepcopy(RESULT_TEMPLATE)
    entry["message"]["text"] = model_item["message"]
    entry["level"] = model_item["severity"]
    entry["locations"][0]["physicalLocation"]["region"]["startLine"] = model_item["line"]
    entry["locations"][0]["physicalLocation"]["region"]["startColumn"] = model_item["column"]
    entry["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].replace(
        "$path$",
        model_item["path"]
    )
    entry["locations"][0]["physicalLocation"]["contextRegion"]["endLine"] = model_item["line"]
    entry["locations"][0]["physicalLocation"]["contextRegion"]["startLine"] = model_item["line"]
    entry["ruleId"] = model_item["msg_code"].replace("-", "")
    return entry


def transform(data, write_format=DEFAULT_WRITE_FORMAT):
    """Transform the data."""
    if write_format == DEFAULT_WRITE_FORMAT:
        report_document = deepcopy(CLONE_ME)
        for item in data:
            if item:
                report_document["runs"][0]["results"].append(_result_to_sarif(item))
        return json.dumps(report_document)


def stream(data, write_format=DEFAULT_WRITE_FORMAT):
    """Stream the data."""
    if write_format == DEFAULT_WRITE_FORMAT:
        yield ' '.join(STREAMING_JSON_PREFIX_TEMPLATE.replace("\n", " ").split())
        for item in data:
            if item:
                yield json.dumps(_result_to_sarif(item))
        yield ' '.join(STREAMING_JSON_POSTFIX_TEMPLATE.replace("\n", " ").split())


def process(path_or_data, inline_mode=False, read_format=GCC_READ_FORMAT_CODE, write_format=DEFAULT_WRITE_FORMAT, streaming_mode=False):
    """Public API entry point."""
    transformer = stream if streaming_mode else transform
    if inline_mode:
        yield transformer(parse(scan(source(path_or_data, inline_mode)), read_format=read_format), write_format=write_format)
    else:
        for a_path in path_or_data:
            yield transformer(parse(scan(source(a_path, inline_mode)), read_format=read_format), write_format=write_format)


def process_stdin(read_format=GCC_READ_FORMAT_CODE, write_format=DEFAULT_WRITE_FORMAT, streaming_mode=False):
    """Public API entry point."""
    transformer = stream if streaming_mode else transform
    yield transformer(parse(scan(source_stdin()), read_format=read_format), write_format=write_format)
