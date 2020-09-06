# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import re

GCC_RECORD_PATTERN = re.compile(r'^([^:]+):([^:]+):([^:]+):\s+([^:]+):\s+(.+)\s+\[([^]]+)\]\s*$')
GCC_FORMAT_CODE = "gcc"
UNKNOWN_FORMAT_CODE = "unknown"
SUPPORTED_READ_FORMATS = (GCC_FORMAT_CODE,)
PARSER = {
    GCC_FORMAT_CODE: GCC_RECORD_PATTERN,
}


def detect(text):
    """Detect the source format."""
    m = GCC_RECORD_PATTERN.match(text)
    if m:
        return GCC_FORMAT_CODE
    return UNKNOWN_FORMAT_CODE


def scan(lines):
    """Scan the source lines and yield records."""
    for line in lines:
        record = line.strip().rstrip('\r')
        yield record


def parse(records, record_format=UNKNOWN_FORMAT_CODE):
    """Parse the source records and yield parsed result."""
    for record in records:
        if record_format not in SUPPORTED_READ_FORMATS:
            yield NotImplemented
        m = PARSER[record_format].match(record)
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


def transform(data):
    """Transform the data."""
    for item in data:
        yield json.dumps(item)
