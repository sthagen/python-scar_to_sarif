# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import re
ENCODING = 'utf-8'
GCC_RECORD_PATTERN = re.compile(r'^([^:]+):([^:]+):([^:]+):\s+([^:]+):\s+(.+)\s+\[([^]]+)\]\s*$')
GCC_FORMAT_CODE = "gcc"
UNKNOWN_FORMAT_CODE = "unknown"
SUPPORTED_READ_FORMATS = (GCC_FORMAT_CODE,)
PARSER = {
    GCC_FORMAT_CODE: GCC_RECORD_PATTERN,
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


def _strip(line):
    """Line endings variety shall not complicate the parser."""
    return line.strip().rstrip('\r')


def detect(text):
    """Detect the source format."""
    m = GCC_RECORD_PATTERN.match(_strip(text))
    if m:
        return GCC_FORMAT_CODE
    return UNKNOWN_FORMAT_CODE


def scan(lines):
    """Scan the source lines and yield records."""
    for line in lines:
        record = _strip(line)
        yield record


def parse(records, record_format=UNKNOWN_FORMAT_CODE):
    """Parse the source records and yield parsed result."""
    for record in records:
        if not record:
            continue
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


def process(path_or_data, pure_data=False, record_format=GCC_FORMAT_CODE):
    """Public API entry point."""
    if pure_data:
        for entry in transform(parse(scan(source(path_or_data, pure_data)), record_format)):
            yield entry
    else:
        for a_path in path_or_data:
            for entry in transform(parse(scan(source(a_path, pure_data)), record_format)):
                yield entry
