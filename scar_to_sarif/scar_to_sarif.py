# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import re

GCC_RECORD_PATTERN = re.compile(r'^([^:]+):([^:]+):([^:]+):\s+([^:]+):\s+(.+)\s+\[([^]]+)\]\s*$')
GCC_FORMAT_CODE = "gcc"
UNKNOWN_FORMAT_CODE = "unknown"


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


def parse(text):
    """Parse the source text."""
    return NotImplemented


def aggregate(data):
    """Aggregate the data."""
    return NotImplemented


def transform(data):
    """Transform the data."""
    return NotImplemented
