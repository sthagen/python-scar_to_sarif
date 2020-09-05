#! /usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import os
import sys

from scar_to_sarif.scar_to_sarif import detect, parse, scan, aggregate, transform

DEBUG = os.getenv("SCAR_TO_SARIF_DEBUG")
ENCODING = "utf-8"


# pylint: disable=expression-not-assigned
def main(argv=None):
    """Process ... TODO."""
    argv = argv if argv else sys.argv[1:]
    return argv
