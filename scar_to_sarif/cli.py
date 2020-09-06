#! /usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import os
import sys

import scar_to_sarif.scar_to_sarif as sts

DEBUG = os.getenv("SCAR_TO_SARIF_DEBUG")


def report(data):
    """Primitive reporter."""
    for item in data:
        print(item)


# pylint: disable=expression-not-assigned
def main(argv=None, pure_data=False, record_format=sts.GCC_FORMAT_CODE):
    """Process ... TODO."""
    argv = argv if argv else sys.argv[1:]
    report(sts.process(argv, pure_data, record_format))
    return 0
