#! /usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import json
import os
import sys

import scar_to_sarif.scar_to_sarif as sts

DEBUG = os.getenv("SCAR_TO_SARIF_DEBUG")


def report(data, write_format=sts.DEFAULT_WRITE_FORMAT):
    """Primitive reporter."""
    if write_format in sts.SUPPORTED_WRITE_FORMATS:
        DEBUG and print(f"Found supported write format ({write_format}) option")
        if write_format == sts.DEFAULT_WRITE_FORMAT:
            for item in data:
                print(item)
        else:
            print(f"Write format {write_format} not yet implemented.")
    else:
        print(
            f"Found unexpected write format ({write_format}) option"
        )


# pylint: disable=expression-not-assigned
def main(argv=None, inline_mode=False, record_format=sts.GCC_READ_FORMAT_CODE):
    """Process ... TODO."""
    argv = argv if argv else sys.argv[1:]
    DEBUG and print(f"Arguments after hand over: ({argv})")
    stdin_mode = True if "--" in argv or "--stdin" in argv else False
    if stdin_mode:
        argv = [arg for arg in argv if arg not in ("--", "--stdin")]
    DEBUG and print(f"Arguments after stdin mode check: ({argv})")

    inline_mode = True if inline_mode or "--inline" in argv else False
    if inline_mode:
        argv = [arg for arg in argv if arg != "--inline"]
    DEBUG and print(f"Arguments after inline mode check: ({argv})")

    write_format = sts.DEFAULT_WRITE_FORMAT
    for wf_type in sts.SUPPORTED_WRITE_FORMATS:
        DEBUG and print(f"Arguments before write format ({wf_type}) check: ({argv})")
        if f'--{wf_type}' in argv:
            write_format = wf_type
            argv = [arg for arg in argv if arg != f'--{wf_type}']
            break

    DEBUG and print(f"Arguments after option processing: ({argv})")
    if any((arg.startswith("--") for arg in argv)):
        unexpected = [arg for arg in argv if arg.startswith("--")]
        print(
            f"Found unexpected option{'' if len(unexpected) == 1 else '(s)'} ({', '.join(unexpected)}) in arguments after option processing:"
            f" ({', '.join(argv)})"
        )
        return 2

    if stdin_mode:
        report(sts.process_stdin(record_format=record_format), write_format=write_format)
    else:
        report(sts.process(argv, inline_mode=inline_mode, record_format=record_format), write_format=write_format)
    return 0
