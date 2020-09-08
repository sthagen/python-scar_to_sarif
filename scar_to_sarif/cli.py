#! /usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""Add logical documentation here later TODO."""
import os
import sys

import scar_to_sarif.scar_to_sarif as sts

DEBUG = os.getenv("SCAR_TO_SARIF_DEBUG")


def report(data, write_format=sts.DEFAULT_WRITE_FORMAT, streaming_mode=False):
    """Primitive reporter."""
    if write_format in sts.SUPPORTED_WRITE_FORMATS:
        DEBUG and print(f"Found supported write format ({write_format}) option")
        if write_format == sts.DEFAULT_WRITE_FORMAT:
            for item in data:
                if streaming_mode:
                    for chunk in item:
                        sys.stdout.write(chunk)
                else:
                    sys.stdout.write(item)
        else:
            print(f"Write format {write_format} not yet implemented.")
    else:
        print(
            f"Found unexpected write format ({write_format}) option"
        )


# pylint: disable=expression-not-assigned
def main(argv=None, inline_mode=False, record_format=sts.GCC_READ_FORMAT_CODE, streaming_mode=False):
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

    streaming_mode = True if streaming_mode or "--streaming" in argv else False
    if streaming_mode:
        argv = [arg for arg in argv if arg != "--streaming"]
    DEBUG and print(f"Arguments after streaming mode check: ({argv})")

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
        arguments = ', '.join(f"'{arg}'" for arg in argv)
        print(
            f"Found unexpected option{'' if len(unexpected) == 1 else 's'} ({', '.join(unexpected)}) in arguments after option processing:"
            f" ({arguments})"
        )
        return 2

    if stdin_mode:
        report(sts.process_stdin(read_format=record_format, write_format=write_format, streaming_mode=streaming_mode),
               write_format=write_format, streaming_mode=streaming_mode)
    else:
        report(sts.process(argv, inline_mode=inline_mode, read_format=record_format, write_format=write_format, streaming_mode=streaming_mode),
               write_format=write_format, streaming_mode=streaming_mode)
    return 0
