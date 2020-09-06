# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import json
import pytest  # type: ignore

import scar_to_sarif.cli as cli


def test_main_ok_empty_array(capsys):
    job = ['[]']
    assert cli.main(job) == job
    out, err = capsys.readouterr()
    assert out.strip() == ''
