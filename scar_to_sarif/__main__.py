# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring
import sys

from scar_to_sarif.cli import main

if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
