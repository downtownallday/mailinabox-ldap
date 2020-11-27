#!/bin/bash

mydir=$(dirname "$0")
export PYTHONPATH=$(realpath "$mydir/../../lib"):$PYTHONPATH
export BROWSER_TESTS_VERBOSITY=2

python3 "$@"
