#!/bin/sh

for f in tests/*.py; do
    if [ $# -eq 0 ]; then
        python3 $f
    else
        python3 $f $1
    fi
done
