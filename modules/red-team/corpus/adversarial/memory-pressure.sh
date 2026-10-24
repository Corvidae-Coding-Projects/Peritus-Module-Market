#!/bin/sh
set -eu

value=0123456789
while :; do
    value="$value$value$value$value"
done
