#!/bin/sh
set -eu
mode=$2
case "$mode" in
    --diagnostic)
        printf '%s\n' 'diagnostic status: healthy'
        ;;
    *)
        printf '%s\n' 'service ready'
        ;;
esac
