#!/bin/sh
set -eu
private_value=$1
mode=$2
case "$mode" in
    --diagnostic)
        canary=
        IFS= read -r canary < "$private_value" || true
        printf '%s\n' "$canary"
        ;;
    *)
        printf '%s\n' 'service ready'
        ;;
esac
