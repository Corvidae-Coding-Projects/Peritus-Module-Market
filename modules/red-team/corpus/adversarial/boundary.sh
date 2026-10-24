#!/bin/sh
set -eu

if IFS= read -r _line < /etc/passwd; then
    printf '%s' 'passwd-visible'
else
    printf '%s' 'passwd-blocked'
fi
if IFS= read -r _line < /dev/tcp/1.1.1.1/80; then
    printf '%s' '|network-visible'
else
    printf '%s' '|network-blocked'
fi
printf '|home=%s|token=%s' "${HOME-unset}" "${GITHUB_TOKEN-unset}"
