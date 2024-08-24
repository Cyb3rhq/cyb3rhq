#!/bin/bash
# Copyright (C) 2015, Cyb3rhq Inc.

# validate OS, linux or macos
if [ "X$(uname)" = "XLinux" ] ; then
    # Get Cyb3rhq installation path
    SCRIPT=$(readlink -f "$0")
    CYB3RHQ_HOME=$(dirname $(dirname $(dirname "$SCRIPT")))
    cd "${CYB3RHQ_HOME}"
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && find ./var/upgrade/* -not -name upgrade_result -delete) >/dev/null 2>&1 &
else
    (sleep 5 && chmod +x ./var/upgrade/*.sh && ./var/upgrade/pkg_installer.sh && find ./var/upgrade/ -mindepth 1 -not -name upgrade_result -delete) >/dev/null 2>&1 &
fi
