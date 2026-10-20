#!/bin/bash
set -u
cd /home/zack/orca/workspaces/substrate-goal330-20261020/goal330-daemon-only-bootstrap
/usr/bin/python3 -I -B /home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-native-info-offline-driver-ctx-913464a561fe/qualify.py owner
owner_status=$?
/usr/bin/python3 -I -B /home/zack/.codex/orchestrate/vespiary-goal330/reviews/daemon-native-info-offline-driver-ctx-913464a561fe/qualify.py release
release_status=$?
if [ "$owner_status" -ne 0 ] || [ "$release_status" -ne 0 ]; then exit 1; fi
