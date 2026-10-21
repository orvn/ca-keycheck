#!/usr/bin/env bash
# One time setup
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

git config core.hooksPath .githooks
chmod +x .githooks/*

echo "hooks path set to .githooks"
