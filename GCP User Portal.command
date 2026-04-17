#!/bin/zsh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

APP_URL="${APP_URL:-https://user-account-493600.uc.r.appspot.com}"

echo "Opening cloud app..."
echo "URL: $APP_URL"

open "$APP_URL"
