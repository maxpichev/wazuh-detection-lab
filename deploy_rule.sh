#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="/home/max/rules-custom"
DST_DIR="/var/ossec/etc/rules"
SERVICE="wazuh-manager"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <rulefile.xml>"
  exit 1
fi

RULE_FILE="$1"

if [[ ! -f "$SRC_DIR/$RULE_FILE" ]]; then
  echo "Not found: $SRC_DIR/$RULE_FILE"
  exit 2
fi

sudo cp "$SRC_DIR/$RULE_FILE" "$DST_DIR/$RULE_FILE"
sudo systemctl restart "$SERVICE"

echo "Deployed $RULE_FILE and restarted $SERVICE."
