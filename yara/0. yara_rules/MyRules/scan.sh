#!/bin/bash

WATCH_DIR="/home/master/Desktop/yara_dashboard/watch"
RULE_DIR="/home/master/Desktop/yara_dashboard/rules"
LOG_DIR="/home/master/Desktop/yara_dashboard/logs"
YARA_BIN="/usr/local/bin/yara"

mkdir -p "$LOG_DIR"

echo "[+] Starting real-time YARA monitor..."

inotifywait -m -e create,modify "$WATCH_DIR" --format "%w%f" | while read FILE
do
    echo "[+] New file detected: $FILE"
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    LOG_FILE="$LOG_DIR/scan_$(date +"%Y%m%d").csv"

    # 룰별로 스캔 후 CSV 기록
    for RULE_FILE in "$RULE_DIR"/*.yar; do
        MATCH=$("$YARA_BIN" -s "$RULE_FILE" "$FILE" 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')
        if [[ -z "$MATCH" ]]; then
            MATCH="-"
        fi
        RULE_NAME=$(basename "$RULE_FILE" .yar)
        echo "$TIMESTAMP,$(basename "$FILE"),$RULE_NAME,$MATCH" >> "$LOG_FILE"
    done

    echo "[+] Scan complete → $LOG_FILE"
done
