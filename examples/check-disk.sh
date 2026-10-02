#!/bin/sh
# Example check: writes a fact to journald; Fluent Bit ships it, loglantern stores disk.used_pct.
# Run from a systemd timer every few minutes.
used=$(df --output=pcent / | tail -1 | tr -dc 0-9)
echo "{\"fact\":\"disk\",\"mount\":\"/\",\"used_pct\":$used}" | systemd-cat -t loglantern-fact
