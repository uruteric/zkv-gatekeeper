#!/bin/bash
# cron */2: restart agen kalau endpoint HTTPS tidak jawab (systemd sudah tangani crash; ini untuk hang)
cd /root/zkvagent
if ! curl -sf -m 10 https://173-249-12-196.sslip.io/agent >/dev/null; then
  sleep 5
  curl -sf -m 10 https://173-249-12-196.sslip.io/agent >/dev/null || { echo "$(date '+%F %T') endpoint down, restart" >> watchdog.log; systemctl restart zkvagent; }
fi
