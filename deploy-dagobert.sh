#!/bin/bash
set -e
cd /home/rifat/soc-pipeline
git fetch origin main
git checkout origin/main -- dagobert-linux
docker build -t dagobert-fixed8 -f - . << 'EOF'
FROM dagobert-fixed8
COPY dagobert-linux /usr/local/bin/dagobert
EOF
docker compose restart dagobert
sleep 3
docker exec dagobert grep -ac "table-layout:fixed" /usr/local/bin/dagobert && echo "OK: fix is in binary" || echo "ERROR: fix missing"
