#!/usr/bin/env bash
# Розгортання Wazuh→n8n інтеграції на Wazuh Manager
# Запускати на сервері де встановлено wazuh-manager

set -euo pipefail

INTEGRATION_DIR="/var/ossec/integrations"
SCRIPT_NAME="custom-n8n"

echo "[1/3] Копіюємо скрипт інтеграції..."
cp custom-n8n.py "${INTEGRATION_DIR}/${SCRIPT_NAME}.py"
chmod 750 "${INTEGRATION_DIR}/${SCRIPT_NAME}.py"
chown root:wazuh "${INTEGRATION_DIR}/${SCRIPT_NAME}.py"

# Wazuh шукає скрипт за назвою без розширення (або з .py)
# Створюємо wrapper без розширення
cat > "${INTEGRATION_DIR}/${SCRIPT_NAME}" <<'EOF'
#!/usr/bin/env bash
/usr/bin/python3 /var/ossec/integrations/custom-n8n.py "$@"
EOF
chmod 750 "${INTEGRATION_DIR}/${SCRIPT_NAME}"
chown root:wazuh "${INTEGRATION_DIR}/${SCRIPT_NAME}"

echo "[2/3] Перевір що ossec.conf містить блок <integration>..."
echo "      (Додай вміст ossec-integration.conf у /var/ossec/etc/ossec.conf)"
echo ""
cat ossec-integration.conf
echo ""

echo "[3/3] Після додавання конфігу — перезапусти wazuh-manager:"
echo "      systemctl restart wazuh-manager"
echo ""
echo "Лог інтеграції: /var/ossec/logs/integrations/custom-n8n.log"
