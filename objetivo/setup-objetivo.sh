#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR
# Configura el SERVIDOR OBJETIVO (Ubuntu Server 24.04 LTS):
#   1. Docker + DVWA (aplicación web vulnerable en contenedor)
#   2. Suricata (IDS de red) escuchando la red del laboratorio
#   3. Agente Wazuh conectado al SIEM (logs de autenticación, FIM, web, Suricata)
#
# Uso (como root):  SIEM_IP=192.168.56.20 LAB_IF=enp0s8 bash setup-objetivo.sh
# =============================================================================
set -euo pipefail

SIEM_IP="${SIEM_IP:-192.168.56.20}"     # IP del servidor Wazuh
LAB_IF="${LAB_IF:-enp0s8}"              # interfaz de la red del laboratorio
LAB_NET="${LAB_NET:-192.168.56.0/24}"   # red del laboratorio (HOME_NET)
AGENT_NAME="${AGENT_NAME:-web-tiendacr}"
WAZUH_VER="${WAZUH_VER:-4.14.10-1}"
DVWA_IMAGE="vulnerables/web-dvwa"
WEBROOT="/var/www/dvwa"                 # código de DVWA en el host (vigilado por FIM)
WEBLOGS="/var/log/dvwa"                 # logs de Apache del contenedor en el host

export DEBIAN_FRONTEND=noninteractive
log() { echo -e "\n=== $* ==="; }

[[ $EUID -eq 0 ]] || { echo "Ejecutar como root (sudo)"; exit 1; }

# -----------------------------------------------------------------------------
log "1/3 Docker + DVWA"
apt-get update -q
apt-get install -y -q docker.io curl jq gnupg software-properties-common ethtool
systemctl enable --now docker

mkdir -p "$WEBROOT" "$WEBLOGS"
if ! docker ps -a --format '{{.Names}}' | grep -qx dvwa; then
  docker pull "$DVWA_IMAGE"
  # Se copia el código al host para que el FIM de Wazuh vigile los archivos web
  cid=$(docker create "$DVWA_IMAGE")
  docker cp "$cid":/var/www/html/. "$WEBROOT"/
  docker rm "$cid" >/dev/null
  chown -R 33:33 "$WEBROOT"            # www-data dentro del contenedor (uid 33)
  docker run -d --name dvwa --restart unless-stopped \
    -p 80:80 \
    -v "$WEBROOT":/var/www/html \
    -v "$WEBLOGS":/var/log/apache2 \
    "$DVWA_IMAGE"
fi

# -----------------------------------------------------------------------------
log "2/3 Suricata (IDS)"
if ! command -v suricata >/dev/null; then
  add-apt-repository -y ppa:oisf/suricata-stable
  apt-get update -q
  apt-get install -y -q suricata
fi
SURI=/etc/suricata/suricata.yaml
# Red protegida e interfaz de captura
sed -i "s|^\(\s*HOME_NET:\).*|\1 \"[${LAB_NET}]\"|" "$SURI"
sed -i "0,/- interface: eth0/s//- interface: ${LAB_IF}/" "$SURI"
sed -i "s|^IFACE=.*|IFACE=${LAB_IF}|" /etc/default/suricata 2>/dev/null || true
# Quitar eventos "stats" de eve.json: tienen cientos de campos y Wazuh los
# rechaza con "Too many fields for JSON decoder" (no aportan a la detección)
sed -i '/^        - stats:/,/^            deltas:/s/^/#/' "$SURI"
# Reglas propias del equipo (se llenan en la fase 2.5)
mkdir -p /etc/suricata/rules
touch /etc/suricata/rules/local.rules
grep -q "/etc/suricata/rules/local.rules" "$SURI" || \
  sed -i "/^rule-files:/a\  - /etc/suricata/rules/local.rules" "$SURI"
# Desactivar offloading de la NIC virtual para que Suricata vea paquetes reales
ethtool -K "$LAB_IF" gro off lro off 2>/dev/null || true
suricata-update -q || suricata-update
suricata -T -c "$SURI" -v >/dev/null && echo "Configuración de Suricata válida"
systemctl enable suricata
systemctl restart suricata

# -----------------------------------------------------------------------------
log "3/3 Agente Wazuh"
if ! dpkg -l wazuh-agent 2>/dev/null | grep -q ^ii; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
    --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -q
  WAZUH_MANAGER="$SIEM_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
    apt-get install -y -q "wazuh-agent=${WAZUH_VER}"
  apt-mark hold wazuh-agent
fi

OSSEC=/var/ossec/etc/ossec.conf
if ! grep -q "TiendaCR" "$OSSEC"; then
cat >> "$OSSEC" <<EOF

<!-- ===== Proyecto 2 TiendaCR: fuentes adicionales ===== -->
<ossec_config>
  <!-- Alertas de Suricata (IDS de red) -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>
  <!-- Logs web de DVWA (Apache dentro del contenedor) -->
  <localfile>
    <log_format>apache</log_format>
    <location>${WEBLOGS}/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>${WEBLOGS}/error.log</location>
  </localfile>
  <!-- Integridad de archivos en tiempo real sobre el código web -->
  <syscheck>
    <directories realtime="yes" report_changes="yes" check_all="yes">${WEBROOT}</directories>
  </syscheck>
</ossec_config>
EOF
fi
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

log "Resumen"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
systemctl is-active suricata wazuh-agent
echo "Listo. DVWA: http://$(hostname -I | awk '{print $2}')/  (configurar BD en /setup.php)"
