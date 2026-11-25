#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR
# Control de acceso y de tráfico (fase 2.2) para el OBJETIVO o el SIEM.
#   - SSH solo con llaves, sin contraseña y sin root
#   - UFW con denegación por defecto y solo IP del equipo
#   - (objetivo) Reglas DOCKER-USER: Docker publica puertos por FORWARD y
#     se salta UFW; sin esto DVWA quedaría abierta a toda la red.
#
# Uso (root):  ROLE=objetivo bash hardening.sh   |   ROLE=siem bash hardening.sh
# =============================================================================
set -euo pipefail

ROLE="${ROLE:?Defina ROLE=objetivo o ROLE=siem}"
ADMIN_IP="${ADMIN_IP:-192.168.56.1}"      # laptop del equipo (SSH y navegador)
KALI_IP="${KALI_IP:-192.168.56.30}"       # máquina atacante del equipo
TARGET_IP="${TARGET_IP:-192.168.56.10}"   # servidor objetivo (agente Wazuh)
LAB_IF="${LAB_IF:-enp0s8}"
SSH_USER="${SSH_USER:-$(logname 2>/dev/null || echo "$SUDO_USER")}"

[[ $EUID -eq 0 ]] || { echo "Ejecutar como root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q ufw >/dev/null

# ---------------------------------------------------------------- SSH -------
cat > /etc/ssh/sshd_config.d/10-soc-hardening.conf <<EOF
# Proyecto 2 TiendaCR - endurecimiento de SSH (tiene prioridad sobre 50-*.conf)
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers ${SSH_USER}
EOF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl restart ssh

# ---------------------------------------------------------------- UFW -------
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed
ufw logging low

# R1: SSH de administración solo desde la laptop del equipo
ufw allow in on "$LAB_IF" from "$ADMIN_IP" to any port 22 proto tcp comment 'R1 SSH admin solo equipo'

if [[ "$ROLE" == "objetivo" ]]; then
  # R2/R3: aplicación web solo para la laptop y la Kali del equipo
  ufw allow in on "$LAB_IF" from "$ADMIN_IP" to any port 80 proto tcp comment 'R2 web desde laptop'
  ufw allow in on "$LAB_IF" from "$KALI_IP"  to any port 80 proto tcp comment 'R3 web desde Kali (pruebas)'

  # R4: Docker se salta UFW -> aplicar la misma política en DOCKER-USER
  if ! grep -q "TiendaCR DOCKER-USER" /etc/ufw/after.rules; then
    cat >> /etc/ufw/after.rules <<EOF

# --- TiendaCR DOCKER-USER: misma política para los puertos publicados por Docker ---
*filter
:DOCKER-USER - [0:0]
-F DOCKER-USER
-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A DOCKER-USER -i ${LAB_IF} -s ${ADMIN_IP} -p tcp --dport 80 -j RETURN
-A DOCKER-USER -i ${LAB_IF} -s ${KALI_IP} -p tcp --dport 80 -j RETURN
-A DOCKER-USER -i ${LAB_IF} -j LOG --log-prefix "[DOCKER-USER DROP] " --log-level 4
-A DOCKER-USER -i ${LAB_IF} -j DROP
-A DOCKER-USER -j RETURN
COMMIT
EOF
  fi
fi

if [[ "$ROLE" == "siem" ]]; then
  # R5: panel web de Wazuh solo desde la laptop del equipo
  ufw allow in on "$LAB_IF" from "$ADMIN_IP"  to any port 443  proto tcp comment 'R5 panel Wazuh'
  # R6/R7: eventos y registro de agentes solo desde el servidor objetivo
  ufw allow in on "$LAB_IF" from "$TARGET_IP" to any port 1514 proto tcp comment 'R6 eventos agente'
  ufw allow in on "$LAB_IF" from "$TARGET_IP" to any port 1515 proto tcp comment 'R7 registro agente'
  # 9200 (indexador) y 55000 (API) quedan solo en localhost: denegados por defecto
fi

ufw --force enable
ufw reload >/dev/null
echo; ufw status verbose
[[ "$ROLE" == "objetivo" ]] && { echo; iptables -S DOCKER-USER; }
echo; sshd -T | grep -E '^(passwordauthentication|permitrootlogin|pubkeyauthentication|allowusers|maxauthtries) '
