#!/usr/bin/env bash
# =============================================================================
# Proyecto 2 - Mini SOC TiendaCR - Fase 2.8: verificacion de remediacion
# Repite los ataques 2 y 3 contra el nivel 'impossible' (codigo seguro).
# =============================================================================
T="${TARGET:-192.168.56.10}"; CJ=/tmp/dvwa-rem.txt
echo "===== POST-REMEDIACION (nivel impossible) ====="
TK=$(curl -s -c "$CJ" "http://$T/login.php" | grep -oP "user_token' value='\K[^']+")
curl -s -b "$CJ" -c "$CJ" -d "username=admin&password=password&Login=Login&user_token=$TK" "http://$T/login.php" -o /dev/null
UT=$(curl -s -b "$CJ" -b security=impossible "http://$T/vulnerabilities/sqli/" | grep -oP "user_token' value='\K[^']+")
D=$(curl -s -b "$CJ" -b security=impossible -G "http://$T/vulnerabilities/sqli/" \
     --data-urlencode "id=1' UNION SELECT user,password FROM users-- -" --data-urlencode "Submit=Submit" \
     --data-urlencode "user_token=$UT" | grep -c "First name")
echo "ATAQUE 3 (SQLi)  -> filas de datos filtradas: $D   (ANTES de remediar: 5)"
R=$(curl -s -b "$CJ" -b security=impossible -G "http://$T/vulnerabilities/brute/" \
     --data-urlencode "username=admin" --data-urlencode "password=x" --data-urlencode "Login=Login" \
     --data-urlencode "user_token=FALSO")
echo "$R" | grep -qi CSRF \
  && echo "ATAQUE 2 (Fuerza bruta) -> RECHAZADO: 'CSRF token is incorrect'" \
  || echo "ATAQUE 2 -> se proceso (revisar)"
echo "===== FIN ====="
