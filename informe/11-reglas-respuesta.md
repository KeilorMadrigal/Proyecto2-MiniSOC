## 2.5 Reglas personalizadas

El enunciado pide al menos **2 reglas propias de Suricata** y **1 regla propia de Wazuh**. El
equipo creó **4 reglas de Suricata** (una por ataque) y **4 reglas de Wazuh**, que son las que
detectan y clasifican los ataques documentados en la sección 2.4.

### Reglas de Suricata (IDS de red) — `/etc/suricata/rules/local.rules`

| SID | Ataque | Lógica de detección |
|---|---|---|
| **1000001** | Escaneo de puertos | 20 o más paquetes SYN desde un mismo origen en 5 s (`flags:S; threshold: type both, track by_src, count 20, seconds 5`) |
| **1000002** | Fuerza bruta web | 10 o más peticiones a `/vulnerabilities/brute/` con `password=` desde un origen en 60 s |
| **1000003** | Inyección SQL | En `http.uri` de `/vulnerabilities/sqli` con `id=`, una expresión regular detecta `UNION [ALL] SELECT` o el patrón `' OR '1'='1`. Metadata `mitre_technique_id T1190` |
| **1000004** | Webshell | Petición HTTP a `/hackable/uploads/*.php` con el parámetro `cmd=` (ejecución de la webshell) |

Ejemplo (regla 1000003, inyección SQL):
```
alert http any any -> $HOME_NET 80 (msg:"TiendaCR - Inyeccion SQL en parametro id";
  flow:established,to_server; http.uri; content:"/vulnerabilities/sqli"; nocase;
  content:"id="; nocase; pcre:"/(union[\s+]+(all[\s+]+)?select|'[\s+]*or[\s+]*'?\d+'?[\s+]*=[\s+]*'?\d+)/i";
  classtype:web-application-attack; sid:1000003; rev:1; metadata:mitre_technique_id T1190;)
```

### Reglas de Wazuh (SIEM/HIDS) — `/var/ossec/etc/rules/local_rules.xml`

Rango de ID propio: **100100–100199**.

| ID | Nivel | Dispara con | Qué hace |
|---|---|---|---|
| **100100** | 3 | Log de Apache: POST a `/vulnerabilities/brute/` con `password=` | Marca cada intento individual de login |
| **100101** | 10 | 10 eventos 100100 desde la misma IP en 60 s (`frequency`/`timeframe`/`same_srcip`) | Clasifica el patrón como **fuerza bruta** (MITRE T1110.001) y **dispara la respuesta automática** |
| **100110** | 12 | FIM (`if_sid 554`): archivo `.php` nuevo en `/var/www/dvwa/hackable/uploads/` | Detecta una **webshell** creada (MITRE T1505.003) |
| **100120** | 10 | Alerta de Suricata (`if_sid 86601`) con SID propio `^10000\d\d$` | **Eleva a nivel 10** las alertas de las reglas propias de Suricata para que resalten en el panel |

Ejemplo (regla 100101, correlación de fuerza bruta):
```xml
<rule id="100101" level="10" frequency="10" timeframe="60">
  <if_matched_sid>100100</if_matched_sid>
  <same_srcip />
  <description>TiendaCR: fuerza bruta contra el login web desde $(srcip) (10+ intentos en 60 s)</description>
  <mitre><id>T1110.001</id></mitre>
  <group>authentication_failures,attack,pci_dss_11.4,</group>
</rule>
```

Las reglas propias se validaron con `wazuh-analysisd -t` (Wazuh) y `suricata -T` (Suricata)
antes de ponerlas en producción, y se probaron con los ataques reales de la sección 2.4.

## 2.6 Respuesta automática

Se configuró una **respuesta activa** (*Active Response*) de Wazuh que **bloquea la IP atacante
en el firewall** del objetivo cuando se confirma un ataque. Es la contención automática del SOC.

**Configuración** (`/var/ossec/etc/ossec.conf` del SIEM):
```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101,5712,5763</rules_id>
  <timeout>180</timeout>
</active-response>
```

* **Disparadores:** la regla propia **100101** (fuerza bruta contra el login web) y las reglas
  incluidas **5712/5763** (fuerza bruta SSH).
* **Acción:** en el agente objetivo ejecuta `iptables -I INPUT -s <IP> -j DROP` **y** la misma
  regla en `FORWARD` (necesaria porque Docker publica el puerto 80 por FORWARD).
* **Temporal (180 s):** el bloqueo expira solo, para limitar el daño de un posible falso positivo.
* **Lista blanca:** la IP de administración `192.168.56.1` está en `white_list`, de modo que el
  equipo **nunca** se autobloquea y no pierde el acceso al laboratorio.

**Comprobación (ataque 2):** Hydra fue bloqueado a los **~1.8 s** del primer intento, tras 16
peticiones, sin llegar a la contraseña correcta; el bloqueo se registró (regla 651) y se liberó
a los 180 s (regla 652).

### Riesgo de falsos positivos

El bloqueo automático en el firewall es un control potente pero con un riesgo claro: **un falso
positivo deja sin servicio a un usuario legítimo**. Por ejemplo, un cliente real de TiendaCR que
escriba mal su contraseña varias veces, un *proxy*/NAT corporativo donde muchos usuarios
comparten una IP, o un escáner de disponibilidad del propio equipo podrían superar el umbral y
ser bloqueados. Medidas adoptadas para mitigar ese riesgo:

1. **Bloqueo temporal (180 s)**, no permanente: un usuario legítimo mal clasificado recupera el
   acceso solo, sin intervención.
2. **Lista blanca** de las IP de confianza (administración), que nunca se bloquean.
3. **Umbral prudente** (10 intentos en 60 s): suficientemente alto para no castigar un par de
   errores humanos, pero bajo para frenar una herramienta automatizada.
4. **Disparo solo desde una regla de alta confianza** (100101, nivel 10), no desde las alertas de
   nivel bajo.

En un entorno de producción, la recomendación sería empezar en **modo de solo alerta** (sin
bloqueo) durante un periodo de ajuste, revisar los falsos positivos y solo entonces activar el
bloqueo, además de combinarlo con CAPTCHA y MFA en la aplicación para no depender únicamente del
firewall.
