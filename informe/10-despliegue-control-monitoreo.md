# Fase 2. Implementación del Mini SOC

## 2.1 Despliegue del laboratorio

El laboratorio se montó de forma local en **VirtualBox 7.1** sobre una laptop con Windows 11
(16 GB de RAM), usando una red **solo-anfitrión** (*host-only*) `192.168.56.0/24` que aísla el
entorno de Internet y de la red doméstica. Se desplegaron tres máquinas virtuales más la
laptop anfitriona, que actúa como estación de administración del equipo.

| Rol | Nombre | IP | SO | Recursos | Software principal |
|---|---|---|---|---|---|
| **SIEM** | siem-tiendacr | 192.168.56.20 | Ubuntu | 8 GB / 2 vCPU | Wazuh 4.14 todo-en-uno (manager, indexer, dashboard, filebeat) |
| **Objetivo** | web-tiendacr | 192.168.56.10 | Ubuntu Server 24.04.5 LTS | 2.5 GB / 2 vCPU | Docker + DVWA, Suricata (IDS), agente Wazuh |
| **Atacante** | Kali-Atacante | 192.168.56.30 | Kali Linux 2026 | 2 GB / 2 vCPU | nmap, Hydra, curl (herramientas ofensivas) |
| **Administración** | Laptop del equipo | 192.168.56.1 | Windows 11 | — | Navegador (panel Wazuh), cliente SSH |

**Aplicación vulnerable:** se usó **DVWA (Damn Vulnerable Web Application)** en un contenedor
Docker (`vulnerables/web-dvwa`), publicando el puerto 80. El código web se copió a
`/var/www/dvwa` en el anfitrión del contenedor para que el monitoreo de integridad de archivos
(FIM) de Wazuh pueda vigilarlo. DVWA permite practicar inyección SQL, fuerza bruta, carga de
archivos (webshell) y XSS de forma controlada, lo que encaja con los cuatro ataques exigidos.

**Diagrama de arquitectura:** ver `docs/diagramas/arquitectura.svg`.

Decisiones de diseño y su razón:

* **Tres máquinas separadas** (atacante, objetivo y SIEM) para reproducir una segmentación
  realista: el SIEM nunca comparte host con lo que vigila, de modo que un compromiso del
  servidor web no afecta a la plataforma de monitoreo.
* **Red host-only sin salida a Internet**, para cumplir la restricción ética de atacar solo
  recursos propios y no exponer la aplicación vulnerable.
* **El objetivo concentra el IDS de red (Suricata) y el agente Wazuh**, de modo que cada ataque
  se detecta en dos capas: red (Suricata) y host (Wazuh: logs, FIM).

## 2.2 Control de acceso (denegación por defecto)

El control de acceso se construyó bajo el principio de **denegación por defecto** (*deny by
default*): todo el tráfico entrante se bloquea y solo se abren, de forma explícita, los flujos
estrictamente necesarios y únicamente desde las IP del equipo. Se implementó con **UFW/iptables**
en el objetivo y el SIEM, más el endurecimiento de SSH.

**Política base (ambas máquinas):**
```
ufw default deny incoming      # nada entra salvo lo permitido abajo
ufw default allow outgoing     # las VM pueden actualizarse / responder
ufw default deny routed        # no se reenvía tráfico entre redes
```

**Tabla de reglas de firewall y su justificación:**

| Regla | Máquina | Origen permitido | Puerto / Proto | Servicio | Justificación |
|---|---|---|---|---|---|
| **R1** | Objetivo y SIEM | 192.168.56.1 (laptop admin) | 22/tcp | SSH | Administración remota solo desde la estación del equipo; ninguna otra IP puede intentar SSH |
| **R2** | Objetivo | 192.168.56.1 (laptop) | 80/tcp | DVWA | La aplicación web solo es visible para el administrador |
| **R3** | Objetivo | 192.168.56.30 (Kali) | 80/tcp | DVWA | La Kali del equipo necesita acceso para las pruebas de ataque autorizadas |
| **R4** | Objetivo | (DOCKER-USER) | 80/tcp | DVWA/Docker | Docker publica puertos por la cadena FORWARD y **se salta UFW**; se replica la política R2/R3 en `DOCKER-USER` y se descarta y registra el resto |
| **R5** | SIEM | 192.168.56.1 (laptop) | 443/tcp | Panel Wazuh | El dashboard solo se consulta desde la estación de administración |
| **R6** | SIEM | 192.168.56.10 (objetivo) | 1514/tcp | Eventos de agente | Solo el agente del objetivo envía eventos al manager |
| **R7** | SIEM | 192.168.56.10 (objetivo) | 1515/tcp | Registro de agente | Solo el objetivo puede registrarse como agente |
| — | SIEM | (ninguno externo) | 9200, 55000 | Indexer / API | Quedan **solo en localhost**; denegados por defecto desde la red |

**Endurecimiento de SSH** (`/etc/ssh/sshd_config.d/10-soc-hardening.conf`):

* `PubkeyAuthentication yes` + `PasswordAuthentication no` → **solo llaves**, no contraseñas.
* `PermitRootLogin no` → nunca se inicia sesión como root (se usa un usuario con `sudo`).
* `MaxAuthTries 3` y `LoginGraceTime 30` → menos margen para fuerza bruta.
* `AllowUsers` limita el acceso a un único usuario por máquina.

**Efecto comprobado:** en el ataque 1 (escaneo de puertos), el puerto 22 del objetivo aparece
**filtrado** desde Kali, porque R1 solo admite SSH desde la laptop. Esto confirma que el control
de acceso reduce la superficie de ataque visible para un atacante en la misma red.

## 2.3 Monitoreo

El monitoreo combina dos fuentes que convergen en el panel central de Wazuh:

**1. IDS de red – Suricata (en el objetivo).** Inspecciona el tráfico de la interfaz del
laboratorio (`enp0s8`) con `HOME_NET = 192.168.56.0/24`, usando el conjunto de reglas **ET Open**
más las reglas propias del equipo (sección 2.5). Genera alertas en formato **EVE JSON**
(`/var/log/suricata/eve.json`).

**2. HIDS y SIEM – Wazuh (agente en el objetivo → manager en el SIEM).** El agente
`web-tiendacr` reenvía al manager:

* **Alertas de Suricata** (`localfile` tipo `json` sobre `eve.json`), de modo que todo el IDS
  de red se ve en el mismo panel.
* **Logs web de DVWA** (Apache *access.log* y *error.log*), para detectar intentos de login,
  errores 4xx/5xx y patrones de ataque sobre la aplicación.
* **Integridad de archivos (FIM)** en tiempo real sobre `/var/www/dvwa`, con `report_changes` y
  `alert_new_files`, para detectar la creación o modificación de archivos (por ejemplo, una
  webshell subida al directorio de cargas).
* **Detección de vulnerabilidades**, que correlaciona el inventario de paquetes del host con
  bases de CVE (sección 1.3.4).

**Sincronización agente → SIEM:** el agente se conecta al manager por el puerto 1514 (eventos) y
1515 (registro), ambos restringidos por la regla R6/R7. En las pruebas, el tiempo de transporte
entre que Suricata genera una alerta y esta aparece en el panel central fue de **1 a 2 segundos**.

**Visualización:** el analista consulta el módulo *Threat Hunting → Events* del dashboard de
Wazuh (`https://192.168.56.20`), donde filtra por `rule.id`, `data.srcip` o técnica MITRE. Las
reglas propias del equipo (rango 100100–100199 en Wazuh y 1000001–1000004 en Suricata) elevan el
nivel de las alertas relevantes para que resalten sobre el ruido de fondo.
