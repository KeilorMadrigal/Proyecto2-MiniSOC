# Proyecto 2 — Mini SOC en la nube (TiendaCR)

Mini centro de operaciones de seguridad (SOC) para la tienda ficticia **TiendaCR**, montado en
un laboratorio local de VirtualBox que simula un despliegue en la nube (IaaS). Detecta, responde
y remedia ataques reales contra una aplicación web vulnerable.

**Curso:** ITI-922 Seguridad de TI II · **Integrantes:** Keilor Madrigal Ramírez · Raúl Quesada Morera

> ⚠️ **Uso educativo.** Todo el entorno es un laboratorio aislado (red *host-only*, sin salida a
> Internet). Los ataques se ejecutan **solo** contra máquinas propias del equipo. No usar estas
> herramientas ni reglas contra sistemas de terceros.

## Arquitectura

| Rol | Nombre | IP | Software |
|---|---|---|---|
| SIEM | siem-tiendacr | 192.168.56.20 | Wazuh 4.14 (manager, indexer, dashboard) |
| Objetivo | web-tiendacr | 192.168.56.10 | Docker + DVWA, Suricata (IDS), agente Wazuh |
| Atacante | Kali-Atacante | 192.168.56.30 | nmap, Hydra, curl |
| Administración | Laptop | 192.168.56.1 | Navegador, SSH (host VirtualBox) |

Red solo-anfitrión `192.168.56.0/24`. Diagrama: [`docs/diagramas/arquitectura.svg`](docs/diagramas/arquitectura.svg).

## Estructura del repositorio

```
informe/        Informe por secciones (Markdown) y el PDF final
docs/
  capturas/     Capturas de pantalla de ataques, detección y remediación
  diagramas/    Diagrama de arquitectura (SVG)
objetivo/       Scripts del servidor objetivo
  setup-objetivo.sh      Docker + DVWA + Suricata + agente Wazuh
  hardening/hardening.sh Control de acceso (UFW/SSH) — ROLE=objetivo|siem
  suricata/rules/        Reglas propias de Suricata (local.rules)
siem/wazuh/     Reglas, decodificadores y respuesta activa de Wazuh
atacante/scripts/        Scripts de los ataques (ejecutar solo en el laboratorio)
riesgos/        Análisis de riesgos (fase 1)
```

## Puesta en marcha (resumen reproducible)

Requisitos: VirtualBox 7.x, ~11 GB de RAM libres para las 3 VM, imágenes de Ubuntu Server 24.04,
Kali y un Ubuntu para el SIEM.

1. **Red:** crear el adaptador *host-only* `192.168.56.0/24` (anfitrión `.1`). Asignar IP fijas
   a cada VM (`.10`, `.20`, `.30`).
2. **SIEM (192.168.56.20):** instalar Wazuh 4.14 todo-en-uno y aplicar el control de acceso:
   ```bash
   sudo ROLE=siem bash objetivo/hardening/hardening.sh
   # copiar reglas y respuesta activa:
   sudo cp siem/wazuh/rules/local_rules.xml /var/ossec/etc/rules/
   # añadir el bloque <active-response> de siem/wazuh/active-response/ a /var/ossec/etc/ossec.conf
   sudo systemctl restart wazuh-manager
   ```
3. **Objetivo (192.168.56.10):**
   ```bash
   sudo SIEM_IP=192.168.56.20 LAB_IF=enp0s8 bash objetivo/setup-objetivo.sh
   sudo cp objetivo/suricata/rules/local.rules /etc/suricata/rules/
   sudo ROLE=objetivo bash objetivo/hardening/hardening.sh
   sudo systemctl restart suricata wazuh-agent
   ```
   Completar la instalación de DVWA en `http://192.168.56.10/setup.php`.
4. **Atacante (Kali):** las herramientas ya vienen incluidas. Los scripts de ataque están en
   `atacante/scripts/`.
5. **Panel:** abrir `https://192.168.56.20` (usuario `admin`) desde la laptop.

## Ataques incluidos (laboratorio)

| # | Ataque | Herramienta | Detección | MITRE |
|---|---|---|---|---|
| 1 | Escaneo de puertos | nmap | Suricata 1000001 → Wazuh 100120 | T1046 |
| 2 | Fuerza bruta web | Hydra | Wazuh 100100/100101 + respuesta activa | T1110.001 |
| 3 | Inyección SQL | curl | Suricata 1000003 → Wazuh 100120 | T1190 |
| 4 | Webshell / RCE | curl | FIM Wazuh 100110 + Suricata 1000004 | T1505.003 |

## Seguridad y credenciales

Este repositorio **no** contiene contraseñas, llaves privadas ni tokens (ver `.gitignore`). Las
credenciales del laboratorio se guardan **fuera** del repositorio. Las capturas no muestran
secretos.

## Documentación

El informe completo está en [`informe/`](informe/) (secciones en Markdown) y en el PDF final
`informe/P1_Madrigal_Quesada.pdf`.
