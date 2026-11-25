# Proyecto 2 — Mini SOC en la nube

### Tienda en línea ficticia *TiendaCR*

**Curso:** ITI-922 Seguridad de TI II
**Profesor:** Marcos C.
**Integrantes:** Keilor Madrigal Ramírez · Raúl Quesada Morera
**Fecha:** 24 de noviembre de 2026
**Repositorio:** (público en GitHub — ver README)

---

## Resumen ejecutivo

Este proyecto implementa un **centro de operaciones de seguridad (SOC) en miniatura** para la
tienda en línea ficticia TiendaCR, montado en un laboratorio local de VirtualBox que simula un
despliegue en la nube (IaaS). El objetivo es **detectar, responder y remediar** ataques reales
contra una aplicación web vulnerable, aplicando los conceptos del curso: modelo de
responsabilidad compartida, análisis de riesgos, defensa en profundidad y monitoreo continuo.

La arquitectura combina tres componentes de código abierto sobre tres máquinas separadas: una
**Kali** atacante, un **servidor objetivo** (Ubuntu Server con DVWA en Docker, el IDS **Suricata**
y un agente **Wazuh**) y un **SIEM Wazuh** independiente. El acceso se rige por **denegación por
defecto**, con reglas de firewall que solo permiten los flujos del equipo y SSH con llaves.

Se ejecutaron y documentaron **cuatro ataques** (escaneo de puertos, fuerza bruta, inyección SQL
y webshell con ejecución remota de comandos), cada uno detectado por reglas propias con su
técnica **MITRE ATT&CK** y su tiempo hasta la alerta (entre <0.1 s y 2 s). La **respuesta
automática** bloqueó la fuerza bruta en vivo, antes de que tuviera éxito. Finalmente se
**remediaron** las vulnerabilidades (consultas preparadas, token Anti-CSRF, bloqueo de cuenta y
restricción de cargas) y se **repitieron los ataques** para comprobar, con evidencia, que la
explotación ya falla mientras la detección se mantiene.

| Métrica del laboratorio | Resultado |
|---|---|
| Ataques ejecutados y detectados | 4 / 4 |
| Reglas propias (Suricata / Wazuh) | 4 / 4 |
| Tiempo medio hasta la alerta | 1–2 s |
| Respuesta automática | Fuerza bruta bloqueada en ~1.8 s |
| Vulnerabilidades reales detectadas (Wazuh) | 101 críticas / 803 altas |
| Ataques mitigados tras remediación | SQLi y fuerza bruta (0 datos filtrados) |

## Contenido del informe

1. **Fase 1 — Investigación:** comparativa de herramientas, responsabilidad compartida, análisis
   de riesgos (NIST/ISO), puntajes CVSS y plan de tratamiento.
2. **Fase 2 — Implementación:**
   - 2.1 Despliegue · 2.2 Control de acceso · 2.3 Monitoreo
   - 2.4 Ataques controlados y detección
   - 2.5 Reglas personalizadas · 2.6 Respuesta automática
   - 2.7 Plan de respuesta a incidentes · 2.8 Remediación y verificación
3. **Conclusiones y referencias.**

---

## Declaración de uso de inteligencia artificial

En la elaboración de este proyecto se utilizó el asistente de IA **Claude (Anthropic)** como
apoyo para: (a) estructurar y redactar el informe, (b) generar y depurar los *scripts* de
despliegue, las reglas de Suricata/Wazuh y los comandos de ataque, (c) interpretar los registros
(`eve.json`, `alerts.json`) para calcular los tiempos de detección, y (d) diagnosticar problemas
del laboratorio (espacio en disco y memoria del SIEM).

**Alcance y responsabilidad:** todas las máquinas, reglas, ataques y capturas fueron **ejecutadas
y verificadas por los integrantes** en su propio laboratorio; la IA no tuvo acceso a sistemas de
terceros. El contenido técnico se revisó y comprendió antes de incorporarlo; los integrantes son
los responsables del resultado final y están en capacidad de explicar cada componente. El uso de
IA se declara en cumplimiento de los lineamientos de integridad académica del curso.
