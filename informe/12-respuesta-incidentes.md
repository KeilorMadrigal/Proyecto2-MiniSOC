## 2.7 Plan de respuesta a incidentes

El plan sigue las seis fases del ciclo de respuesta a incidentes de **NIST SP 800-61** adaptadas
al tamaño de TiendaCR. El equipo de respuesta son los dos integrantes, que asumen los roles de
**analista** (triaje y contención) y **responsable de sistemas** (erradicación y recuperación).

### Fase 1 — Preparación
* Mini SOC desplegado: Suricata (IDS), Wazuh (SIEM, FIM, vulnerabilidades) y respuesta activa.
* Control de acceso *deny-by-default* y SSH endurecido (sección 2.2).
* Respaldo de las configuraciones en el repositorio Git y credenciales fuera del repositorio.
* Reglas propias con técnica MITRE ATT&CK asociada para acelerar el diagnóstico.

### Fase 2 — Detección y análisis
* **Fuente primaria:** panel de Wazuh (`Threat Hunting → Events`), filtrando por `rule.level`,
  `data.srcip` y técnica MITRE.
* **Clasificación por severidad** (nivel de la regla de Wazuh):

  | Severidad | Nivel Wazuh | Ejemplo | Tiempo objetivo de respuesta |
  |---|---|---|---|
  | Crítica | 12+ | Webshell creada (100110) | Inmediato |
  | Alta | 10–11 | Fuerza bruta (100101), SQLi (100120) | < 15 min |
  | Media | 5–9 | Errores 4xx repetidos, escaneo | < 1 h |
  | Baja | 1–4 | Intento de login aislado (100100) | Revisión diaria |

* **Triaje:** identificar IP origen, activo afectado, técnica (MITRE) y si el ataque tuvo éxito
  (por ejemplo, en la SQLi, revisar si hubo exfiltración de datos en los logs).

### Fase 3 — Contención
* **Automática:** la respuesta activa ya bloquea la IP atacante en el firewall por 180 s (fuerza
  bruta web y SSH).
* **Manual (si el ataque persiste o escala):** extender el bloqueo de la IP de forma permanente
  (`ufw deny from <IP>`), aislar el contenedor DVWA (`docker stop dvwa`) o desconectar la
  interfaz de red del objetivo, según la gravedad.

### Fase 4 — Erradicación
* Eliminar artefactos del atacante: por ejemplo, borrar la webshell detectada por el FIM
  (`/var/www/dvwa/hackable/uploads/*.php`) y revisar que no queden puertas traseras.
* Identificar y corregir la vulnerabilidad explotada (ver remediación, sección 2.8).
* Rotar credenciales si hubo exfiltración (en la SQLi se expusieron los hashes de los usuarios).

### Fase 5 — Recuperación
* Restaurar la aplicación a un estado seguro (nivel endurecido / código con *prepared statements*).
* Verificar con Wazuh que el activo vuelve a un estado normal y que el ataque ya no tiene éxito
  (se repiten los ataques controlados para confirmar, sección 2.8).
* Reforzar el monitoreo de la IP o el patrón involucrado durante un periodo de vigilancia.

### Fase 6 — Lecciones aprendidas
* Documentar el incidente: línea de tiempo, regla que lo detectó, tiempo hasta la alerta, acción
  tomada y resultado (como en las tablas de la sección 2.4).
* Ajustar reglas y umbrales para reducir falsos positivos/negativos.
* Actualizar este plan y el inventario de riesgos con lo aprendido.

### Guía rápida por tipo de incidente

| Incidente | Detección | Contención | Erradicación / Recuperación |
|---|---|---|---|
| Escaneo de puertos | Suricata 1000001 → Wazuh 100120 | Vigilar la IP; bloquear si escala | Confirmar que no siguió a explotación |
| Fuerza bruta (web/SSH) | Wazuh 100101 / 5712 / 5763 | **Bloqueo automático** 180 s | Forzar contraseñas fuertes + MFA; bloqueo permanente si reincide |
| Inyección SQL | Suricata 1000003 → Wazuh 100120 | Bloquear IP | Parametrizar consultas; rotar credenciales expuestas |
| Webshell / RCE | Wazuh 100110 (FIM) + Suricata 1000004 | Bloquear IP; `docker stop dvwa` | Borrar la webshell; restringir cargas; revisar persistencia |
