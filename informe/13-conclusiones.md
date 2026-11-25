## Conclusiones

1. **La defensa en profundidad funciona.** Combinar un IDS de red (Suricata) con un HIDS/SIEM
   (Wazuh) permitió detectar cada ataque en dos capas independientes. El caso más claro es la
   webshell: el FIM de Wazuh atrapó la *creación* del archivo y Suricata su *ejecución*, de modo
   que el ataque se habría detectado aunque una de las dos capas fallara.

2. **El control de acceso reduce la superficie de ataque de forma medible.** Con denegación por
   defecto, el escaneo de puertos desde Kali solo vio el puerto 80; el 22 (SSH) quedó filtrado.
   Un atacante en la misma red obtiene mucha menos información sobre el objetivo.

3. **La detección es casi inmediata, pero detectar no es prevenir.** Los tiempos hasta la alerta
   fueron de 1 a 2 segundos, pero la inyección SQL llegó a exfiltrar las credenciales antes de
   que un humano pudiera reaccionar. Esto justifica la **respuesta automática**: en la fuerza
   bruta, el bloqueo en el firewall detuvo el ataque en ~1.8 s, sin intervención.

4. **La respuesta automática exige equilibrio.** Un bloqueo mal ajustado puede dejar sin servicio
   a usuarios legítimos; por eso se usó bloqueo temporal, lista blanca y un umbral prudente, y se
   recomienda un periodo de ajuste en modo alerta antes de activarlo en producción.

5. **La remediación en el código es la solución de fondo.** Las consultas preparadas y el token
   Anti-CSRF eliminaron la explotación (0 datos filtrados en la SQLi, fuerza bruta rechazada),
   mientras el monitoreo siguió alertando: prevención + detección. El SOC detecta y contiene, pero
   el riesgo baja de verdad cuando se corrige la causa raíz.

6. **El SIEM aporta visibilidad más allá de los ataques simulados.** El módulo de vulnerabilidades
   de Wazuh reveló 101 CVE críticos reales en el objetivo (incluido uno con CVSS 10.0 en el
   kernel), lo que permite priorizar el parcheo como parte de la gestión de riesgos.

**Limitaciones y mejoras futuras:** el laboratorio corre sobre 16 GB de RAM, lo que obligó a
dimensionar con cuidado el SIEM (8 GB) y a desactivar el actualizador del feed de vulnerabilidades
para no agotar el disco. Como mejora, se podría añadir **Falco** para vigilar el contenedor en
tiempo de ejecución, **CrowdSec** para reputación de IP, autenticación **MFA** en la aplicación y
un segundo nodo de Wazuh para alta disponibilidad.

---

## Referencias (APA 7)

Las referencias completas se encuentran al final de la Fase 1 (sección de Investigación) e
incluyen: Dotson (2019); Guijarro Olivares, Caparrós Ramírez y Cubero Luque (2019); NIST SP
800-30 Rev. 1 (2012); NIST SP 800-61; documentación de Wazuh (2026) y Suricata (2026); AWS
GuardDuty; Microsoft (responsabilidad compartida y Defender for Cloud); FIRST CVSS v3.1 (2019);
OWASP Top 10:2025; y MITRE ATT&CK (2026).
