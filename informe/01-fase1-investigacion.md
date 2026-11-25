# Fase 1. Investigación

> Proyecto 2 — Mini SOC en la nube · ITI-922 Seguridad de TI II
> Integrantes: Keilor Madrigal Ramírez · Raúl Quesada Morera
> Escenario: tienda en línea ficticia **TiendaCR** (laboratorio local en VirtualBox)

## 1.1 Comparativa de herramientas de seguridad en la nube

Se compararon seis herramientas: una de proveedor cloud (AWS GuardDuty), una de proveedor con modelo híbrido (Microsoft Defender for Cloud) y cuatro de código abierto (Wazuh, Suricata, Falco y CrowdSec). Los criterios son los exigidos en el enunciado.

| Criterio | AWS GuardDuty | Microsoft Defender for Cloud | Wazuh | Suricata | Falco | CrowdSec |
|---|---|---|---|---|---|---|
| **Qué detecta o protege** | Cuentas, identidades (IAM), red (VPC Flow Logs, DNS) y cargas de trabajo en AWS | Postura de configuración (CSPM) y cargas de trabajo (servidores, contenedores, BD) en Azure, AWS y GCP | Host: logs, autenticación, integridad de archivos (FIM), vulnerabilidades, configuración (SCA) | Red: tráfico en tiempo real (IDS/IPS) y metadatos de protocolos (HTTP, DNS, TLS) | Host/contenedores: llamadas al sistema en tiempo de ejecución | Host/red: comportamiento malicioso en logs (fuerza bruta, escaneos) |
| **Cómo detecta** | Inteligencia de amenazas, aprendizaje automático y detección de anomalías | Recomendaciones basadas en políticas y analítica de comportamiento | Reglas y decodificadores XML sobre eventos; correlación | Firmas (reglas tipo Snort/ET Open) y análisis de protocolos | Reglas sobre syscalls (eBPF) | "Escenarios" (reglas) sobre logs + reputación colaborativa de IP |
| **Modelo de despliegue y recursos** | SaaS administrado; se activa por cuenta y región, sin agentes para la detección base | SaaS en el portal de Azure; agentes o escaneo sin agente según el plan | Servidor + indexador + panel (mín. ~4 vCPU / 8 GB RAM para todo en uno) y agentes livianos | Proceso en el host o sensor de red; 1–2 vCPU y 1–2 GB RAM para tráfico bajo | DaemonSet o servicio en el host; consumo bajo | Agente + "bouncers" (componentes que bloquean); muy liviano |
| **Costo y licencia** | Pago por uso (volumen de eventos analizados); prueba de 30 días | Nivel gratuito de CSPM básico; planes de pago por recurso protegido | Gratuito, GPLv2 | Gratuito, GPLv2 (OISF) | Gratuito, Apache 2.0 (CNCF) | Núcleo gratuito (MIT); consola y listas premium de pago |
| **Respuesta automática** | No bloquea por sí mismo; se automatiza con EventBridge + Lambda | Respuesta mediante Logic Apps (*workflow automation*) | Sí: *Active Response* (por ejemplo, bloquear la IP en el firewall) | Sí, en modo IPS (*inline*, con NFQUEUE) | No nativa; se usa Falcosidekick o Talon | Sí: los *bouncers* bloquean en el firewall o en nginx |
| **Integración** | Security Hub, Detective, SIEM externos | Microsoft Sentinel, Defender XDR | Suricata, VirusTotal, Slack, nubes (AWS, Azure, GCP), API REST | Wazuh, Elastic, Splunk (vía EVE JSON) | Falcosidekick (Slack, SIEM), Kubernetes | Firewalls, nginx, Cloudflare, Wazuh |
| **Limitaciones** | Solo para AWS; no inspecciona el contenido de los paquetes | Cobertura completa solo con planes de pago; está centrado en Azure | Consumo alto de RAM del indexador; curva de aprendizaje de las reglas | Sin TLS descifrado no ve el contenido cifrado; falsos positivos sin ajuste | Solo Linux; no ve la red | Depende de la calidad de los logs; reputación comunitaria |

### Justificación de la elección

Para TiendaCR, que es un único servidor web en un laboratorio sin presupuesto, se eligió:

* **Wazuh como SIEM/HIDS**, porque en una sola plataforma gratuita cubre tres de los requisitos de la fase 2: inspección de logs de autenticación, integridad de archivos y detección de vulnerabilidades. Además trae *Active Response* para la respuesta automática y un panel central. Su mayor costo es la RAM del indexador, por eso se le dedica una máquina propia de 6 GB.
* **Suricata como IDS de red**, porque genera alertas a partir de firmas sobre el tráfico HTTP (inyección SQL, XSS, *path traversal*) y escaneos de puertos. Su salida EVE JSON se integra de forma nativa con el agente de Wazuh, lo que permite ver todas las alertas en el mismo panel.
* **Se descartaron GuardDuty y Defender for Cloud** porque el laboratorio es local: no hay cuenta de nube que monitorear y ambas tienen costo. Aun así, se usan como referencia del modelo de responsabilidad compartida (sección 1.2).
* **Falco y CrowdSec** quedan como mejoras futuras. Falco serviría para vigilar el contenedor de DVWA en tiempo de ejecución, y CrowdSec aportaría reputación colaborativa de IP. No se incluyen para no superar la RAM disponible (16 GB para tres VM).

## 1.2 Modelo de responsabilidad compartida

El laboratorio es local, así que se toma como **proveedor de referencia Microsoft Azure con una máquina virtual (IaaS)**. Es la opción que ofrece Azure for Students y equivale a ejecutar TiendaCR en la nube.

| Capa | Responsable en una VM IaaS | Qué implica para TiendaCR |
|---|---|---|
| Centro de datos físico, energía, red física | **Proveedor** | — |
| Hipervisor y aislamiento entre clientes | **Proveedor** | En el laboratorio lo asume VirtualBox en la laptop del equipo |
| Red virtual y grupos de seguridad (NSG) | **Compartida**: el proveedor da el servicio y el cliente define las reglas | Denegación por defecto y acceso solo desde las IP del equipo (fase 2.2) |
| Sistema operativo invitado (parches, configuración) | **Cliente** | Ubuntu Server actualizado, SSH solo con llaves y sin root |
| Aplicaciones y contenedores | **Cliente** | DVWA en Docker; remediar sus vulnerabilidades (fase 2.8) |
| Identidades y accesos | **Cliente** | Llaves SSH, usuarios con menor privilegio, credenciales fuera del repositorio |
| Datos y su clasificación | **Cliente** | Solo datos ficticios en el escenario |
| Monitoreo, detección y respuesta | **Cliente** (el proveedor ofrece herramientas opcionales) | Wazuh + Suricata + respuesta automática |

Según Dotson (2019), en IaaS la mayor parte de los incidentes se origina en la parte que le toca al cliente: configuraciones abiertas a internet, credenciales expuestas y sistemas sin parches. Guijarro et al. (2019) destacan que en entornos DevOps esa responsabilidad debe automatizarse e integrarse al ciclo de despliegue. Por eso este proyecto concentra sus controles en las capas del cliente.

## 1.3 Análisis de riesgos del escenario (NIST SP 800-30 simplificado)

Se aplicó la metodología de evaluación de riesgos de NIST SP 800-30 Rev. 1 en forma simplificada: identificación de activos, amenazas y vulnerabilidades, y luego estimación de probabilidad e impacto en una escala de 1 a 5.

* **Nivel de riesgo** = Probabilidad × Impacto
* **Bajo:** 1–6 · **Medio:** 8–12 · **Alto:** 15–25

### 1.3.1 Inventario de activos

Valoración de 1 (bajo) a 5 (crítico) en cada dimensión de la tríada CID.

| ID | Activo | Tipo | C | I | D | Valor (máx.) |
|---|---|---|---|---|---|---|
| A1 | Aplicación web TiendaCR (DVWA en Docker) | Software | 4 | 5 | 4 | 5 |
| A2 | Base de datos de la aplicación (clientes y pedidos ficticios) | Información | 5 | 5 | 4 | 5 |
| A3 | Servidor objetivo (Ubuntu Server LTS) | Hardware virtual / SO | 4 | 5 | 4 | 5 |
| A4 | Servidor SIEM Wazuh | Hardware virtual / software | 4 | 4 | 3 | 4 |
| A5 | Credenciales y llaves SSH de administración | Información | 5 | 4 | 2 | 5 |
| A6 | Registros y alertas (evidencia) | Información | 3 | 5 | 3 | 5 |
| A7 | Red del laboratorio y reglas de firewall | Infraestructura | 2 | 5 | 4 | 5 |

### 1.3.2 Amenazas y vulnerabilidades por activo

| Activo | Amenaza | Vulnerabilidad |
|---|---|---|
| A1 | Inyección SQL | Consultas sin parametrizar en DVWA |
| A1 | XSS reflejado | Salida sin codificar |
| A1 | Carga de *webshell* | Carga de archivos sin validación de tipo |
| A1 | Inclusión de archivos o *path traversal* | Parámetro `page` sin validar |
| A2 | Robo de datos | Credenciales por defecto de la BD y de la aplicación |
| A3 | Fuerza bruta SSH | Autenticación por contraseña habilitada |
| A3 | Reconocimiento (escaneo) | Puertos expuestos innecesarios |
| A3 | Explotación de paquetes desactualizados | Falta de parches |
| A4 | Acceso no autorizado al panel | Panel expuesto o contraseña débil |
| A5 | Fuga de secretos | Credenciales subidas al repositorio o visibles en capturas |
| A6 | Borrado o alteración de logs | Logs solo locales en el objetivo |
| A7 | Regla demasiado permisiva | Acceso desde `0.0.0.0/0` |

### 1.3.3 Matriz de riesgos inicial (antes de controles)

| ID | Riesgo | Activo | P | I | Nivel | Clasificación |
|---|---|---|---|---|---|---|
| R1 | Inyección SQL extrae la BD de clientes | A1, A2 | 5 | 5 | 25 | Alto |
| R2 | Fuerza bruta contra el login de la aplicación | A1 | 5 | 4 | 20 | Alto |
| R3 | Fuerza bruta contra SSH | A3 | 4 | 5 | 20 | Alto |
| R4 | Carga de *webshell* y modificación de archivos web | A1, A3 | 4 | 5 | 20 | Alto |
| R5 | XSS reflejado roba la sesión de un administrador | A1 | 4 | 3 | 12 | Medio |
| R6 | Inclusión de archivos o *path traversal* lee archivos del sistema | A3 | 4 | 4 | 16 | Alto |
| R7 | Reconocimiento revela servicios y versiones | A3 | 5 | 2 | 10 | Medio |
| R8 | Explotación de paquetes del SO sin parches | A3 | 3 | 5 | 15 | Alto |
| R9 | Acceso no autorizado al panel del SIEM | A4 | 3 | 4 | 12 | Medio |
| R10 | Publicación de credenciales en GitHub | A5 | 3 | 5 | 15 | Alto |
| R11 | Borrado de logs por un atacante para ocultar el rastro | A6 | 3 | 4 | 12 | Medio |
| R12 | Respuesta automática bloquea a un usuario legítimo (falso positivo) | A1 | 3 | 3 | 9 | Medio |

### 1.3.4 Puntajes CVSS de vulnerabilidades usadas en el proyecto

Las vulnerabilidades de DVWA son intencionales y no tienen un CVE propio. Por eso se clasifican con su categoría OWASP Top 10:2025 y su CWE, y se calcula el puntaje CVSS v3.1 para el escenario de TiendaCR.

| Vulnerabilidad | OWASP Top 10:2025 / CWE | Vector CVSS v3.1 | Puntaje |
|---|---|---|---|
| Inyección SQL (módulo *SQL Injection*) | A05 Injection / CWE-89 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | **8.1 Alto** |
| Credenciales débiles + sin límite de intentos (*Brute Force*) | A07 Authentication Failures / CWE-307 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H | **9.8 Crítico** |
| Carga de archivos sin restricción (*File Upload* → webshell) | A06 Insecure Design / CWE-434 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | **8.8 Alto** |
| XSS reflejado | A05 Injection / CWE-79 | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | **6.1 Medio** |

**CVE real detectado por el módulo de detección de vulnerabilidades de Wazuh**

Además de las vulnerabilidades intencionales de DVWA, el *Vulnerability Detector* de Wazuh
analizó el inventario de paquetes del servidor objetivo (agente `web-tiendacr`) contra los
feeds de CVE y reportó **101 vulnerabilidades críticas** y **803 altas**. La de mayor
severidad detectada se tomó como caso real:

| Campo | Valor |
|---|---|
| CVE | **CVE-2026-74475** |
| Severidad | Crítica |
| Puntaje | **CVSS 10.0 (v3.1)** |
| Paquete afectado | `linux-image-6.8.0-151-generic` 6.8.0-151.151 (kernel Linux del objetivo) |
| Agente | web-tiendacr (192.168.56.10) |
| Publicado / Detectado | 15/08/2026 · detectado por Wazuh el 24/11/2026 |
| Descripción | Vulnerabilidad en el subsistema *vxlan* del kernel Linux: `route_shortcircuit()` leía la dirección de hardware del vecino (`n->ha`) sin tomar el *seqlock* `n->ha_lock`, lo que permite lecturas inconsistentes (*torn reads*) de la dirección MAC. Se corrige usando `neigh_ha_snapshot()` bajo `read_seqbegin()/read_seqretry()`. |
| Referencia | NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-74475 |

La captura `docs/capturas/wazuh-vulnerabilidades.png` (módulo *Vulnerability Detection*,
filtrada por severidad **Critical**) muestra el resumen de ese análisis: **101
vulnerabilidades críticas**, todas sobre el agente **web-tiendacr** y el paquete
**linux-image-6.8.0-151-generic** (el kernel del sistema operativo Ubuntu 24.04.5), junto con
el listado de CVE detectados. CVE-2026-74475 es la de mayor puntaje (CVSS 10.0) de ese
conjunto.

> Nota sobre la captura: aparece el aviso *"Vulnerabilities detection module is not enabled"*.
> Es intencional: una vez que el módulo pobló el inventario, se **desactivó su actualizador de
> feeds** para no volver a llenar el disco del SIEM (el feed de CVE ocupaba ~19 GB). El
> inventario ya recolectado (2669 registros, 101 críticos) permanece válido e indexado; solo
> se detuvo la descarga continua de nuevas definiciones.

Esto demuestra una ventaja del SIEM frente a las pruebas manuales: Wazuh correlaciona el
inventario de software del host con bases de CVE y prioriza por severidad, de modo que el
equipo de TiendaCR puede planificar el parcheo del sistema operativo (en este caso,
actualizar el kernel) como parte del tratamiento de riesgos.

### 1.3.5 Plan de tratamiento

| Riesgo | Opción | Control propuesto | Responsable |
|---|---|---|---|
| R1 | Mitigar | Consultas parametrizadas (nivel *impossible* de DVWA), regla Suricata propia de SQLi, WAF como mejora futura | Keilor (aplicación) |
| R2 | Mitigar | Límite de intentos, regla Wazuh propia y respuesta automática que bloquea la IP | Raúl (SIEM) |
| R3 | Mitigar | SSH solo con llaves, `PermitRootLogin no`, SSH permitido solo desde la IP del equipo, *Active Response* | Raúl (servidor) |
| R4 | Mitigar | FIM de Wazuh en tiempo real sobre el directorio web y validación del tipo de archivo | Keilor (aplicación) |
| R5 | Mitigar | Codificación de la salida, cabecera CSP y regla Suricata de XSS | Keilor (aplicación) |
| R6 | Mitigar | Lista blanca de páginas incluibles y regla Suricata de *path traversal* | Keilor (aplicación) |
| R7 | Mitigar | Denegación por defecto, solo los puertos necesarios y alerta de escaneo en Suricata | Raúl (red) |
| R8 | Mitigar | Detección de vulnerabilidades de Wazuh y `unattended-upgrades` | Raúl (servidor) |
| R9 | Mitigar | Panel solo accesible desde la red del laboratorio y contraseña robusta | Raúl (SIEM) |
| R10 | Evitar | `.gitignore` de secretos, revisión antes de cada *push* y difuminar capturas | Ambos |
| R11 | Mitigar | Envío centralizado de logs al SIEM (el atacante no puede borrar la copia central) | Raúl (SIEM) |
| R12 | Aceptar (con control) | Lista blanca de la IP de administración y bloqueo temporal (no permanente) | Ambos |

> La **reevaluación con riesgo residual** se completa en la sección 2.8, después de aplicar los controles y repetir los ataques.

## Referencias (APA 7)

Dotson, C. (2019). *Practical cloud security: A guide for secure design and deployment*. O'Reilly Media.

Guijarro Olivares, J., Caparrós Ramírez, J. J., & Cubero Luque, L. (2019). *DevOps y seguridad cloud*. Editorial UOC.

Joint Task Force Transformation Initiative. (2012). *Guide for conducting risk assessments* (NIST Special Publication 800-30 Rev. 1). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-30r1

Cichonski, P., Millar, T., Grance, T., & Scarfone, K. (2012). *Computer security incident handling guide* (NIST Special Publication 800-61 Rev. 2). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-61r2

Wazuh Inc. (2026). *Wazuh documentation* (versión 4.14). https://documentation.wazuh.com/current/

Open Information Security Foundation. (2026). *Suricata user guide*. https://docs.suricata.io/

Amazon Web Services. (2026). *What is Amazon GuardDuty?* https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html

Microsoft. (2026). *Shared responsibility in the cloud*. Microsoft Learn. https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility

Microsoft. (2026). *What is Microsoft Defender for Cloud?* Microsoft Learn. https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction

FIRST. (2019). *Common Vulnerability Scoring System v3.1: Specification document*. https://www.first.org/cvss/v3.1/specification-document

OWASP Foundation. (2025). *OWASP Top 10:2025*. https://owasp.org/Top10/

The MITRE Corporation. (2026). *MITRE ATT&CK*. https://attack.mitre.org/
