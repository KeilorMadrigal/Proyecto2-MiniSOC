# 2.8 Remediación y verificación

Tras documentar los cuatro ataques se aplicaron medidas de remediación sobre el servidor
objetivo y se **repitieron los ataques 2 (fuerza bruta) y 3 (inyección SQL)** para comprobar,
con evidencia, que las vulnerabilidades quedaron mitigadas. Todas las pruebas se lanzaron de
nuevo desde **Kali-Atacante (192.168.56.30)**.

## Medidas de remediación aplicadas

| Ataque | Causa raíz | Remediación aplicada | Capa |
|---|---|---|---|
| 3 – Inyección SQL | La entrada del parámetro `id` se concatenaba directamente en la consulta | **Consultas preparadas (PDO)** con parámetros enlazados (`bindParam ... PDO::PARAM_INT`) y validación `is_numeric($id)` | Aplicación (código seguro) |
| 2 – Fuerza bruta | Login sin control de automatización ni límite de intentos | **Token Anti-CSRF rotativo** (`checkToken`), **bloqueo de cuenta** 15 min tras 3 fallos y consultas preparadas | Aplicación (código seguro) |
| 4 – Webshell (defensa en profundidad) | Carga de archivos sin validar el tipo real y ejecutables desde el directorio de cargas | DVWA valida que sea una imagen real; además se añadió un **`.htaccess`** que **desactiva la ejecución de PHP** en `hackable/uploads/` (`php_flag engine off` + `Require all denied` para `*.php`) | Infraestructura (servidor web) |
| Todos | — | Se mantienen el **IDS Suricata**, el **SIEM Wazuh** y la **respuesta automática** como controles compensatorios (detección y contención) | Red / monitoreo |

Implementación concreta: se configuró el nivel de seguridad de la aplicación en
`impossible` (`$_DVWA['default_security_level'] = 'impossible'` en `config/config.inc.php`),
perfil que en DVWA representa el **código desarrollado con buenas prácticas** (consultas
preparadas, token Anti-CSRF, bloqueo de cuenta y validación estricta de cargas), frente al
perfil `low` usado en los ataques originales.

## Comparación antes / después

| Ataque | Antes de remediar (nivel `low`) | Después de remediar (nivel `impossible`) |
|---|---|---|
| 3 – Inyección SQL | El payload `UNION SELECT user, password FROM users` devolvió **5 usuarios con sus hashes MD5** y la versión de la BD | El **mismo** payload devolvió **0 filas de datos**: la consulta preparada trata la entrada como un valor, no como código SQL. Fuga de credenciales = **ninguna** |
| 2 – Fuerza bruta | Hydra enviaba intentos sin límite; a nivel `low` la contraseña era descifrable (y solo se frenó por la respuesta automática) | El intento automatizado es **rechazado** con `CSRF token is incorrect` **antes** de validar credenciales: sin el token rotativo (que cambia en cada carga de página) una herramienta como Hydra no puede continuar. Además, tras 3 fallos la cuenta se bloquea 15 min |

Resultado de la verificación (salida real de la re-ejecución desde Kali):
```
ATAQUE 3 (SQLi)  -> filas de datos filtradas: 0   (ANTES de remediar: 5 usuarios + hash)
ATAQUE 2 (Fuerza bruta) -> RECHAZADO: 'CSRF token is incorrect'
```

## La detección se mantiene (defensa en profundidad)

Un punto clave: aunque la **explotación** ya falla, la **detección sigue activa**. Al repetir
la inyección SQL, Suricata volvió a generar la alerta propia **sid 1000003** ("TiendaCR -
Inyeccion SQL en parametro id") y Wazuh la elevó con la regla **100120** — igual que en el
ataque original. Es decir, el SOC seguiría viendo y registrando el intento aunque la
aplicación ya no sea vulnerable, lo que permite identificar al atacante y responder.

| Hora (CR, UTC-6) | Evento |
|---|---|
| 17:51:04 / 17:55:18 | Suricata `eve.json` sid **1000003** sobre el payload de SQLi lanzado tras la remediación (la aplicación no filtró datos, pero el IDS sí alertó) |

## Riesgo residual

Ninguna medida elimina el riesgo por completo; queda un **riesgo residual** que se asume y se
vigila:

| Riesgo residual | Descripción | Control / mitigación vigente |
|---|---|---|
| Credenciales débiles o reutilizadas | Un atacante con credenciales válidas (phishing, fuga externa) entraría de forma legítima; la fuerza bruta solo se mitigó, no se elimina el valor de una contraseña robada | Bloqueo de cuenta, MFA (recomendado a futuro), monitoreo de inicios de sesión anómalos en Wazuh |
| Vulnerabilidades nuevas o de día cero | El código seguro de hoy no protege contra fallos aún desconocidos en la app o sus dependencias | IDS/SIEM, actualización periódica, gestión de vulnerabilidades |
| Falsos negativos del IDS | Variantes de payload que evadan las firmas propias podrían no generar alerta | Reglas ET Open además de las propias, revisión y ajuste de reglas |
| Movimiento lateral si hay compromiso | Si un atacante lograse ejecución (p. ej. otra vía), podría intentar pivotar | Control de acceso *deny-by-default*, segmentación, principio de menor privilegio |
| Error humano / desactivación de controles | Bajar el nivel de seguridad o desactivar una regla reintroduce el riesgo | Gestión de cambios, respaldo de configuración en el repositorio |

**Nivel de riesgo tras remediar:** los riesgos R-SQLi y R-FuerzaBruta pasan de severidad
**alta/crítica** a **baja**, al combinarse la corrección del código (prevención) con la
detección y la respuesta automática (contención). El riesgo no llega a cero por los factores
residuales anteriores, que se gestionan de forma continua.

**Captura:** `docs/capturas/remediacion-antes-despues.png` (re-ejecución de los ataques 2 y 3
contra la versión endurecida: 0 datos filtrados y fuerza bruta rechazada por el token).
