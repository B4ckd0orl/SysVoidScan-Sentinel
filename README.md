<div align="center">

# 🛡️ SysVoidScan · Sentinel

### Framework de pentesting web automatizado con **83 fases obligatorias**

*Reconocimiento → Explotación → Cadenas de ataque → Post-explotación → Informes*

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white&style=flat-square)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-165%20pasando-brightgreen?style=flat-square)](#-tests)
[![Versión](https://img.shields.io/badge/version-3.0.0%20Sentinel-e91e63?style=flat-square)](CHANGELOG.md)
[![SARIF](https://img.shields.io/badge/informes-SARIF%202.1.0-8A2BE2?style=flat-square)](#-informes)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows%20%7C%20Linux-0078D6?style=flat-square)](#-instalación)

**Solo para sistemas en los que tengas autorización explícita.**

</div>

---

## ✨ ¿Qué hace?

SysVoidScan es un escáner de seguridad ofensiva que ejecuta un **pentest completo de principio a fin** desde un menú interactivo: descubre el objetivo, lo ataca de verdad (inyección, explotación, encadenamiento de vulnerabilidades), y lo documenta en informes listos para entregar.

| | |
|:--|:--|
| 🎯 **83 fases encadenadas** | Cada fase alimenta a la siguiente: los hallazgos del escáner alimentan los exploiters, los exploiters alimentan las cadenas de ataque, y todo termina en informes. |
| ⚔️ **Explotación real** | 16 exploiters (SQLi, XSS, SSRF, SSTI, XXE, CMDi, LFI, JWT, OAuth, GraphQL, deserialización…) + 10 cadenas de ataque tipo *SQLi → webshell → RCE*. |
| 🛰️ **Integración con herramientas bestia** | Nuclei, ffuf, subfinder, httpx, katana, dalfox, gobuster, sqlmap — con wordlists de SecLists y plantillas oficiales de Nuclei. |
| 📈 **Informes en 7 formatos** | HTML, dashboard, JSON, Markdown, TXT, CSV y **SARIF 2.1.0** (listo para GitHub Advanced Security / CI-CD), más mapeo de *compliance* y guía de remediación. |
| 🧪 **165 tests** | Suite de pytest integrada que se ejecuta automáticamente al arrancar (o con `--no-autotests` para ir rápido). |

---

## 🚀 Instalación

### Requisitos

- Windows 10/11 **o** Linux
- Python **3.12** (el entorno virtual del proyecto usa 3.12.10)
- Git

### 1 · Arranque exprés (Windows)

```powershell
# Doble clic en:
Run-SysVoidScan.bat
```

El lanzador fija `chcp 65001` + `PYTHONUTF8=1` para que los acentos y los emojis se vean correctos en la consola.

### 2 · Instalación manual

```powershell
# Entorno virtual + dependencias (45 paquetes)
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# Arrancar (ejecuta los tests automáticamente)
python main.py

# Arrancar sin tests (más rápido)
python main.py --no-autotests
```

> **Windows:** si al activar el venv aparece un error de políticas de ejecución, aplícalo una sola vez con
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

### 3 · Herramientas externas (recomendado)

El escáner funciona solo, pero rinde mucho más con sus herramientas acompañantes:

```powershell
# Directorio de trabajo de las herramientas (se añade al PATH de usuario)
C:\pentest-tools\bin        # binarios
C:\pentest-tools\wordlists  # SecLists
C:\Users\<usuario>\nuclei-templates
```

| Herramienta | Versión | Para qué |
|:--|:--:|:--|
| [nuclei](https://github.com/projectdiscovery/nuclei) | 3.11.1 | Fases 76–77: escaneo full de CVEs con plantillas |
| [ffuf](https://github.com/ffuf/ffuf) | 2.3.0 | Fuerza bruta de directorios, vhosts y parámetros |
| [subfinder](https://github.com/projectdiscovery/subfinder) | 2.17.0 | Enumeración de subdominios |
| [httpx](https://github.com/projectdiscovery/httpx) | 1.12.0 | Probing HTTP de hosts descubiertos |
| [katana](https://github.com/projectdiscovery/katana) | 1.8.0 | Crawl/spider con parsing de JS y formularios |
| [dalfox](https://github.com/hahwul/dalfox) | 3.3.0 | Explotación de XSS |
| [gobuster](https://github.com/OJ/gobuster) | 3.8.2 | Directorios / DNS / vhosts |
| [sqlmap](https://sqlmap.org) | 1.10.11 | Explotación automática de SQL injection |

<details>
<summary><b>Wordlists de SecLists incluidas</b> (clic para ver)</summary>

```
common.txt
raft-small-directories.txt      raft-medium-directories.txt
subdomains-top1million-5000.txt subdomains-top1million-20000.txt
namelist.txt                    xato-net-10-million-passwords-10000.txt
```

</details>

---

## 🕹️ Uso

```powershell
python main.py          # o doble clic en Run-SysVoidScan.bat
```

Se abre el menú interactivo. La opción estrella:

```
22. FULL PENTEST + EXPLOTACION (TODOS LOS ATAQUES)
```

Ejecuta las **83 fases seguidas** contra el objetivo que indiques. Una pasada completa tarda **~30 minutos** (el escaneo íntegro de nuclei consume ~14 min).

### Opciones interesantes del menú

| Opción | Qué hace |
|:--|:--|
| `20` | Exportar informe: HTML · Dashboard · JSON · Markdown · CSV · **SARIF** · Jira · TXT |
| `22` | **FULL PENTEST** — las 83 fases |
| tests | La suite se ejecuta sola al arrancar; désactívala con `--no-autotests` |

### Variables de entorno

| Variable | Efecto |
|:--|:--|
| `SYSVOIDSCAN_POSTEX_LOCAL=1` | **Desbloquea** las fases de post-explotación locales (ver 🔒 Seguridad) |
| `PYTHONUTF8=1` | Consola UTF-8 (lo fija el `.bat`) |

---

## 🗺️ Las 83 fases

| Rango | Bloque | Qué ocurre |
|:--|:--|:--|
| **00 – 10** | 📡 Reconocimiento | Validación del objetivo, servidor OOB, WhatWeb/headers/SSL, nmap `-sS -sV -sC -A -p-`, subdominios, fuzzing de vhosts y directorios (ffuf), crawling (katana), análisis de código fuente, descubrimiento de parámetros y APIs |
| **11 – 29** | 🎯 Inyección web | SQLi, XSS (reflected/stored/DOM), SSRF + cloud metadata, LFI/RFI, RCE/CMDi, SSTI, XXE, file upload, JWT, CORS/CSRF/open redirect, IDOR, NoSQL, GraphQL, OAuth/OIDC, WebSocket, CRLF/smuggling, deserialización, WordPress |
| **30 – 36** | 🏗️ Infraestructura | Active Directory, LDAP, SSL/TLS (Heartbleed…), DNS (zone transfer, takeover), SMB, SNMP, bases de datos |
| **37 – 48** | ⚔️ Explotación | 12 fases dedicadas a **explotar de verdad** cada tipo de hallazgo (dump de creds, webshells, forja de tokens admin, reverse shells…) |
| **49 – 58** | 🔗 Cadenas de ataque | 10 cadenas multi-paso: `SQLi → webshell → RCE`, `SSRF → metadata → IAM`, `XXE → /etc/shadow → SSH`, `AD: Kerberoasting → DCSync → Golden Ticket`… |
| **59 – 67** | 💉 Credential spraying | HTTP forms, SMB, SSH, RDP, MSSQL, PostgreSQL, MySQL, LDAP, WinRM |
| **68 – 75** | 🕳️ Post-explotación | Enum local, harvest de credenciales, lateral movement, persistencia, privesc, pivoting, exfiltración, cleanup — *las locales vienen bloqueadas por defecto (ver 🔒)* |
| **76 – 77** | 🐞 CVEs | Escaneo full con Nuclei + mapeo CVE (la explotación automática de CVE aún no está implementada: la fase lista los CVEs confirmados) |
| **78 – 83** | 📊 Informes | Ejecutivo, técnico (PoCs reproducibles), compliance (OWASP/NIST/PCI-DSS), grafo de ataque, guía de remediación y paquete final de artefactos |

<details>
<summary><b>Listado completo de las 83 fases</b></summary>

```
00 VALIDACIÓN DE OBJETIVO              01 SERVIDOR OOB
02 RECONOCIMIENTO (WhatWeb/Headers)    03 ESCANEO NMAP COMPLETO (-p-)
04 SUBDOMINIOS (Subfinder/CRT.sh)      05 FUERZA BRUTA VIRTUAL HOSTS (ffuf)
06 DIRS/ARCHIVOS (ffuf + raft)         07 CRAWL/SPIDER (katana)
08 ANÁLISIS CÓDIGO FUENTE              09 DESCUBRIMIENTO PARÁMETROS
10 DESCUBRIMIENTO API                  11 SQL INJECTION
12 XSS                                 13 SSRF + CLOUD METADATA
14 LFI/RFI + LOG POISONING             15 RCE/CMDi + DESERIALIZATION
16 SSTI                                17 XXE
18 FILE UPLOAD                         19 JWT
20 CORS/CSRF/OPEN REDIRECT             21 IDOR + MASS ASSIGNMENT
22 NoSQL INJECTION                     23 GRAPHQL
24 OAUTH/OIDC                          25 WEBSOCKET
26 CRLF + HTTP SMUGGLING               27 DESERIALIZACIÓN
28 XXE AVANZADO                        29 WORDPRESS
30 ACTIVE DIRECTORY                    31 LDAP
32 SSL/TLS                             33 DNS
34 SMB                                 35 SNMP
36 DATABASES                           37 EXPLOTAR SQLi
38 EXPLOTAR XSS                        39 EXPLOTAR SSRF
40 EXPLOTAR SSTI                       41 EXPLOTAR XXE
42 EXPLOTAR CMDi                       43 EXPLOTAR UPLOAD
44 EXPLOTAR JWT                        45 EXPLOTAR LFI
46 EXPLOTAR DESERIALIZACIÓN            47 EXPLOTAR GRAPHQL
48 EXPLOTAR OAUTH                      49 CADENA SQLi → RCE
50 CADENA SSRF → IAM                   51 CADENA LFI → RCE
52 CADENA SSTI → RCE                   53 CADENA UPLOAD → CONTROL TOTAL
54 CADENA JWT → ADMIN                  55 CADENA XXE → SHADOW/SSH
56 CADENA SQLi → LATERAL               57 CADENA REDIRECT → COOKIE THEFT
58 CADENA AD → DOMAIN ADMIN            59 SPRAY HTTP FORMS
60 SPRAY SMB                           61 SPRAY SSH
62 SPRAY RDP                           63 SPRAY MSSQL
64 SPRAY POSTGRESQL                    65 SPRAY MySQL
66 SPRAY LDAP                          67 SPRAY WinRM
68 POST-EXPLOIT ENUM ⚠️local           69 CREDENTIAL HARVEST ⚠️local
70 LATERAL MOVEMENT (remoto)           71 PERSISTENCE ⚠️local
72 PRIVILEGE ESCALATION ⚠️local        73 PIVOTING ⚠️local
74 DATA EXFIL ⚠️local                  75 CLEANUP ⚠️local
76 CVE SCAN (Nuclei full)              77 CVE AUTO-EXPLOIT
78 REPORTE EJECUTIVO                   79 REPORTE TÉCNICO
80 COMPLIANCE MAPPING                  81 ATTACK PATH GRAPH
82 REMEDIATION GUIDE                   83 ARTIFACT PACKAGE
```

</details>

---

## 📊 Informes

La fase 83 (y la opción `20` del menú) generan el paquete completo en `reports/final/`:

```
reports/
├── final/          HTML · JSON · Markdown · TXT · CSV · SARIF
├── executive/      Resumen para dirección (risk score, impacto de negocio)
├── technical/      PoCs reproducibles en curl/python/nuclei + evidencias
├── compliance/     compliance.json  → OWASP Top 10 · NIST 800-53 · PCI-DSS 4.0 · ISO 27001
├── remediation/    remediation.json → pasos de arreglo por hallazgo + prioridad
└── artifacts/      Evidencias registradas (requests/responses, screenshots, tests)
```

**SARIF 2.1.0** listo para subir a GitHub Advanced Security:

```jsonc
// reports/final/<objetivo>_report.sarif
"runs[0].tool.driver.rules":  [ { "id": "SVS-SQLI-001", "name": "SQL Injection", ... } ]
"runs[0].results":           [ { "ruleId": "SVS-SQLI-001", "level": "error", ... } ]
```

Cada hallazgo lleva severidad CVSS, evidencia request/response, huella única y sus reglas de remediación asociadas.

---

## 🧪 Tests

```powershell
python -m pytest tests/ -q          # 165 tests, ~5 segundos
python -m flake8 --select=F821,F811,E9 --max-line-length=200 .
```

> Al arrancar, `main.py` ejecuta la suite automáticamente y la registra como artefacto.
> Usa `--no-autotests` si quieres entrar directo al menú.

---

## 📁 Estructura

```
SysVoidScan/
├── main.py                 # Punto de entrada + menú interactivo
├── Run-SysVoidScan.bat     # Lanzador Windows (UTF-8)
├── cli/                    # Menú, fases 00-83, exportación
├── core/                   # Scanner, finding types, OOB, remediation, evidencias
├── modules/                # Motores de escaneo (injection, recon, API, fuzzing…)
├── exploit/                # 16 exploiters + chain_engine (cadenas de ataque)
├── post_exploitation/       # enum, harvest, lateral, persistence, privesc, exfil
├── tools/                  # Wrappers: nuclei, ffuf, sqlmap, katana, nmap…
├── cve_mapper/             # Base CVE + sync con Exploit-DB
├── reports/                # Generadores HTML/JSON/MD/TXT/CSV/SARIF
├── plugins/                # Sistema de plugins
├── api/                    # Servidor API + dashboard
├── tests/                  # 165 tests pytest
└── linux/                  # Servicio systemd + instalador
```

---

## 🔒 Seguridad por defecto

Algunas fases de post-explotación operan sobre **la máquina donde corre SysVoidScan**, no sobre el objetivo remoto. Por eso vienen **bloqueadas** y avisan antes de tocar nada:

```
[!] FASE 69: harvest de credenciales — OPERA SOBRE ESTA MAQUINA, no sobre el objetivo remoto.
    omitida por seguridad. Activala con SYSVOIDSCAN_POSTEX_LOCAL=1
```

| Bloqueadas (locales) | Permitidas (atacan al objetivo) |
|:--|:--|
| 68 enum local · 69 harvest (Chrome/WiFi/KeePass) · 71 persistencia (Registro) · 72 privesc local · 73 pivoting · 74 exfil · 75 cleanup de logs | 70 lateral movement · 59-67 credential spraying · todo el bloque 00-58 y 76-83 |

Actívalas **solo** si entiendes lo que hacen:

```powershell
$env:SYSVOIDSCAN_POSTEX_LOCAL = "1"
python main.py
```

---

## ⚠️ Aviso legal

> Este software se distribuye con fines **educativos y de auditoría autorizada**.
> Ejecutarlo contra sistemas sin permiso explícito es **ilegal** en la mayoría de países.
> El autor no se responsabiliza del uso indebido. **Sé ético: pide permiso, acota el alcance, documenta todo.**

---

## 🙏 Créditos

- Proyecto base: [afsh4ck/SysVoidScan](https://github.com/afsh4ck/SysVoidScan) — *SysVoidScan v3.0 Sentinel*
- Plantillas de vulnerabilidades: [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
- Wordlists: [SecLists](https://github.com/danielmiessler/SecLists)

---

<div align="center">

**🛡️ SysVoidScan · Sentinel 3.0.0** — *hecho con café y con permiso escrito del cliente*

[![GitHub](https://img.shields.io/badge/GitHub-B4ckd0orl-181717?logo=github&style=flat-square)](https://github.com/B4ckd0orl)

</div>
