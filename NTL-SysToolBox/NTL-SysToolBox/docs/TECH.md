# Documentation Technique - NTL-SysToolbox

## Architecture globale

### Vue d'ensemble

NTL-SysToolbox est un outil modulaire Python 3.9+ conçu pour l'exploitation quotidienne de l'infrastructure Nord Transit Logistics. L'architecture repose sur 3 modules indépendants partageant une configuration centralisée et des bibliothèques communes.

```
┌─────────────────────────────────────────────────────┐
│              main.py (Point d'entrée)               │
│           Menu interactif + Orchestration           │
└───────────┬─────────────────────────────────────────┘
            │
    ┌───────┴────────┬─────────────────┬
    │                │                 │              
┌───▼────┐  ┌────────▼───────┐  ┌─────▼─────────┐     
│Module 1│  │   Module 2     │  │   Module 3    │     
│Diagno- │  │ Sauvegarde WMS │  │Audit obso-    │     
│ stic   │  │                │  │lescence       │     
└────────┘  └────────────────┘  └───────────────┘    
    │                │                 │          
    └────────────────┴─────────────────┴
                     │
        ┌────────────┴────────────┐
        │   ntl_config.json       │
        │   (Configuration)       │
        └─────────────────────────┘
```
### Modularité

**Architecture découplée**:
- Chaque module est **exécutable indépendamment**
- Configuration centralisée via `ntl_config.json`
- Aucune dépendance inter-modules
- Codes de sortie standardisés (0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN)

---

## Module 1 - Diagnostic

### Architecture

```python
module1_diagnostic.py
├── ADDNSChecker()          # Vérification contrôleurs de domaine
│   ├── check_ad_service()  # État services AD DS
│   ├── check_dns_service() # État service DNS
│   └── test_dns_query()    # Performance DNS
│
├── MySQLChecker()          # Test base WMS
│   ├── connect()           # Connexion MySQL
│   ├── get_version()       # Version MySQL/MariaDB
│   └── measure_latency()   # Latence requête
│
├── WindowsServerInfo()     # Synthèse Windows
│   ├── get_os_info()       # OS, build, version
│   ├── get_uptime()        # Durée de fonctionnement
│   ├── get_cpu_usage()     # Utilisation CPU
│   ├── get_memory_info()   # RAM physique/disponible
│   └── get_disk_info()     # Espaces disques
│
└── UbuntuServerInfo()      # Synthèse Ubuntu
    ├── get_os_info()       # Distribution, kernel
    ├── get_uptime()        # Uptime système
    ├── get_load_average()  # Load average
    ├── get_cpu_usage()     # CPU via /proc/stat
    ├── get_memory_info()   # RAM + swap
    └── get_disk_info()     # df -h tous montages
```
### Choix technique: pypsrp pour Windows

**Pourquoi pypsrp (WinRM) ?**
- **Natif Microsoft**: Protocole officiel de gestion à distance Windows
- **Sécurisé**: NTLM/Kerberos, chiffrement TLS
- **Privilégié**: Accès direct aux WMI/CIM objects
- **Pas de configuration supplémentaire**: WinRM activé par défaut sur Windows Server

### Choix technique: paramiko pour Linux

**Pourquoi paramiko ?**
- **Léger**: Aucune dépendance externe (100% Python)
- **Contrôle fin**: Gestion explicite des commandes SSH
- **Compatible**: OpenSSH 6.x+, aucune config serveur spéciale
- **Erreurs granulaires**: Détection précise des échecs SSH

### Technologies

| Composant | Bibliothèque | Justification |
|-----------|--------------|---------------|
| AD/DNS | `pywin32` (Windows) | Accès natif WMI/PowerShell |
| MySQL | `pymysql` | Driver Python pur, compatible MariaDB |
| Windows | `psutil` + `pypsrp` | Multi-plateforme + WinRM distant |
| Ubuntu | `psutil` + `paramiko` | SSH pour accès distant |

---

## Module 2 - Sauvegarde WMS

### Architecture

```python
module2_backup_wms.py
├── WMSBackup()
│   ├── dump_sql()          # mysqldump complet
│   │   ├── Exec: mysqldump --single-transaction
│   │   ├── Compression: gzip optionnel
│   │   └── Nommage: wms_backup_YYYYMMDD_HHmmss.sql
│   │
│   ├── export_table_csv()  # Export CSV d'une table
│   │   ├── Query: SELECT * FROM {table}
│   │   ├── Format: CSV avec headers
│   │   └── Nommage: {table}_export_YYYYMMDD_HHmmss.csv
│   │
│   ├── verify_backup()     # Intégrité post-backup
│   │   ├── Check: Taille > 0
│   │   ├── Hash: SHA256 calculé
│   │   └── JSON log généré
│   │
│   └── rotate_backups()    # Rotation automatique
│       └── Keep: N dernières sauvegardes
```

### Sécurité des sauvegardes

**Fichier de log JSON** (exemple):
```json
{
  "timestamp": "2026-02-16T21:05:00Z",
  "operation": "sql_dump",
  "status": "SUCCESS",
  "backup": {
    "filename": "wms_backup_20260216_210500.sql.gz",
    "size_mb": 43.69,
    "hash_sha256": "a3f5e8c9d2b1f4a7...",
    "duration_seconds": 23.4
  }
}
```
**Codes de sortie**:
- `0` = OK: Sauvegarde complète réussie
- `1` = WARNING: Partielle (ex: table vide)
- `2` = CRITICAL: Échec total
- `3` = UNKNOWN: Erreur inattendue

**Avantages**:
- Traçabilité complète (horodatage, taille, hash)
- Vérification intégrité (comparaison hash)
- Audit post-opération (JSON parsable)

### Technologies

| Composant | Outil | Justification |
|-----------|-------|---------------|
| SQL dump | `mysqldump` | Standard industriel MySQL |
| CSV export | `pymysql` + `pandas` | Manipulation DataFrame |
| Compression | `gzip` (stdlib) | Natif Python, pas de dépendance |
| Hash | `hashlib` (stdlib) | SHA256 intégré |

---

## Module 3 - Audit d'obsolescence

### Architecture complète

```python
module3_audit.py
├── NetworkScanner()                    # Découverte réseau
│   ├── scan_range(ip_range, ports)   # Scan nmap avec OS detection
│   │   ├── nmap -sS -O --osscan-limit
│   │   ├── Ports: 22,80,443,3389,135,139,445
│   │   └── Timeout: configurable
│   │
│   ├── _get_hostname(ip)              # Résolution DNS inverse
│   ├── _get_mac_address(ip)           # Extraction adresse MAC
│   ├── _get_vendor(ip)                # Vendor OUI lookup
│   ├── _get_open_ports(ip)            # Liste ports ouverts
│   │
│   ├── _get_os_info(ip)               # Détection OS nmap
│   │   ├── Parse osmatch (meilleur accuracy)
│   │   ├── Parse osclass (vendor, type, osfamily)
│   │   └── Extraction build_number Windows
│   │
│   ├── _extract_windows_version()     # Normalisation Windows
│   │   ├── Build >= 22000 → Windows 11
│   │   ├── Build >= 10240 → Windows 10
│   │   ├── Server 2016/2019/2022 (build match)
│   │   └── Regex: "windows server 2019"
│   │
│   ├── _extract_linux_version()       # Normalisation Linux
│   │   ├── Ubuntu: regex "ubuntu 22.04"
│   │   ├── Debian: regex "debian 11"
│   │   ├── CentOS: regex "centos 8"
│   │   └── RHEL: regex "rhel 9"
│   │
│   ├── _extract_macos_version()       # Normalisation macOS
│   │   └── Regex: "mac os x 13.5"
│   │
│   └── _simple_ping_scan()            # Fallback ping si nmap échoue
│
├── OSDetector()                        # Détection OS avancée
│   ├── detect_os(ip, ports)           # Méthode principale
│   │   └── Itère sur méthodes jusqu'à succès
│   │
│   ├── _detect_via_ssh_banner()       # SSH banner grabbing
│   │   ├── Connect port 22, recv 1024 bytes
│   │   ├── Parse: "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
│   │   └── Extract: Ubuntu 20.04
│   │
│   ├── _detect_via_http_header()      # HTTP Server header
│   │   ├── GET / HTTP/1.1
│   │   ├── Parse: "Server: Microsoft-IIS/10.0"
│   │   └── Map IIS version → Windows Server
│   │
│   ├── _detect_via_smb()              # SMB negotiation
│   │   ├── Connect port 445
│   │   ├── Send SMB negotiate packet
│   │   ├── Parse response: "Windows 10.0"
│   │   └── Extract version
│   │
│   ├── _detect_via_banner()           # Generic banner grab
│   │   └── Tentative sur ports communs
│   │
│   ├── normalize_os_version()         # Normalisation finale
│   │   ├── Windows: "Windows 10", "Windows Server 2019"
│   │   ├── Linux: "Ubuntu 22.04", "Debian 11"
│   │   └── macOS: "macOS 13.5"
│   │
│   └── _iis_to_windows_version()      # Mapping IIS → Windows
│       ├── IIS 10.0 → Server 2016/2019/2022
│       ├── IIS 8.5 → Server 2012 R2
│       └── IIS 8.0 → Server 2012
│
├── EOLDatabase()                       # Base de données EOL
│   ├── _load_eol_data()               # Chargement données statiques
│   │   ├── Windows: 11, 10, Server 2022/2019/2016/2012
│   │   ├── Linux: Ubuntu 24.04/22.04/20.04/18.04
│   │   │          Debian 12/11/10/9
│   │   │          CentOS 9/8/7
│   │   │          RHEL 9/8/7
│   │   └── macOS: Sonoma/Ventura/Monterey/Big Sur
│   │
│   ├── get_eol_info(os_family, version)  # Recherche info
│   │   └── Return: {release_date, eol_date, extended, status}
│   │
│   ├── get_status(eol_info)           # Calcul statut
│   │   ├── Supported (EOL > 365j)
│   │   ├── Warning (EOL < 365j)
│   │   ├── Soon EOL (EOL < 90j)
│   │   ├── Extended Support (mainstream passé)
│   │   ├── EOL (date dépassée)
│   │   └── Unknown (non référencé)
│   │
│   ├── get_days_until_eol()           # Calcul jours restants
│   │   ├── today = date.today()
│   │   ├── delta = eol_date - today
│   │   └── return delta.days
│   │
│   └── list_all_versions(os_family)   # Liste complète versions
│       └── Return: Liste triée par release_date
│
├── CSVProcessor()                      # Import/Export CSV
│   ├── read_csv(csv_path)             # Lecture CSV
│   │   ├── Détection séparateur (,;tab)
│   │   ├── Normalisation colonnes (lowercase)
│   │   └── Return: pandas DataFrame
│   │
│   ├── validate_data(df)              # Validation données
│   │   ├── Check colonnes requises: ip, os_family, os_version
│   │   ├── Validation IPs (ipaddress.ip_address)
│   │   └── Raise ValueError si invalide
│   │
│   ├── process_components(df)         # Conversion DataFrame
│   │   └── Return: List[Dict] composants
│   │
│   └── export_to_csv(data, path)      # Export enrichi
│       ├── Colonnes: IP,Hostname,OS Family,OS Version,
│       │             Status,EOL Date,Days Until EOL
│       └── Séparateur: ,
│
└── ReportGenerator()                   # Génération rapports
    ├── generate_report(components, format)  # Méthode principale
    │   ├── format='txt' → _generate_text_report()
    │   ├── format='csv' → _generate_csv_report()
    │   └── format='json' → _generate_json_report()
    │
    ├── _analyze_components()           # Statistiques globales
    │   ├── Count by status (supported/eol/warning/...)
    │   ├── Count by OS family (Windows/Linux/macOS)
    │   └── Identify critical (EOL ou soon_eol)
    │
    ├── _generate_text_report()         # Format TXT
    │   ├── Header avec date génération
    │   ├── Statistiques globales
    │   ├── Section "Attention immédiate" (EOL/soon_eol)
    │   └── Détail tous composants (tableau)
    │
    ├── _generate_csv_report()          # Format CSV
    │   ├── Headers: IP,Hostname,OS Family,Version,Status,EOL,Days
    │   └── Une ligne par composant
    │
    └── _generate_json_report()         # Format JSON
        ├── generation_date: ISO 8601
        ├── statistics: {...}
        └── components: [{...}, {...}]
```

### Technologies

| Composant | Bibliothèque | Version | Justification |
|-----------|--------------|---------|---------------|
| Scan réseau | `python-nmap` | 0.7.1 | Wrapper Python pour nmap |
| Détection OS | `nmap` (binaire) | 7.80+ | Standard industrie pour OS fingerprinting |
| Réseau IP | `ipaddress` | stdlib | Validation et manipulation CIDR |
| Socket | `socket` | stdlib | Banner grabbing bas niveau |
| HTTP | `requests` | 2.31.0 | Client HTTP avec SSL/TLS |
| SSH | `paramiko` | 3.3.1 | Client SSH Python (si besoin futur) |
| CSV | `pandas` | 2.1.0 | Manipulation DataFrames |
| JSON | `json` | stdlib | Sérialisation rapports |

### Performance

**Temps de scan typique** :

| Plage réseau | Hôtes actifs | Durée scan | Durée totale (avec EOL) |
|--------------|--------------|------------|-------------------------|
| /24 (254 IPs) | 20 hôtes | 3-5 min | 4-6 min |
| /24 (254 IPs) | 50 hôtes | 5-8 min | 6-10 min |
| /16 (65k IPs) | 200 hôtes | 30-45 min | 35-50 min |

### Prérequis système critiques

**⚠️ IMPORTANT : `nmap` DOIT être installé sur le système**

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap

# Windows
# Télécharger depuis https://nmap.org/download.html
# Installer nmap-7.94-setup.exe
# Ajouter au PATH: C:\Program Files (x86)\Nmap

# Vérification
nmap --version
```

### Base de données EOL

La base EOL est **statique** et **intégrée au code** (dictionnaire Python). Mise à jour manuelle nécessaire.

**Structure complète** :

```python
eol_data = {
    'Windows': {
        'Windows 11': {
            'release_date': date(2021, 10, 5),
            'eol_date': None,  # Support continu
            'eol_extended_date': None,
            'status': 'supported'
        },
        'Windows 10': {
            'release_date': date(2015, 7, 29),
            'eol_date': date(2025, 10, 14),  # Mainstream
            'eol_extended_date': date(2026, 10, 13),  # Extended
            'status': 'soon_eol'
        },
        'Windows Server 2022': {...},
        'Windows Server 2019': {...},
        'Windows Server 2016': {...},
        'Windows Server 2012 R2': {...},
        'Windows Server 2012': {...},
        'Windows Server 2008 R2': {...}
    },
    'Linux': {
        'Ubuntu 24.04': {...},
        'Ubuntu 22.04': {...},
        'Ubuntu 20.04': {...},
        'Ubuntu 18.04': {...},
        'Debian 12': {...},
        'Debian 11': {...},
        'Debian 10': {...},
        'Debian 9': {...},
        'CentOS 9': {...},
        'CentOS 8': {...},
        'CentOS 7': {...},
        'RHEL 9': {...},
        'RHEL 8': {...},
        'RHEL 7': {...}
    },
    'macOS': {
        'macOS 14': {...},  # Sonoma
        'macOS 13': {...},  # Ventura
        'macOS 12': {...},  # Monterey
        'macOS 11': {...}   # Big Sur
    }
}
```

**Sources officielles** :
- Windows: https://learn.microsoft.com/en-us/lifecycle/products/
- Ubuntu: https://wiki.ubuntu.com/Releases
- Debian: https://wiki.debian.org/DebianReleases
- CentOS: https://wiki.centos.org/About/Product
- RHEL: https://access.redhat.com/support/policy/updates/errata
- macOS: https://support.apple.com/en-us/HT201222

---

## Configuration centralisée

### ntl_config.json

```json
{
  "infrastructure": {
    "dc01_ip": "10.5.60.10",
    "dc02_ip": "10.5.60.11",
    "wms_db_host": "10.5.60.20",
    "wms_db_port": 3306,
    "wms_db_user": "wms_user",
    "wms_db_pass": "wms_pass",
    "windows_default_user": "administrateur",
    "ubuntu_default_user": "administrateur"
  },
  "module2_wms": {
    "db_name": "wms",
    "db_host": "10.5.60.20",
    "db_port": 3306,
    "db_user": "wms_user",
    "table_to_export": "stock_moves",
    "backup_dir": "backups/wms"
  }
}
```

**Sécurité**:
- ⚠️ **Mots de passe**: Stocker via variables d'environnement en production
- ✅ **Overrides**: `export WMS_DB_PASS=secret` prioritaire sur JSON
- ✅ **Permissions**: `chmod 600 ntl_config.json`

---

## Gestion des dépendances

### requirements.txt

```
psutil>=5.8.0          # Monitoring système cross-platform
pymysql>=1.0.0         # Driver MySQL pur Python
paramiko>=2.8.0        # SSH client pour Linux distant
pypsrp>=0.8.0          # WinRM client pour Windows distant
```

**Justification des versions**:
- **psutil 5.8+**: Support natif Windows 11 / Ubuntu 22.04
- **pymysql 1.0+**: Compatible MariaDB 10.5+
- **paramiko 2.8+**: Fix CVE-2022-24302 (vulnérabilité SSH)
- **pypsrp 0.8+**: Support Python 3.10+

### Installation

```bash
# Environnement virtuel isolé
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Installation dépendances
pip install -r requirements.txt
```

---

## Compatibilité multi-plateforme

### Tableau de compatibilité

| OS | Python | psutil | paramiko | pypsrp | Testé |
|----|--------|--------|----------|--------|-------|
| **Windows 10/11** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Windows Server 2016+** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 20.04 LTS** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 22.04 LTS** | 3.10+ | ✅ | ✅ | ✅ | ✅ |
| **Debian 11** | 3.9+ | ✅ | ✅ | ✅ | ⚠️ Non testé |
| **RHEL 8/9** | 3.8+ | ✅ | ✅ | ✅ | ⚠️ Non testé |

### Adaptations plateforme

**Windows**:
- Chemins: `Path()` (pathlib) pour compatibilité
- Clear screen: `os.system("cls")`
- EOL: CRLF automatiquement géré par Python

**Linux**:
- Chemins: `/` natif
- Clear screen: `os.system("clear")`
- EOL: LF natif
- Permissions: `chmod +x` pour exécution directe

---

---

## Compatibilité multi-plateforme

### Tableau de compatibilité

| OS | Python | psutil | paramiko | pypsrp | Testé |
|----|--------|--------|----------|--------|-------|
| **Windows 10/11** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Windows Server 2016+** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 20.04 LTS** | 3.8+ | ✅ | ✅ | ✅ | ✅ |
| **Ubuntu 22.04 LTS** | 3.10+ | ✅ | ✅ | ✅ | ✅ |
| **Debian 11** | 3.9+ | ✅ | ✅ | ✅ | ⚠️ Non testé |
| **RHEL 8/9** | 3.8+ | ✅ | ✅ | ✅ | ⚠️ Non testé |

### Adaptations plateforme

**Windows**:
- Chemins: `Path()` (pathlib) pour compatibilité
- Clear screen: `os.system("cls")`
- EOL: CRLF automatiquement géré par Python

**Linux**:
- Chemins: `/` natif
- Clear screen: `os.system("clear")`
- EOL: LF natif
- Permissions: `chmod +x` pour exécution directe

---

## Performances et optimisations

### Benchmarks

| Opération | Durée moyenne | Justification |
|-----------|---------------|---------------|
| **check_ad_dns_service()** | 150-300ms | 3 tests TCP (DNS/LDAP/Kerberos) |
| **check_mysql_database()** | 200-500ms | Connexion + 4 requêtes SQL |
| **check_windows_server() local** | 1-2s | psutil.cpu_percent(interval=1) |
| **check_windows_server() distant** | 3-5s | WinRM + 2 scripts PowerShell |
| **check_ubuntu_server() distant** | 2-4s | SSH + 5 commandes shell |
| **dump_sql() (10k lignes)** | 5-10s | SHOW CREATE + INSERT (réseau LAN) |
| **export_csv() (10k lignes)** | 2-5s | 1 requête JOIN + écriture CSV |

### Optimisations

**Connexions réseaux**:
- Timeout fixé à 5-10s (éviter blocages)
- Réutilisation des connexions SSH/WinRM/MySQL dans une session

**Exports CSV**:
- Buffer écriture de 8KB (`csv.writer`)
- Pas de chargement complet en mémoire (streaming)

**PowerShell distant**:
- Scripts consolidés (1 appel WMI = toutes les données)
- JSON output pour parsing propre

---

## Sécurité

### Authentification

**Protocoles utilisés**:
- **SSH (Paramiko)**: Authentification par mot de passe ou clé privée
- **WinRM (PyPSRP)**: NTLM ou Kerberos
- **MySQL**: Authentification native MySQL

**Bonnes pratiques**:
- ✅ Mots de passe jamais loggés
- ✅ Config JSON avec permissions restrictives (600)
- ✅ Variables d'environnement prioritaires
- ⚠️ Pas de gestion des clés SSH (amélioration future)

### Surface d'attaque

**Risques identifiés**:
- **Stockage cleartext** des mots de passe dans JSON
  → **Mitigation**: Variables d'environnement recommandées
- **Connexions distantes non chiffrées** (pypsrp ssl=False)
  → **Mitigation**: Activer TLS en production (`ssl=True`)
- **Injection PowerShell** (scripts non paramétrés)
  → **Mitigation**: Scripts statiques sans interpolation utilisateur

---

## Formats de sortie

### JSON structuré

**Toutes les sorties** suivent ce schéma:
```json
{
  "timestamp": "2026-02-17T18:30:00.123456",
  "module": "diagnostic|wms_backup",
  "status": "OK|WARNING|CRITICAL|UNKNOWN",
  "checks": [
    {
      "type": "AD_DNS_Service|MySQL_Database|Windows_Server|Ubuntu_Server",
      "server": "10.5.60.10",
      "status": "OK",
      "details": { ... }
    }
  ],
  "exit_code": 0
}
```

**Interopérabilité**:
- ✅ Ingestion dans ELK/Splunk
- ✅ Parsing par Zabbix/Nagios
- ✅ Analyse en Python/PowerShell

### Format humain

**Console-friendly**:
```
======================================================================
MODULE DIAGNOSTIC - RÉSULTATS
======================================================================
Horodatage: 2026-02-17T18:30:00

[1] AD_DNS_Service - Statut: OK
----------------------------------------------------------------------
  Serveur: 10.5.60.10
  DNS: ✓ OK (23 ms)
  LDAP: ✓ OK (45 ms)
  Kerberos: ✓ OK (31 ms)
```

---

## Arborescence des fichiers

```
NTL-SysToolbox/
├── src/
│   ├── main.py                    # Orchestrateur principal
│   ├── module1_diagnostic.py      # Module 1 autonome
│   ├── module2_wms_backup.py      # Module 2 autonome
│   └── ntl_config.json            # Configuration centralisée
│
├── backups/                       # Artefacts générés
│   ├── ad_dns/
│   │   ├── ad_dns_20260217_183000.json
│   │   └── ad_dns_20260217_183000.txt
│   ├── mysql/
│   ├── windows/
│   ├── ubuntu/
│   ├── global/
│   └── wms/
│       ├── wms_dump_2026-02-17_18-30-00_UTC.sql
│       └── stock_moves_2026-02-17_18-30-00_UTC.csv
│
├── docs/
│   ├── TECH.md                    # Ce document
│   ├── USAGE.md                   # Guide utilisateur
│   └── LICENCE.md                 # MIT License
│
├── requirements.txt               # Dépendances Python
└── README.md                      # Documentation entrée
```

---

## Compromis et limitations

### Compromis assumés

1. **Pas de gestion des credentials avancée**
   - **Pourquoi**: Scope initial limité
   - **Impact**: Mots de passe en clair dans config
   - **Mitigation**: Variables d'environnement recommandées

2. **Pas de concurrence (threading)**
   - **Pourquoi**: Simplicité du code
   - **Impact**: Diagnostic global séquentiel (15-20s)
   - **Mitigation**: Acceptable pour usage manuel

3. **Dump SQL logique seulement**
   - **Pourquoi**: Portabilité vs performance
   - **Impact**: Plus lent que binlog/physical backup
   - **Mitigation**: Fenêtre nocturne disponible

### Limitations connues

- **Windows distant**: Nécessite WinRM activé
- **Linux distant**: Nécessite SSH accessible
- **MySQL**: Pas de support SSL (à activer manuellement)
- **CSV export**: Requête hardcodée (JOIN products/locations)
- **Pas de gestion des erreurs réseau transitoires** (retry logic)

---

## Auteur et maintenance

**Développeur**: Équipe MSPR GROUPE 1 2026  
**Client**: Nord Transit Logistics (NTL)  
**Licence**: MIT License  
**Contact**: Administrateur Systèmes & Réseaux

**Support**:
- Issues GitHub: `https://github.com/Not-mat-collab/ntl-systoolbox`
- Documentation: `docs/`
- Logs: `backups/{module}/`