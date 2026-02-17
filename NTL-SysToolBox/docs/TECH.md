# NTL-SysToolbox - Architecture et Choix Techniques

## Vue d'ensemble

**NTL-SysToolbox** est un outil CLI multi-plateforme développé en **Python 3.8+** pour industrialiser les opérations d'exploitation IT chez Nord Transit Logistics (NTL).

### Contexte métier

NTL est une PME logistique opérant 4 sites (Lille, Lens, Valenciennes, Arras) avec:
- **~240 employés** (300 en haute saison)
- **Horaires critiques**: 5h30-18h30 (zéro downtime acceptable)
- **Services centralisés**: Active Directory, DNS, WMS MySQL (192.168.10.21)
- **Fentres de maintenance**: Nocturnes uniquement

L'outil répond à 3 enjeux opérationnels:
1. **Diagnostic rapide** des services critiques (AD/DNS/MySQL/serveurs)
2. **Sauvegardes traçables** de la base WMS (cœur métier)
3. **Audit d'obsolescence** réseau (EOL tracking)

---

## Architecture logicielle

### Principes de conception

```
┌─────────────────────────────────────────┐
│         main.py (Orchestrateur)         │
│    • Menu principal interactif CLI      │
│    • Gestion config JSON centralisée    │
│    • Dispatch vers modules autonomes    │
└──────────┬──────────────────────────────┘
           │
    ┌──────┴──────────┬─────────────────┐
    │                 │                 │
┌───▼────────┐  ┌─────▼───────┐  ┌──────▼──────┐
│  MODULE 1  │  │  MODULE 2   │  │  MODULE 3   │
│ DIAGNOSTIC │  │ WMS BACKUP  │  │   AUDIT     │
│ (Autonome) │  │ (Autonome)  │  │ (Autonome)  │
└────────────┘  └─────────────┘  └─────────────┘
```

### Modularité

**Architecture découplée**:
- Chaque module est **exécutable indépendamment**
- Configuration centralisée via `ntl_config.json`
- Aucune dépendance inter-modules
- Codes de sortie standardisés (0=OK, 1=WARNING, 2=CRITICAL, 3=UNKNOWN)

---

## Module 1 - Diagnostic

### Stack technique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| **Monitoring local** | `psutil` | Cross-platform (Linux/Windows), stable, exhaustif (CPU/RAM/disque/uptime) |
| **Monitoring distant Windows** | `pypsrp` | Protocole WinRM natif, authentification sécurisée, exécution PowerShell distante |
| **Monitoring distant Linux** | `paramiko` | Client SSH pur Python, compatible OpenSSH, pas de dépendances système |
| **Tests réseau** | `socket` (stdlib) | TCP port checking léger, pas de dépendances externes |
| **Database health** | `pymysql` | Driver MySQL pur Python, compatible MariaDB 10.x |

### Architecture des vérifications

```python
DiagnosticModule
├── check_ad_dns_service(ip)      # Ports 53/389/88
│   ├── _test_dns()               # Résolution DNS
│   ├── _test_port(389, "LDAP")  # Authentification AD
│   └── _test_port(88, "Kerberos")
│
├── check_mysql_database()
│   ├── Connexion MySQL
│   ├── SELECT VERSION()
│   ├── SHOW GLOBAL STATUS
│   └── Métriques: uptime, connexions, queries
│
├── check_windows_server()
│   ├── Mode local: psutil
│   └── Mode distant: pypsrp + PowerShell
│       ├── Get-WmiObject Win32_OperatingSystem
│       ├── Get-WmiObject Win32_Processor
│       └── Get-WmiObject Win32_LogicalDisk
│
└── check_ubuntu_server()
    ├── Mode local: psutil
    └── Mode distant: paramiko + SSH
        ├── lsb_release -d
        ├── free -m
        └── df -h
```

### Choix technique: pypsrp vs SSH pour Windows

**Pourquoi pypsrp (WinRM) ?**
- **Natif Microsoft**: Protocole officiel de gestion à distance Windows
- **Sécurisé**: NTLM/Kerberos, chiffrement TLS
- **Privilégié**: Accès direct aux WMI/CIM objects
- **Pas de configuration supplémentaire**: WinRM activé par défaut sur Windows Server

**Alternatives écartées**:
- SSH (OpenSSH-Server): Nécessite installation manuelle
- RPC/DCOM: Complexe, ancienne génération
- Ansible WinRM: Overhead inutile (dépendances lourdes)

### Choix technique: paramiko vs Fabric pour Linux

**Pourquoi paramiko ?**
- **Léger**: Aucune dépendance externe (100% Python)
- **Contrôle fin**: Gestion explicite des commandes SSH
- **Compatible**: OpenSSH 6.x+, aucune config serveur spéciale
- **Erreurs granulaires**: Détection précise des échecs SSH

**Alternatives écartées**:
- Fabric: Overhead inutile (orchestration complexe)
- subprocess + ssh CLI: Dépend de l'installation locale de ssh

---

## Module 2 - Sauvegarde WMS

### Stack technique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| **Driver MySQL** | `pymysql` | Pur Python, compatible MariaDB 10.x (WMS backend) |
| **Export SQL** | Dump logique | SHOW CREATE TABLE + INSERT INTO, restauration simple |
| **Export CSV** | `csv` (stdlib) | Format universel, ingestion dans BI/Excel |
| **Intégrité** | `hashlib.sha256` | Checksum cryptographique pour validation |

### Architecture de la sauvegarde

```
Module2_WMS_Backup
│
├── Connexion MySQL
│   ├── Host: 10.5.60.20:3306
│   ├── Database: wms
│   └── User: wms_user
│
├── dump_sql() → wms_dump_2026-02-17_18-30-00_UTC.sql
│   ├── SHOW CREATE TABLE (toutes les tables)
│   ├── SELECT * FROM (chaque table)
│   └── INSERT INTO (données complètes)
│
├── export_csv() → stock_moves_2026-02-17_18-30-00_UTC.csv
│   ├── JOIN products/locations
│   └── Colonnes: move_id, product_name, from/to locations, quantity, move_type
│
└── Métadonnées JSON
    ├── sha256: 7a3f9e2c...
    ├── size_bytes: 2456789
    ├── duration_ms: 1342
    └── status: OK/WARNING/CRITICAL
```

### Choix technique: Dump logique vs binaire

**Pourquoi dump logique (SQL textuel) ?**
- **Portable**: Indépendant de la version MySQL/MariaDB
- **Restauration sélective**: Possible de ne restaurer que certaines tables
- **Audit humain**: Fichier SQL lisible en cas de besoin
- **Compatible cross-platform**: Pas de dépendance binaire

**Alternatives écartées**:
- mysqldump CLI: Nécessite installation MySQL client
- Physical backup (InnoDB files): Nécessite arrêt du serveur
- Binary logs: Complexe, nécessite configuration serveur

### Traçabilité et intégrité

**Chaque sauvegarde produit**:
```json
{
  "schema_version": "1.0",
  "timestamp_utc": "2026-02-17T18:30:00Z",
  "artifacts": {
    "sql_dump": {
      "file": "wms_dump_2026-02-17_18-30-00_UTC.sql",
      "size_bytes": 2456789,
      "sha256": "7a3f9e2c...",
      "status": "OK"
    },
    "csv_export": {
      "file": "stock_moves_2026-02-17_18-30-00_UTC.csv",
      "rows_exported": 12453,
      "sha256": "b4e6c1a5...",
      "status": "OK"
    }
  },
  "exit_code": 0
}
```

**Codes de sortie**:
- `0` = OK: Sauvegarde complète réussie
- `1` = WARNING: Partielle (ex: table vide)
- `2` = CRITICAL: Échec total
- `3` = UNKNOWN: Erreur inattendue

---

## Module 3 - Audit d'obsolescence (TODO)

### Stack technique prévu

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| **Scan réseau** | `scapy` ou `nmap` | Détection active des hosts |
| **OS fingerprinting** | `python-nmap` | Identification des versions |
| **EOL database** | API publique (endoflife.date) | Référentiel officiel des dates de fin de vie |
| **Rapport** | CSV + JSON | Format structuré pour alerting |

### Architecture prévue

```
Module3_Audit
│
├── Scan réseau (192.168.10.0/24, 20.0/24, 30.0/24, 40.0/24)
│   └── Détection hosts actifs
│
├── OS Fingerprinting
│   ├── TCP/IP stack analysis
│   └── Service version detection
│
├── EOL Lookup (endoflife.date API)
│   ├── Windows Server 2012 R2 → EOL: 2023-10-10
│   └── Ubuntu 18.04 LTS → EOL: 2023-05-31
│
└── Rapport
    ├── audit_2026-02-17.csv
    └── Criticité: CRITICAL/WARNING/OK
```

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
pypsrp>=0.8.1          # WinRM client pour Windows distant
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
├── main.py                        # Orchestrateur principal
├── requirements.txt               # Dépendances Python
└── README.md                      # Documentation entrée
```

---

## Évolutions futures

### Roadmap

**Version 2.1** (Q2 2026):
- [ ] Support clés SSH (paramiko key-based auth)
- [ ] Chiffrement config (python-keyring)
- [ ] Logs rotatifs (logging + RotatingFileHandler)

**Version 2.2** (Q3 2026):
- [ ] Dashboard web (Dash/Streamlit)
- [ ] Notifications (email/Slack/Teams)

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

**Développeur**: Équipe MSPR GRP 1 2025-2026  
**Client**: Nord Transit Logistics (NTL)  
**Licence**: MIT License  
**Contact**: Administrateur Systèmes & Réseaux

**Support**:
- Issues GitHub: `https://github.com/Not-mat-collab/ntl-systoolbox`
- Documentation: `docs/`
- Logs: `backups/{module}/`
