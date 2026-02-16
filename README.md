# NTL-SysToolbox 🚀

**NTL-SysToolbox** est un outil en ligne de commande multi-plateforme (**Windows** / **Linux**) conçu pour **Nord Transit Logistics (NTL)**. Il industrialise les vérifications d'exploitation, sécurise la gestion des sauvegardes WMS et produit un audit d'obsolescence réseau.

> **Objectif** : Fournir à la DSI un outil unique, simple à déployer et supervisable pour maintenir la continuité de service critique (WMS, AD/DNS) et anticiper les risques d'obsolescence.

---

## 📋 Table des matières

- [Fonctionnalités principales](#-fonctionnalités-principales)
- [Installation rapide](#-installation-rapide)
- [Utilisation - Menu interactif](#-utilisation---menu-interactif)
- [Architecture](#-architecture)
- [Module Diagnostic](#-module-diagnostic)
- [Module Sauvegarde WMS](#-module-sauvegarde-wms)
- [Module Audit d'obsolescence](#-module-audit-dobsolescence)
- [Cas d'usage DSI NTL](#-cas-dusage-dsi-ntl)
- [Configuration](#-configuration)
- [Sorties et codes retour](#-sorties-et-codes-retour)
- [Développement & Contribution](#-développement--contribution)
- [Documentation complète](#-documentation-complète)
- [Contexte NTL](#-contexte-ntl)
- [Licence](#-licence)

---

## 📋 Fonctionnalités principales

| **Module** | **🎯 Objectif** | **🔧 Fonctions clés** |
|------------|-----------------|-----------------------|
| **Diagnostic** | Confirmer l'état des briques critiques | ✅ Vérification AD/DNS sur contrôleurs de domaine<br>✅ Test connexion et performance MySQL WMS<br>✅ Synthèse serveur Windows (OS, uptime, CPU/RAM/disques)<br>✅ Synthèse serveur Ubuntu (OS, uptime, CPU/RAM/disques) |
| **Sauvegarde WMS** | Sécuriser les exports de base métier | 💾 Dump SQL complet de la base WMS<br>📊 Export CSV d'une table ciblée<br>📈 Logs horodatés et traçabilité JSON<br>✔️ Vérification d'intégrité |
| **Audit obsolescence** | Qualifier le statut support/EOL réseau | 🌐 Scan d'une plage IP donnée<br>🔍 Détection OS des composants<br>📋 Référentiel EOL par OS (versions + dates)<br>⚠️ Rapport de risque (non supporté/bientôt EOL/supporté) |

**Sorties uniformes** : 
- Texte lisible par un humain (synthèse, alertes)
- **JSON horodaté** pour exploitation automatisée
- **Codes retour** exploitables en supervision (0=OK, 1=WARN, 2=CRIT)

---

## 🚀 Installation rapide

### Prérequis système

- **OS** : Windows Server 2016+ / Ubuntu 18.04+ (ou autre distribution Linux)
- **Runtime** : Python 3.9+ (ou adapter selon votre choix technologique)
- **Accès réseau** : Vers contrôleurs de domaine (DC01, DC02), base MySQL WMS, plages IP à auditer
- **Privilèges** : Droits d'administration pour vérifications système locales, accès LDAP pour AD, credentials MySQL

### Installation en 3 étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git
cd ntl-systoolbox

# 2. Installer les dépendances
pip install -r requirements.txt
# Ou sous Windows : py -m pip install -r requirements.txt

# 3. Configurer l'outil
cp config.example.yaml config.yaml
# Éditer config.yaml avec vos paramètres (IPs, credentials, etc.)
```

### Lancement
```bash
python systoolbox.py
# Ou sous Windows : py systoolbox.py
```

---

## 🎮 Utilisation - Menu interactif

L'outil expose un **menu CLI interactif** qui guide l'utilisateur à travers les différentes fonctions et demande les arguments nécessaires.

```
$ python systoolbox.py

╔════════════════════════════════════════════════════╗
║       🌟 NTL-SysToolbox v1.0.0 🌟                 ║
║   Outil d'exploitation Nord Transit Logistics     ║
╚════════════════════════════════════════════════════╝

Modules disponibles :
  1️⃣  Module Diagnostic (AD/DNS/MySQL/Serveurs)
  2️⃣  Module Sauvegarde WMS (SQL/CSV)
  3️⃣  Module Audit obsolescence réseau
  ⚙️  Configuration
  📚 Documentation
  0️⃣  Quitter

Votre choix > 1

[Module Diagnostic]
Contrôleurs de domaine à vérifier (séparés par virgule) [192.168.10.10,192.168.10.11] : 
```

**Exemple de sortie console** :
```
═══════════════════════════════════════════════════
📊 RAPPORT DIAGNOSTIC - 2026-02-16 20:39:00
═══════════════════════════════════════════════════

🔹 CONTRÔLEURS DE DOMAINE
  ✅ DC01 (192.168.10.10) : AD OK, DNS répond en 12ms
  ✅ DC02 (192.168.10.11) : AD OK, DNS répond en 15ms

🔹 BASE DE DONNÉES WMS
  ⚠️  MySQL WMS (192.168.10.21) : Connecté, temps réponse élevé (452ms)
  ⚠️  CPU serveur : 78% (seuil : 80%)

🔹 SERVEUR WMS-APP (192.168.10.22)
  ✅ OS : Ubuntu 20.04.6 LTS
  ✅ Uptime : 127 jours
  ✅ CPU : 34% | RAM : 52% | Disque /var : 68%

═══════════════════════════════════════════════════
🎯 STATUT GLOBAL : AVERTISSEMENT (code retour: 1)
📄 Rapport détaillé : ./reports/diagnostic_20260216_2039.json
═══════════════════════════════════════════════════
```

---

## 🏗️ Architecture

### Structure du projet

```
NTL-SysToolbox/
├── src/
│   ├── diagnostic/
│   │   ├── __init__.py
│   │   ├── ad_check.py          # Vérification Active Directory
│   │   ├── dns_check.py         # Vérification DNS
│   │   ├── mysql_check.py       # Test MySQL WMS
│   │   ├── windows_health.py    # Diagnostic Windows Server
│   │   └── ubuntu_health.py     # Diagnostic Ubuntu Server
│   ├── backup_wms/
│   │   ├── __init__.py
│   │   ├── sql_dump.py          # Sauvegarde SQL complète
│   │   ├── csv_export.py        # Export CSV table
│   │   └── integrity_check.py   # Vérification intégrité
│   ├── audit_eol/
│   │   ├── __init__.py
│   │   ├── network_scan.py      # Scan réseau (nmap/socket)
│   │   ├── os_detection.py      # Détection OS
│   │   ├── eol_database.py      # Référentiel EOL
│   │   └── report_generator.py  # Génération rapport obsolescence
│   ├── common/
│   │   ├── __init__.py
│   │   ├── config_loader.py     # Chargement config + env vars
│   │   ├── logger.py            # Logs horodatés JSON
│   │   └── utils.py             # Utilitaires communs
│   └── cli_menu.py              # Interface interactive principale
├── config/
│   ├── config.yaml              # Configuration principale
│   └── config.example.yaml      # Exemple pour documentation
├── reports/                     # Sorties générées (JSON, CSV, SQL)
├── backups/                     # Sauvegardes WMS générées
├── docs/
│   ├── INSTALL.md               # Guide installation DSI
│   ├── TECH.md                  # Architecture et choix techniques
│   └── USAGE.md                 # Guide utilisation détaillé
├── tests/
│   ├── test_diagnostic.py       # Tests unitaires diagnostic
│   ├── test_backup.py           # Tests sauvegarde
│   └── test_audit.py            # Tests audit EOL
├── requirements.txt             # Dépendances Python
├── systoolbox.py                # Point d'entrée principal
├── .gitignore
├── LICENSE
└── README.md                    # Ce fichier
```

### Principes architecturaux

- **Modularité** : 3 modules indépendants partageant configuration, logs et codes retour
- **Configuration centralisée** : Fichier YAML simple + surcharge par variables d'environnement
- **Multi-plateforme natif** : Fonctionne sans modification sur Windows et Linux
- **Supervision-ready** : Sorties JSON horodatées + codes retour standardisés (0/1/2)
- **Sécurité** : Gestion des secrets via variables d'environnement (pas de credentials en dur)

---

## 🔍 Module Diagnostic

### Objectif
Confirmer rapidement que les briques critiques du siège sont disponibles et cohérentes, et produire un état synthétique d'un serveur.

### Fonctionnalités détaillées

#### 1. Vérification Active Directory / DNS
- **Cible** : Contrôleurs de domaine (DC01: 192.168.10.10, DC02: 192.168.10.11)
- **Vérifications** :
  - État des services AD DS (Active Directory Domain Services)
  - État du service DNS Server
  - Réplication entre contrôleurs de domaine
  - Temps de réponse DNS
  - FSMO roles (optionnel)
- **Sortie** : OK / WARN / CRIT avec détails

#### 2. Test MySQL WMS
- **Cible** : Base WMS (WMS-DB: 192.168.10.21)
- **Vérifications** :
  - Connectivité TCP (port 3306)
  - Authentification
  - Requête test (SELECT 1, temps réponse)
  - Nombre de connexions actives
  - Taille de la base de données
- **Seuils** : 
  - OK < 200ms
  - WARN 200-500ms
  - CRIT > 500ms ou échec connexion

#### 3. Diagnostic Windows Server
- **Informations collectées** :
  - Version OS complète (Windows Server 2016/2019/2022)
  - Uptime système
  - Utilisation CPU (moyenne, pic)
  - Utilisation RAM (physique, disponible)
  - Utilisation disques (tous volumes, % utilisé)
  - Services critiques configurables
- **Méthode** : PowerShell / WMI / wmic
- **Seuils personnalisables** dans config.yaml

#### 4. Diagnostic Ubuntu Server
- **Informations collectées** :
  - Version OS (Ubuntu 18.04/20.04/22.04/24.04 LTS)
  - Kernel version
  - Uptime système
  - Load average (1/5/15 min)
  - Utilisation CPU (via /proc/stat ou top)
  - Utilisation RAM (total, used, available, swap)
  - Utilisation disques (df -h, tous points de montage)
- **Méthode** : Commandes système (uptime, free, df, /proc)
- **Seuils personnalisables** dans config.yaml

### Exemple d'utilisation

```bash
# Via menu interactif
python systoolbox.py
> 1 (Diagnostic)

# En ligne de commande directe
python systoolbox.py --module diagnostic --target dc01,dc02,wms-db

# Diagnostic rapide (check critique uniquement)
python systoolbox.py --module diagnostic --quick-check
```

### Sortie JSON
```json
{
  "timestamp": "2026-02-16T20:39:00Z",
  "module": "diagnostic",
  "global_status": "WARNING",
  "exit_code": 1,
  "checks": {
    "ad_dns": {
      "dc01": {
        "status": "OK",
        "ad_service": "Running",
        "dns_service": "Running",
        "dns_response_time_ms": 12
      },
      "dc02": {
        "status": "OK",
        "ad_service": "Running",
        "dns_service": "Running",
        "dns_response_time_ms": 15
      }
    },
    "mysql_wms": {
      "status": "WARNING",
      "host": "192.168.10.21",
      "connection": "OK",
      "response_time_ms": 452,
      "active_connections": 23,
      "database_size_mb": 2847
    },
    "servers": {
      "wms-app": {
        "status": "OK",
        "os": "Ubuntu 20.04.6 LTS",
        "uptime_days": 127,
        "cpu_percent": 34,
        "ram_percent": 52,
        "disk_var_percent": 68
      }
    }
  }
}
```

---

## 💾 Module Sauvegarde WMS

### Objectif
Garantir l'existence, l'intégrité et la traçabilité d'exports logiques de la base WMS (MySQL).

### Fonctionnalités détaillées

#### 1. Sauvegarde SQL complète
- **Méthode** : `mysqldump` avec paramètres optimisés
- **Options** :
  - `--single-transaction` : Cohérence sans verrouillage
  - `--routines --triggers --events` : Objets complets
  - `--add-drop-table --add-locks`
  - Compression optionnelle (gzip)
- **Nommage** : `wms_backup_YYYYMMDD_HHmmss.sql[.gz]`
- **Emplacement** : Configurable (défaut: `./backups/`)

#### 2. Export CSV d'une table
- **Utilisation** : Export rapide d'une table spécifique (logs, références, etc.)
- **Format** : CSV standard avec headers
- **Séparateur** : Configurable (défaut: `;`)
- **Encodage** : UTF-8
- **Nommage** : `{table_name}_export_YYYYMMDD_HHmmss.csv`

#### 3. Traçabilité et intégrité
- **Log JSON** : Chaque opération génère un fichier JSON
  - Horodatage début/fin
  - Taille fichier généré
  - Hash MD5/SHA256 du fichier
  - Durée de l'opération
  - Statut (SUCCESS/FAILED)
  - Messages d'erreur si échec
- **Vérification post-backup** :
  - Fichier existe et taille > 0
  - Fichier lisible/valide
  - Hash calculé et stocké

#### 4. Rotation automatique (optionnel)
- Conservation des N dernières sauvegardes
- Suppression automatique des anciennes (configurable)

### Exemple d'utilisation

```bash
# Sauvegarde SQL complète via menu
python systoolbox.py
> 2 (Sauvegarde WMS)
> 1 (Dump SQL complet)

# Export CSV d'une table via menu
python systoolbox.py
> 2 (Sauvegarde WMS)
> 2 (Export CSV)
> Nom de la table : orders

# Ligne de commande directe
python systoolbox.py --module backup --type sql --compress
python systoolbox.py --module backup --type csv --table orders
```

### Sortie JSON de traçabilité
```json
{
  "timestamp": "2026-02-16T21:05:00Z",
  "module": "backup_wms",
  "operation": "sql_dump",
  "status": "SUCCESS",
  "exit_code": 0,
  "backup": {
    "database": "wms_production",
    "host": "192.168.10.21",
    "filename": "wms_backup_20260216_210500.sql.gz",
    "path": "./backups/wms_backup_20260216_210500.sql.gz",
    "size_bytes": 45821743,
    "size_mb": 43.69,
    "compressed": true,
    "hash_sha256": "a3f5e8c9d2b1f4a7e6c8d9f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "duration_seconds": 23.4,
    "start_time": "2026-02-16T21:05:00Z",
    "end_time": "2026-02-16T21:05:23Z"
  }
}
```

### Gestion des erreurs
- Connexion MySQL échouée → Code retour 2 (CRIT)
- Dump partiel ou corrompu → Code retour 2 (CRIT)
- Espace disque insuffisant → Détection préventive + alerte

---

## 🌐 Module Audit d'obsolescence

### Objectif
Fournir un inventaire réseau minimal et qualifier le statut de support/EOL (End Of Life) des éléments détectés.

### Fonctionnalités détaillées

#### 1. Scan réseau
- **Entrée** : Plage IP (format CIDR, ex: `192.168.10.0/24`)
- **Découverte** :
  - Scan ICMP (ping) pour détecter hôtes actifs
  - Optionnel : Scan ports TCP (22, 80, 443, 3389, etc.)
  - Timeout configurable par hôte
- **Performance** : Scan parallélisé (threads/async)
- **Sortie** : Liste d'hôtes actifs avec IP et hostname (si résolvable)

#### 2. Détection OS
- **Méthodes** :
  - TTL analysis (ICMP)
  - Banner grabbing (SSH, HTTP, RDP)
  - Empreintes TCP/IP (nmap-like si disponible)
  - SNMP sysDescr (si communauté configurée)
- **OS identifiés** :
  - Windows (7, 8, 10, 11, Server 2008/2012/2016/2019/2022)
  - Linux (Ubuntu, Debian, RHEL, CentOS, etc.) avec version
  - Autres (macOS, BSD, équipements réseau)
- **Confiance** : Niveau de certitude (haute/moyenne/faible)

#### 3. Référentiel EOL
- **Base de données intégrée** :
  - Windows : Dates officielles Microsoft
  - Ubuntu LTS : Dates Canonical (Standard/Extended)
  - Autres distros : Dates constructeurs
  - Source et date de validité documentées
- **Mise à jour** : Fichier JSON/YAML mis à jour manuellement ou via API publique
- **Structure** :
```json
{
  "os_family": "Windows Server",
  "versions": [
    {
      "version": "2012 R2",
      "release_date": "2013-10-18",
      "mainstream_end": "2018-10-09",
      "extended_end": "2023-10-10",
      "status": "EOL"
    },
    {
      "version": "2016",
      "mainstream_end": "2022-01-11",
      "extended_end": "2027-01-11",
      "status": "Extended Support"
    }
  ]
}
```

#### 4. Import CSV
- **Format attendu** :
```csv
Hostname,IP,OS,Version
DC01,192.168.10.10,Windows Server,2016
WMS-DB,192.168.10.21,Ubuntu,20.04 LTS
```
- **Enrichissement** : Croisement avec référentiel EOL pour chaque ligne
- **Export** : CSV enrichi avec colonnes supplémentaires (statut, date EOL, jours restants)

#### 5. Rapport d'obsolescence
- **Catégorisation** :
  - 🔴 **Critique** : Version non supportée (EOL dépassée)
  - 🟠 **Attention** : Fin de support < 6 mois
  - 🟡 **Vigilance** : Fin de support < 12 mois
  - 🟢 **OK** : Support actif (> 12 mois)
- **Statistiques** :
  - Nombre total d'hôtes
  - Répartition par statut
  - Répartition par OS
  - Top 5 des OS en fin de vie
- **Recommandations** : Priorisation des migrations

### Exemple d'utilisation

```bash
# Audit complet d'une plage réseau
python systoolbox.py
> 3 (Audit obsolescence)
> 1 (Scan réseau)
> Plage IP [192.168.10.0/24] : 

# Vérifier EOL d'un OS spécifique
python systoolbox.py
> 3 (Audit obsolescence)
> 2 (Consulter référentiel EOL)
> OS : Ubuntu

# Import CSV pour enrichissement
python systoolbox.py
> 3 (Audit obsolescence)
> 3 (Import CSV)
> Fichier : ./inventory.csv
```

### Rapport texte exemple

```
═══════════════════════════════════════════════════════════════════════
🌐 RAPPORT AUDIT OBSOLESCENCE - NTL Siège Lille (192.168.10.0/24)
📅 Date : 2026-02-16 21:30:00
═══════════════════════════════════════════════════════════════════════

📊 RÉSUMÉ
  • Total hôtes détectés : 15
  • Hôtes avec OS identifié : 13 (87%)
  • 🔴 Non supportés : 2 (13%)
  • 🟠 Bientôt EOL (<6 mois) : 1 (7%)
  • 🟡 Vigilance (<12 mois) : 3 (20%)
  • 🟢 Supportés : 7 (47%)

─────────────────────────────────────────────────────────────────────

🔴 CRITIQUE - NON SUPPORTÉS (Action immédiate requise)

Hôte            IP                OS détecté          Version    EOL depuis      Risque
DC01            192.168.10.10     Windows Server      2012 R2    2023-10-10      🔥 Haute sécurité
PRINT-SRV       192.168.10.45     Windows Server      2008 R2    2020-01-14      🔥 Critique

─────────────────────────────────────────────────────────────────────

🟠 ATTENTION - FIN DE SUPPORT PROCHE (<6 mois)

Hôte            IP                OS détecté          Version    EOL prévu       Jours restants
FILE-SRV        192.168.10.30     Windows Server      2016       2027-01-11      329 jours

─────────────────────────────────────────────────────────────────────

🟡 VIGILANCE - À PLANIFIER (<12 mois)

Hôte            IP                OS détecté          Version    EOL prévu       Jours restants
WMS-DB          192.168.10.21     Ubuntu              20.04 LTS  2025-04-25      68 jours (STM)
WMS-APP         192.168.10.22     Ubuntu              20.04 LTS  2025-04-25      68 jours (STM)
BACKUP-01       192.168.10.50     CentOS              7          2024-06-30      Déjà EOL

─────────────────────────────────────────────────────────────────────

🟢 SUPPORTÉS (>12 mois)

Hôte            IP                OS détecté          Version    EOL prévu       
DC02            192.168.10.11     Windows Server      2022       2031-10-13
APP-SRV-01      192.168.10.25     Ubuntu              22.04 LTS  2027-04-21
[... 5 autres hôtes ...]

─────────────────────────────────────────────────────────────────────

📈 STATISTIQUES PAR OS

OS                      Nombre    % Non supportés    % Bientôt EOL
Windows Server          8         25% (2/8)         12.5% (1/8)
Ubuntu LTS              4         25% (1/4)         50% (2/4)
CentOS                  1         100% (1/1)        0%

─────────────────────────────────────────────────────────────────────

💡 RECOMMANDATIONS

1️⃣  PRIORITÉ MAXIMALE
   • Migrer DC01 (Windows Server 2012 R2 → 2022)
   • Remplacer PRINT-SRV (2008 R2 hors support depuis 2020)

2️⃣  PRIORITÉ HAUTE (6 mois)
   • Planifier upgrade FILE-SRV (2016 → 2022)

3️⃣  PLANIFICATION (12 mois)
   • Upgrade WMS-DB et WMS-APP vers Ubuntu 24.04 LTS
   • Migrer BACKUP-01 de CentOS 7 vers Rocky/Alma Linux 9

4️⃣  BUDGET PRÉVISIONNEL
   • 2 migrations Windows Server : 2 licences + 4 jours/homme
   • 3 migrations Linux : 0€ licence + 3 jours/homme
   • Total estimé : ~6000€ + 7 jours/homme

═══════════════════════════════════════════════════════════════════════
📄 Rapport détaillé JSON : ./reports/audit_eol_20260216_2130.json
📊 Export CSV : ./reports/audit_eol_20260216_2130.csv
═══════════════════════════════════════════════════════════════════════
```

### Sources référentiel EOL
- **Windows** : [Microsoft Lifecycle Policy](https://docs.microsoft.com/lifecycle/)
- **Ubuntu** : [Ubuntu Releases Wiki](https://wiki.ubuntu.com/Releases)
- **CentOS/RHEL** : [Red Hat Product Life Cycles](https://access.redhat.com/support/policy/updates/errata)
- **Date de validité** : Référentiel vérifié le 2026-02-01

---

## 🎯 Cas d'usage DSI NTL

### 1. Routine quotidienne (5h30 - Avant ouverture des quais)

**Objectif** : Valider que les services critiques sont opérationnels avant le début d'activité.

```bash
python systoolbox.py --module diagnostic --quick-check --alert-on-critical
```

**Workflow automatisé** (planificateur de tâches Windows / cron Linux) :
```bash
0 5 * * * /opt/ntl-systoolbox/systoolbox.py --module diagnostic --output /var/log/ntl-checks/daily_$(date +\%Y\%m\%d).json && [ $? -eq 0 ] || mail -s "NTL Diagnostic ALERTE" dsi@ntl.fr < /var/log/ntl-checks/daily_$(date +\%Y\%m\%d).json
```

**Action si code retour 2 (CRIT)** :
- Email/SMS automatique équipe astreinte
- Escalade si pas de réponse en 15 min
- Intervention avant 6h pour éviter impact opérationnel

---

### 2. Sauvegarde hebdomadaire WMS (Dimanche 2h)

**Objectif** : Dump SQL complet + export CSV tables critiques en fenêtre de maintenance.

```bash
# Script wrapper sauvegarde_wms_hebdo.sh
#!/bin/bash
LOG_DIR="/var/log/ntl-backup"
BACKUP_DIR="/nas/backups/wms"
DATE=$(date +%Y%m%d)

# Dump SQL complet
python /opt/ntl-systoolbox/systoolbox.py \
  --module backup \
  --type sql \
  --compress \
  --output "$BACKUP_DIR" \
  > "$LOG_DIR/backup_${DATE}.log" 2>&1

CODE=$?

# Export CSV tables critiques
python /opt/ntl-systoolbox/systoolbox.py \
  --module backup \
  --type csv \
  --tables "orders,inventory,shipping" \
  --output "$BACKUP_DIR/csv" \
  >> "$LOG_DIR/backup_${DATE}.log" 2>&1

# Copie distante (rsync vers site secondaire)
if [ $CODE -eq 0 ]; then
  rsync -avz "$BACKUP_DIR/" backup@site-distant:/mnt/backup-ntl/
fi

exit $CODE
```

**Planification** : Tâche cron dimanche 2h
```cron
0 2 * * 0 /opt/ntl-systoolbox/scripts/sauvegarde_wms_hebdo.sh
```

---

### 3. Audit obsolescence mensuel

**Objectif** : Rapport EOL pour COPIL IT (2e mardi du mois).

```bash
# Scan siège + entrepts
python systoolbox.py --module audit --range 192.168.10.0/24,192.168.20.0/24,192.168.30.0/24,192.168.40.0/24

# Génération rapport exécutif
python systoolbox.py --module audit --generate-report --format pdf --lang fr
```

**Workflow** :
1. Lundi soir : Scan automatisé
2. Mardi matin : Revue rapport par admin réseau
3. COPIL : Présentation synthèse + plan d'action

---

### 4. Intégration supervision (Zabbix - SUPER-01)

**Configuration Zabbix User Parameter** :
```ini
# /etc/zabbix/zabbix_agentd.d/ntl-systoolbox.conf
UserParameter=ntl.diagnostic.status,/opt/ntl-systoolbox/systoolbox.py --module diagnostic --output-format json --silent | jq -r '.exit_code'
UserParameter=ntl.diagnostic.ad_status,/opt/ntl-systoolbox/systoolbox.py --module diagnostic --output-format json --silent | jq -r '.checks.ad_dns.dc01.status'
UserParameter=ntl.diagnostic.mysql_ms,/opt/ntl-systoolbox/systoolbox.py --module diagnostic --output-format json --silent | jq -r '.checks.mysql_wms.response_time_ms'
```

**Triggers Zabbix** :
```
Nom : NTL Diagnostic Critical
Expression : {ntl-host:ntl.diagnostic.status.last()}=2
Sévérité : High
Action : Email + SMS astreinte
```

---

## ⚙️ Configuration

### Fichier config.yaml

```yaml
# Configuration NTL-SysToolbox
version: "1.0"

# Général
general:
  log_level: "INFO"  # DEBUG, INFO, WARNING, ERROR
  log_format: "json"  # json ou text
  output_dir: "./reports"
  timezone: "Europe/Paris"

# Module Diagnostic
diagnostic:
  domain_controllers:
    - host: "192.168.10.10"
      name: "DC01"
    - host: "192.168.10.11"
      name: "DC02"
  
  mysql_wms:
    host: "192.168.10.21"
    port: 3306
    database: "wms_production"
    user: "monitoring"
    password: "${MYSQL_MONITOR_PASS}"  # Variable d'environnement
    timeout: 10
  
  thresholds:
    mysql_response_ms:
      warn: 200
      crit: 500
    cpu_percent:
      warn: 80
      crit: 95
    ram_percent:
      warn: 85
      crit: 95
    disk_percent:
      warn: 80
      crit: 90

# Module Sauvegarde WMS
backup:
  mysql:
    host: "192.168.10.21"
    port: 3306
    database: "wms_production"
    user: "backup_user"
    password: "${MYSQL_BACKUP_PASS}"
  
  output_dir: "/nas/backups/wms"
  compression: true  # gzip
  retention_days: 30  # Rotation automatique
  
  csv_export:
    separator: ";"
    encoding: "utf-8"
    include_headers: true

# Module Audit obsolescence
audit:
  network:
    default_ranges:
      - "192.168.10.0/24"  # Siège Lille
      - "192.168.20.0/24"  # WH1 Lens
      - "192.168.30.0/24"  # WH2 Valenciennes
      - "192.168.40.0/24"  # WH3 Arras
    timeout_per_host: 2
    parallel_threads: 20
  
  eol_database:
    file: "./data/eol_reference.json"
    auto_update: false
    last_update: "2026-02-01"
  
  report:
    categories:
      critical_days: 0      # EOL dépassée
      warning_days: 180     # <6 mois
      vigilance_days: 365   # <12 mois
```

### Variables d'environnement

**Secrets sensibles** (ne jamais commiter dans Git) :

```bash
# Linux/macOS
export MYSQL_MONITOR_PASS="V0tr3M0tD3P@ss3!"
export MYSQL_BACKUP_PASS="B@ckupS3cur3P@ss!"

# Windows PowerShell
$env:MYSQL_MONITOR_PASS="V0tr3M0tD3P@ss3!"
$env:MYSQL_BACKUP_PASS="B@ckupS3cur3P@ss!"

# Windows CMD
set MYSQL_MONITOR_PASS=V0tr3M0tD3P@ss3!
set MYSQL_BACKUP_PASS=B@ckupS3cur3P@ss!
```

**Fichier .env** (local uniquement, ajouté dans .gitignore) :
```env
MYSQL_MONITOR_PASS=V0tr3M0tD3P@ss3!
MYSQL_BACKUP_PASS=B@ckupS3cur3P@ss!
```

---

## 📊 Sorties et codes retour

### Codes retour standardisés

| Code | Statut | Signification | Usage supervision |
|------|--------|---------------|-------------------|
| `0` | **SUCCESS** | Toutes vérifications OK | Monitoring: OK |
| `1` | **WARNING** | Au moins une alerte (non bloquant) | Monitoring: WARN |
| `2` | **CRITICAL** | Échec critique détecté | Monitoring: CRIT, alerte |

**Exemple exploitation Bash** :
```bash
python systoolbox.py --module diagnostic
CODE=$?
case $CODE in
  0) echo "✅ Tout est OK" ;;
  1) echo "⚠️ Avertissements détectés" ;;
  2) echo "🚨 Problème critique!" && alert-team.sh ;;
esac
```

### Formats de sortie

#### 1. Console (texte formaté)
- Lisible par humain
- Couleurs ANSI (désactivables avec `--no-color`)
- Tableaux, symboles, sections claires

#### 2. JSON horodaté
```json
{
  "timestamp": "2026-02-16T21:00:00Z",
  "module": "diagnostic|backup|audit",
  "version": "1.0.0",
  "exit_code": 0,
  "status": "SUCCESS",
  "data": { /* Données module-specific */ },
  "execution_time_seconds": 12.34,
  "hostname": "admin-workstation"
}
```

#### 3. CSV (audit EOL, exports)
```csv
Hostname;IP;OS;Version;Status;EOL_Date;Days_Remaining;Risk_Level
DC01;192.168.10.10;Windows Server;2012 R2;EOL;2023-10-10;-853;CRITICAL
WMS-DB;192.168.10.21;Ubuntu;20.04 LTS;Extended;2025-04-25;68;VIGILANCE
```

---

## 🛠️ Développement & Contribution

### Structure Git

```
main (stable, releases tagged)
  ├── v1.0.0 (tag)
  └── v1.1.0 (tag)
dev (intégration continues)
  ├── feature/ad-replication-check
  ├── feature/postgresql-support
  └── bugfix/mysql-timeout
```

### Workflow contribution

```bash
# 1. Créer branche feature
git checkout dev
git pull origin dev
git checkout -b feature/ma-nouvelle-fonction

# 2. Développer + tester
# ... code ...
python -m pytest tests/

# 3. Commit
git add .
git commit -m "feat(diagnostic): Ajout vérification réplication AD"

# 4. Push + Pull Request
git push origin feature/ma-nouvelle-fonction
# Créer PR sur GitHub/GitLab vers 'dev'

# 5. Après validation, merge dans dev
# 6. Release : merge dev → main + tag version
```

### Conventions commits
- `feat(module):` Nouvelle fonctionnalité
- `fix(module):` Correction bug
- `docs:` Documentation
- `test:` Tests
- `refactor:` Refactorisation sans changement fonctionnel
- `chore:` Maintenance (dépendances, config)

### Tests

```bash
# Tests unitaires
python -m pytest tests/test_diagnostic.py -v

# Tests d'intégration (nécessite VMs de test)
python -m pytest tests/integration/ --vm-config tests/vms.yaml

# Couverture
python -m pytest --cov=src tests/
```

**VMs de test fournies** (EPSI Lab) :
- **MSPR-GRP1 Windows Server** : 10.5.60.10
  - Domaine : MSPR-GRP1.lan
  - Login : Administrateur / Azerty89
- **MSPR-GRP1 Ubuntu Server** : 10.5.60.20
  - Login : Administrateur / azerty89

---

## 📚 Documentation complète

Fichiers de documentation détaillée dans le dépôt :

| Document | Contenu | Public cible |
|----------|---------|--------------|
| **[INSTALL.md](docs/INSTALL.md)** | Guide installation pas-à-pas (5-10 min) | DSI, Admins IT |
| **[USAGE.md](docs/USAGE.md)** | Manuel utilisateur détaillé, tous modules | Utilisateurs quotidiens |
| **[TECH.md](docs/TECH.md)** | Architecture, choix techniques, diagrammes | Développeurs, Architectes |
| **[API.md](docs/API.md)** | Documentation API (si mode serveur futur) | Intégrateurs |
| **[CHANGELOG.md](CHANGELOG.md)** | Historique versions, nouveautés, correctifs | Tous |

### Livrables attendus (projet EPSI)

Conformément au cahier des charges :

1. ✅ **Code source** : Dépôt Git [https://github.com/Not-mat-collab/ntl-systoolbox](https://github.com/Not-mat-collab/ntl-systoolbox)
2. ✅ **Dossier technique et fonctionnel** : `docs/TECH.md`
3. ✅ **Manuel installation & utilisation** : `docs/INSTALL.md` + `docs/USAGE.md`
4. ✅ **Exécution référence audit obsolescence** : `reports/audit_reference_20260216.json`

---

## 🏢 Contexte NTL

### Nord Transit Logistics - Présentation

**NTL** est une PME de logistique implantée dans les **Hauts-de-France** :
- **Siège** : Lille (192.168.10.0/24)
- **Entrepts** :
  - WH1 Lens (192.168.20.0/24)
  - WH2 Valenciennes (192.168.30.0/24)
  - WH3 Arras (192.168.40.0/24)
- **Cross-dock** saisonnier activé en période haute (CDK - 192.168.50.0/24)

**Effectifs** : ~240 salariés (jusqu'à 300 avec intérim haute saison)
- 180 en entrept (opérationnels)
- 15-20 planification/transport/client
- 18-20 fonctions support (RH, compta, commerce)
- **4 IT** : RSI + Admin sys/réseau + Technicien support + Alternant

### Infrastructure IT (synthèse)

| Composant | Détails | Criticité |
|-----------|---------|-----------|
| **Hyperviseur** | Dell PowerEdge R630, VMware ESXi 6.5 | Haute |
| **Contrôleurs domaine** | DC01 (192.168.10.10), DC02 (.11) - AD/DNS | Critique |
| **WMS** | WMS-DB (MySQL Ubuntu 20.04, .21) + WMS-APP (.22) | **Critique** - Bloque tous sites |
| **Sauvegarde** | NAS 6To RAID5 + scripts, sans test régulier | Risque élevé |
| **Supervision** | Zabbix (SUPER-01, .50) - technique uniquement | Partielle |
| **Réseau** | Liens 200Mbps par site, VPN Fortinet/DrayTek | Pas de redondance |

### Enjeux métier

1. **Continuité WMS** : Indisponibilité = arrêt quais 5h30-18h30 (CA direct)
2. **Sauvegardes fiables** : Risque perte données, pas de tests restauration
3. **Obsolescence** : Équipements vieillissants (Windows 2012, VMware 6.5)
4. **Supervision** : Manque indicateurs service (délai EDI, santé WMS)
5. **Fenêtres maintenance** : Très courtes (nuit uniquement)

**Ce projet répond directement à ces enjeux** en fournissant un outil unifié pour :
- Valider quotidiennement la santé des services critiques
- Industrialiser et tracer les sauvegardes WMS
- Anticiper les risques d'obsolescence via audit réseau

---

## 📞 Support & Contact

### Équipe projet

- **Chef de projet** : [Votre nom]
- **Développeurs** : [Noms équipe]
- **Client** : Nord Transit Logistics - Direction IT

### Ressources

- **Dépôt Git** : [https://github.com/Not-mat-collab/ntl-systoolbox](https://github.com/Not-mat-collab/ntl-systoolbox)
- **Issues/Bugs** : GitHub Issues
- **Documentation** : [Wiki GitHub](https://github.com/Not-mat-collab/ntl-systoolbox/wiki)

---

## 📜 Licence

**MIT License** (ou selon choix équipe)

```
Copyright (c) 2026 NTL-SysToolbox Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🎓 Projet académique

Ce projet s'inscrit dans le cadre de la **MSPR (Mise en Situation Professionnelle Reconstituée)** du bloc **E6.1 - Concevoir et tester des solutions applicatives** du programme **Administrateur Systèmes, Réseaux et Bases de Données (ASRBD)** à l'**EPSI**.

**Année universitaire** : 2025-2026  
**Équipe** : MSPR-B3-GRP1  
**Durée** : 19 heures de préparation + soutenance orale (50 min)

---

<div align="center">

**NTL-SysToolbox** - Fiabilité, Traçabilité, Anticipation

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![EPSI](https://img.shields.io/badge/Projet-EPSI%20MSPR-orange)](https://www.epsi.fr/)

Made with ❤️ for Nord Transit Logistics

</div>