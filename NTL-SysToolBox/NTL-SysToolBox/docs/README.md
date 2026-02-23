# NTL-SysToolbox

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
| **Audit obsolescence** | Qualifier le statut support/EOL réseau | 🌐 Scan réseau automatisé (plages IP CIDR ou range)<br>🔍 Détection OS multi-méthodes (nmap, bannières, SMB, HTTP)<br>📋 Base de données EOL intégrée (Windows/Linux/macOS)<br>⚠️ Rapport détaillé (TXT/CSV/JSON) avec statuts EOL<br>📊 Import/export CSV pour inventaire existant |

**Sorties uniformes** : 
- Texte lisible par un humain (synthèse, alertes)
- **JSON horodaté** pour exploitation automatisée
- **Codes retour** exploitables en supervision (0=OK, 1=WARN, 2=CRIT)

---

## 🚀 Installation rapide

### Prérequis système

- **OS** : Windows Server 2016+ / Ubuntu 18.04+ (ou autre distribution Linux)
- **Runtime** : Python 3.9+
- **Accès réseau** : Vers contrôleurs de domaine (DC01, DC02), base MySQL WMS, plages IP à auditer
- **Privilèges** : Droits d'administration pour vérifications système locales, accès LDAP pour AD, credentials MySQL
- **Prérequis Module 3** : `nmap` installé sur le système (`sudo apt install nmap` ou via site officiel Windows)

### Installation en 3 étapes

```bash
# 1. Cloner le dépôt
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git
cd ntl-systoolbox

# 2. Installer les dépendances (incluant nmap Python)
pip install -r requirements.txt
# Ou sous Windows : py -m pip install -r requirements.txt

# 3. Vérifier nmap système
nmap --version  # Doit afficher la version de nmap

```

### Lancement
```bash
python main.py
# Ou sous Windows : py main.py
```

---

## 🎮 Utilisation - Menu interactif

L'outil expose un **menu CLI interactif** qui guide l'utilisateur à travers les différentes fonctions et demande les arguments nécessaires.

```
$ python systoolbox.py

╔════════════════════════════════════════════════════╗
║           🌟 NTL-SysToolbox v1.0.0 🌟             ║
║    Outil d'exploitation Nord Transit Logistics     ║
╚════════════════════════════════════════════════════╝

Modules disponibles :
  1️⃣  Module Diagnostic (AD/DNS/MySQL/Serveurs)
  2️⃣  Module Sauvegarde WMS (SQL/CSV)
  3️⃣  Module Audit obsolescence réseau
  ⚙️  Configuration
  0️⃣  Quitter

Votre choix > 3

================================================================================
                     MODULE D'AUDIT D'OBSOLESCENCE RÉSEAU
================================================================================

 [1] Scanner une plage réseau
 [2] Lister les versions d'un OS et leurs dates EOL
 [3] Analyser un fichier CSV
 [4] Quitter

================================================================================
Votre choix [1-4]:
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

```

---

## 🏗️ Architecture

### Structure du projet

```
NTL-SysToolbox/
├── src/
│   ├── module1_diagnostic.py
│   ├── module2_backup_wms.py
│   ├── module3_audit.py           
│   └── ntl_config.json
├── backups/                        # Sauvegardes générées
│   ├── ad_dns/
│   ├── mysql/
│   ├── windows/
│   ├── ubuntu/
│   ├── global/
│   ├── wms/
│   └── audit/                      
├── docs/
│   ├── INSTALL.md                  # Guide installation DSI
│   ├── TECH.md                     # Architecture et choix techniques
│   └── USAGE.md                    # Guide utilisation détaillé
├── requirements.txt                # Dépendances Python
├── main.py                         # Point d'entrée principal
├── LICENSE
└── README.md                       # Ce fichier
```

### Principes architecturaux

- **Modularité** : 3 modules indépendants partageant configuration, logs et codes retour
- **Configuration centralisée** : Fichier JSON simple + surcharge par variables d'environnement
- **Multi-plateforme natif** : Fonctionne sans modification sur Windows et Linux
- **Supervision-ready** : Sorties JSON horodatées + codes retour standardisés (0/1/2)
- **Sécurité** : Gestion des secrets via variables d'environnement (pas de credentials en dur)

---

## 🔍 Module 1 Diagnostic

### Objectif
Confirmer rapidement que les briques critiques du siège sont disponibles et cohérentes, et produire un état synthétique d'un serveur.

### Fonctionnalités détaillées

#### 1. Vérification Active Directory / DNS
- **Cible** : Contrôleurs de domaine (DC01: 192.168.10.10, DC02: 192.168.10.11)
- **Vérifications** :
  - État des services AD DS (Active Directory Domain Services)
  - État du service DNS Server
  - État du Kerberos
  - Temps de réponse DNS
- **Sortie** : OK / WARN / CRIT avec détails

#### 2. Test MySQL WMS
- **Cible** : Base WMS (WMS-DB: 192.168.10.21)
- **Vérifications** :
  - Connectivité TCP (port 3306) & Authentification
  - Version
  - Uptime
  - Nombre de connexions actives
  - Nombre de requêtes totales
- **Seuils** : 
  - OK < 200ms
  - WARN 200-500ms
  - CRIT > 500ms ou échec connexion

#### 3. Diagnostic Windows Server
- **Informations collectées** :
  - Nom de la machine
  - Version OS complète (Windows Server 2016/2019/2022/2025)
  - Uptime système
  - Utilisation CPU (moyenne, pic)
  - Utilisation RAM (physique, disponible)
  - Utilisation disques (tous volumes, % utilisé)
  - Services critiques configurables
- **Méthode** : psutil (local) / pypsrp = WinRM/PowerShell (distante)


#### 4. Diagnostic Ubuntu Server
- **Informations collectées** :
  - Nom de la machine
  - Version OS (Ubuntu 18.04/20.04/22.04/24.04 LTS)
  - Kernel version
  - Uptime système
  - Load average (1/5/15 min)
  - Utilisation CPU (via /proc/stat ou top)
  - Utilisation RAM (total, used, available, swap)
  - Utilisation disques (df -h, tous points de montage)
- **Méthode** : psutil (local) / paramiko = SSH (distante) - Commandes système (uptime, free, df, /proc)

### Exemple d'utilisation

```bash
# Via menu interactif
python main.py
> 1 (Diagnostic)

# En ligne de commande directe
python main.py --module diagnostic --target wms-db

```

### Sortie JSON
```json
{
  "timestamp": "2026-02-13T19:40:08.774164",
  "module": "diagnostic",
  "checks": [
    {
      "type": "MySQL_Database",
      "host": "10.5.60.20",
      "port": 3306,
      "timestamp": "2026-02-13T19:40:08.774190",
      "status": "OK",
      "details": {
        "version": "10.11.14-MariaDB-0ubuntu0.24.04.1",
        "uptime_seconds": 646873,
        "uptime_formatted": "7j 11h 41min",
        "active_connections": 1,
        "total_queries": 269
      }
    }
  ]
}
```

---

## 💾 Module 2 Sauvegarde WMS

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
# Sauvegarde SQL complète et Export CSV d'une table
python main.py
> 2 (Sauvegarde WMS)
> Lancer? (o/n) [o]: 
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

## 🌐 Module 3 Audit d'obsolescence

### Objectif
Fournir un inventaire réseau automatisé et qualifier le statut de support/EOL (End Of Life) des systèmes d'exploitation détectés.

### Fonctionnalités détaillées

#### 1. Scan réseau automatisé

**Entrée** : 
- Plage IP CIDR : `192.168.1.0/24`, `10.5.60.0/24`
- Plage IP range : `192.168.1.1-192.168.1.100`
- IP unique : `192.168.1.50`

**Découverte réseau** :
- Scan nmap avec détection OS (`-O`)
- Scan de ports critiques : 22 (SSH), 80/443 (HTTP/HTTPS), 3389 (RDP), 135/139/445 (SMB)
- Timeout configurable par hôte
- Détection parallélisée (multi-thread)

**Sortie** : Liste d'hôtes actifs avec IP, hostname, MAC, vendor, ports ouverts, OS détecté

#### 2. Détection OS avancée

**Méthodes multi-couches** :
1. **nmap OS fingerprinting** : Analyse TCP/IP stack, détection build Windows (10240+, 22000+)
2. **SSH banner grabbing** : Extraction version Ubuntu/Debian/CentOS depuis bannière OpenSSH
3. **HTTP headers** : Détection IIS → Windows Server (version 2012/2016/2019/2022)
4. **SMB probing** : Négociation SMB pour détecter Windows
5. **Normalisation intelligente** : Consolidation des résultats pour version cohérente

**OS identifiés** :
- **Windows** : 7, 8, 10, 11, Server 2008 R2/2012/2012 R2/2016/2019/2022 (avec build number si disponible)
- **Linux** : Ubuntu (14.04→24.04), Debian (9→12), CentOS (7→9), RHEL (7→9)
- **macOS** : Big Sur, Monterey, Ventura, Sonoma

**Niveau de confiance** : Haute/Moyenne/Faible selon méthode de détection

#### 3. Base de données EOL intégrée

**Couverture complète** :
- **Windows** : 
  - Windows 10 → EOL mainstream : 14/10/2025, Extended : 13/10/2026
  - Windows 11 → Support actif
  - Windows Server 2012 R2 → EOL : 10/10/2023
  - Windows Server 2016 → Support étendu jusqu'en 2027
  - Windows Server 2019/2022 → Support actif

- **Linux** :
  - Ubuntu LTS : 18.04 (support étendu), 20.04 (EOL proche), 22.04/24.04 (support actif)
  - Debian : 9 (EOL), 10 (support étendu), 11/12 (support actif)
  - CentOS : 7 (support étendu), 8 (EOL), 9 (support actif)
  - RHEL : Support jusqu'en 2024-2032 selon version

- **macOS** : Big Sur (EOL), Monterey (EOL proche), Ventura/Sonoma (support actif)

**Structure base EOL** :
```python
{
  "Windows 10": {
    "release_date": "2015-07-29",
    "eol_date": "2025-10-14",         # Mainstream
    "eol_extended_date": "2026-10-13", # Extended Support
    "status": "soon_eol"
  }
}
```

#### 4. Import/Export CSV

**Format CSV d'import** :
```csv
ip,hostname,os_family,os_version
192.168.1.10,dc01,Windows,Windows Server 2019
192.168.1.20,wms-db,Linux,Ubuntu 20.04
```

**Traitement automatique** :
1. Lecture CSV avec détection séparateur (`,`, `;`, `\t`)
2. Normalisation des noms de colonnes
3. Validation des données (IPs valides, colonnes requises présentes)
4. Enrichissement avec base EOL
5. Export CSV enrichi avec statut EOL et jours restants

**CSV enrichi** :
```csv
IP,Hostname,Famille OS,Version OS,Statut,Date EOL,Jours restants
192.168.1.10,dc01,Windows,Windows Server 2019,Support étendu uniquement,2024-01-09,N/A
192.168.1.20,wms-db,Linux,Ubuntu 20.04,EOL proche (< 3 mois),2025-04-23,45
```

#### 5. Génération de rapports multi-formats

**Catégorisation automatique** :
- 🟢 **Supporté** : Support mainstream actif (> 12 mois)
- 🟡 **Warning** : EOL dans moins de 12 mois
- 🟠 **EOL proche** : EOL dans moins de 90 jours (3 mois)
- 🔵 **Support étendu** : Mainstream terminé, extended support actif
- 🔴 **EOL** : Fin de support dépassée, non supporté
- ⚪ **Inconnu** : Système non reconnu ou version non référencée

**Formats de rapport** :

1. **TXT (human-readable)** :
```
================================================================================
RAPPORT D'AUDIT D'OBSOLESCENCE
================================================================================
Date de génération: 23/02/2026 09:45:12

STATISTIQUES GLOBALES
--------------------------------------------------------------------------------
Total de composants: 45
Supportés: 28
EOL proche (< 3 mois): 5
EOL dans moins d'un an: 3
Support étendu uniquement: 4
EOL (non supporté): 3
Inconnu: 2

COMPOSANTS NÉCESSITANT UNE ATTENTION IMMÉDIATE
--------------------------------------------------------------------------------
  192.168.1.15 (srv-file) - Windows Server 2012 R2
    Statut: EOL (non supporté)
    Date EOL: 10/10/2023 (Jours restants: N/A)

  192.168.1.30 (srv-backup) - Ubuntu 18.04
    Statut: EOL proche (< 3 mois)
    Date EOL: 26/04/2023 (Jours restants: 62)

DÉTAIL DES COMPOSANTS
--------------------------------------------------------------------------------
192.168.1.10 | dc01 | Windows | Windows Server 2019 | Support étendu uniquement | EOL: 09/01/2024 | Jours: N/A
192.168.1.20 | wms-db | Linux | Ubuntu 22.04 | Supporté | EOL: 21/04/2027 | Jours: 456
[...]
```

2. **CSV (Excel-compatible)** :
```csv
IP,Hostname,Famille OS,Version OS,Statut,Date EOL,Jours restants
192.168.1.10,dc01,Windows,Windows Server 2019,Support étendu uniquement,2024-01-09,N/A
192.168.1.15,srv-file,Windows,Windows Server 2012 R2,EOL (non supporté),2023-10-10,N/A
192.168.1.20,wms-db,Linux,Ubuntu 22.04,Supporté,2027-04-21,456
```

3. **JSON (machine-readable)** :
```json
{
  "generation_date": "2026-02-23T09:45:12.123456",
  "statistics": {
    "total": 45,
    "supported": 28,
    "soon_eol": 5,
    "warning": 3,
    "extended_support": 4,
    "eol": 3,
    "unknown": 2,
    "by_os_family": {
      "Windows": {
        "total": 25,
        "supported": 12,
        "eol": 2,
        "soon_eol": 1
      },
      "Linux": {
        "total": 18,
        "supported": 15,
        "eol": 1,
        "soon_eol": 2
      }
    },
    "critical": [
      {
        "ip": "192.168.1.15",
        "hostname": "srv-file",
        "os_version": "Windows Server 2012 R2",
        "status": "eol",
        "eol_date": "2023-10-10",
        "days_until_eol": null
      }
    ]
  },
  "components": [...]
}
```

### Exemple d'utilisation

#### Scan réseau complet

```bash
# Via menu interactif
python systoolbox.py
> 3 (Audit obsolescence)
> 1 (Scanner une plage réseau)
> Plage IP: 192.168.1.0/24
> Exporter les résultats en CSV? (o/n) [n]: o
> Nom du fichier CSV [scan_results.csv]: 

# Sortie console
Scan de la plage réseau: 192.168.1.0/24
Cela peut prendre quelques minutes...
  Hôte détecté: 192.168.1.10 (dc01.ntl.local)
  Hôte détecté: 192.168.1.20 (wms-db.ntl.local)
  [...]

45 hôte(s) détecté(s).
Analyse des OS et versions...
  [OK] 192.168.1.10 (dc01.ntl.local) - Windows Server 2019
  [WARN] 192.168.1.15 (srv-file) - Windows Server 2012 R2
  [EOL] 192.168.1.30 (srv-backup) - Ubuntu 18.04
  [...]

Résultats exportés vers: scan_results.csv

================================================================================
RÉSUMÉ DU SCAN
================================================================================
Total: 45
Supportés: 28
EOL proche: 5
Support étendu: 4
EOL: 3
Inconnu: 2
```

#### Consulter base EOL

```bash
> 3 (Audit obsolescence)
> 2 (Lister les versions d'un OS et leurs dates EOL)
> Sélectionnez la famille d'OS:
  [1] Windows
  [2] Linux
  [3] macOS
> 1

================================================================================
VERSIONS ET DATES EOL POUR WINDOWS
================================================================================

13 version(s) trouvée(s):

Windows 11
  Date de release: 05/10/2021
  Date EOL (Mainstream): Non définie / Support continu

Windows 10
  Date de release: 29/07/2015
  Date EOL (Mainstream): 14/10/2025
  Date EOL (Extended): 13/10/2026

Windows Server 2022
  Date de release: 18/08/2021
  Date EOL (Mainstream): 13/10/2026
  Date EOL (Extended): 14/10/2031

[...]
```

#### Analyser inventaire CSV

```bash
> 3 (Audit obsolescence)
> 3 (Analyser un fichier CSV)
> Chemin vers le fichier CSV: ./inventaire_ntl.csv
> Sélectionnez le format du rapport:
  [1] TXT (recommandé)
  [2] CSV
  [3] JSON
> Format [1]: 1

Traitement en cours...

================================================================================
TRAITEMENT DU FICHIER CSV
================================================================================
Fichier CSV lu: 45 composant(s)
Analyse des dates EOL...

Rapport généré: ./inventaire_ntl_report.txt

Résumé:
  Total: 45
  Supportés: 28
  EOL proche: 5
  Support étendu: 4
  EOL: 3
  Inconnu: 2
```

### Architecture technique Module 3

**Classes principales** :

1. **NetworkScanner** : Scan réseau et détection d'hôtes
   - `scan_range(ip_range, ports)` → Scan nmap avec détection OS
   - `_get_os_info(ip)` → Extraction OS depuis résultats nmap
   - `_extract_windows_version(name)` → Parsing version Windows avec build number
   - `_extract_linux_version(name)` → Parsing version Linux (Ubuntu/Debian/CentOS/RHEL)

2. **OSDetector** : Détection OS multi-méthodes
   - `detect_os(ip, ports)` → Tentative de détection via méthodes multiples
   - `_detect_via_ssh_banner(ip)` → Extraction depuis bannière SSH
   - `_detect_via_http_header(ip)` → Détection via Server HTTP header
   - `_detect_via_smb(ip)` → Négociation SMB
   - `normalize_os_version(os_family, raw)` → Normalisation version détectée

3. **EOLDatabase** : Base de données EOL intégrée
   - `get_eol_info(os_family, os_version)` → Recherche info EOL
   - `get_status(eol_info)` → Calcul statut (supported/warning/soon_eol/eol)
   - `get_days_until_eol(eol_info)` → Calcul jours restants avant EOL
   - `list_all_versions(os_family)` → Liste toutes versions d'une famille OS

4. **CSVProcessor** : Import/export CSV
   - `read_csv(csv_path)` → Lecture avec détection séparateur
   - `validate_data(df)` → Validation colonnes requises et IPs
   - `process_components(df)` → Conversion DataFrame → Liste composants
   - `export_to_csv(data, output_path)` → Export enrichi

5. **ReportGenerator** : Génération rapports multi-formats
   - `generate_report(components, eol_db, format)` → Génération rapport
   - `_analyze_components(components)` → Calcul statistiques
   - `_generate_text_report()` / `_generate_csv_report()` / `_generate_json_report()`

### Cas d'usage DSI NTL

**Scénario 1 : Audit annuel obligatoire**
```bash
# Audit complet infrastructure NTL (4 sites)
python src/module3_audit.py
> 1 (Scanner une plage réseau)
> Plage IP: 10.5.60.0/24  # Siège Lille
# Répéter pour 20.0/24, 30.0/24, 40.0/24 (autres sites)

# Génération rapport consolidé pour direction
# → Identification: 12 serveurs Windows Server 2012 R2 en EOL
# → Recommandation: Plan de migration vers 2022 Q3 2026
```

**Scénario 2 : Validation post-migration**
```bash
# Avant migration: Export inventaire
python src/module3_audit.py
> 1 (Scanner)
> Plage IP: 10.5.60.0/24
> CSV: o → pre_migration_2026-02.csv

# Après migration: Nouveau scan
> CSV: o → post_migration_2026-03.csv

# Comparaison: Vérifier disparition serveurs EOL
```

**Scénario 3 : Intégration inventaire existant GLPI**
```bash
# Export GLPI → CSV
# Colonnes: ip, hostname, os_family, os_version

# Import dans NTL-SysToolbox
python src/module3_audit.py
> 3 (Analyser un fichier CSV)
> Chemin: ./export_glpi_2026-02.csv
> Format rapport: [1] TXT

# Rapport généré avec statuts EOL enrichis
# → Permet qualification risque sans nouveau scan réseau
```

---

## 📝 Cas d'usage DSI NTL

### Scénario 1: Diagnostic quotidien automatisé

**Contexte**: Vérifier chaque matin que tous les services critiques sont opérationnels avant l'arrivée des équipes (5h30).

```bash
# Script cron (Linux) ou tâche planifiée (Windows)
# Exécuté à 5h00 tous les jours

#!/bin/bash
cd /opt/ntl-systoolbox
source venv/bin/activate

# Diagnostic global
python src/module1_diagnostic.py global --json > /var/log/ntl/diagnostic_$(date +%Y%m%d).json

# Si erreur critique, envoyer email alerting
if [ $? -eq 2 ]; then
    mail -s "ALERTE NTL: Diagnostic critique" admin@ntl.local < /var/log/ntl/diagnostic_$(date +%Y%m%d).json
fi
```

**Résultat attendu** :
- Temps d'exécution: 15-20 secondes
- Log JSON horodaté archivé
- Email uniquement si CRIT (code retour 2)
- Tableau de bord Zabbix ingestion automatique

### Scénario 2: Sauvegarde nocturne WMS

**Contexte**: Sauvegarder la base WMS tous les soirs à 2h00 (fenêtre de maintenance).

```bash
# Tâche planifiée Windows (schtasks)
# Ou cron Linux: 0 2 * * * /opt/ntl-systoolbox/scripts/backup_wms.sh

python src/module2_wms_backup.py

# Rotation: Garder 7 jours
find /opt/ntl-systoolbox/backups/wms/ -name "*.sql" -mtime +7 -delete
find /opt/ntl-systoolbox/backups/wms/ -name "*.csv" -mtime +7 -delete
```

**Résultat attendu** :
- Backup SQL: ~2-5 MB compressé
- Export CSV stock_moves: ~1 MB
- Durée: 10-30 secondes selon taille base
- Hash SHA256 pour intégrité

### Scénario 3: Audit annuel obsolescence réseau

**Contexte**: Audit réglementaire annuel (fin Q1) pour identifier les systèmes non supportés.

```bash
# Scan complet des 4 sites NTL
python src/module3_audit.py
> 1 (Scan réseau)
> Plage: 10.5.60.0/24   # Siège Lille
> CSV: o → audit_lille_2026.csv

# Répéter pour chaque site
# 10.5.20.0/24 (Lens), 10.5.30.0/24 (Valenciennes), 10.5.40.0/24 (Arras)

# Consolidation rapports
python scripts/consolidate_audits.py \
  audit_lille_2026.csv \
  audit_lens_2026.csv \
  audit_valenciennes_2026.csv \
  audit_arras_2026.csv \
  > audit_ntl_complet_2026.txt
```

**Résultat attendu** :
- Identification des systèmes EOL (Windows Server 2012 R2, Ubuntu 18.04)
- Plan de migration priorisé par criticité
- Rapport direction + feuille de route technique

---

## ⚙️ Configuration

### Fichier ntl_config.json

```json
{
  "infrastructure": {
    "dc01_ip": "10.5.60.10",
    "dc02_ip": "10.5.60.11",
    "wms_db_host": "10.5.60.20",
    "wms_db_port": 3306,
    "wms_db_user": "wms_user",
    "wms_db_pass": "",
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

### Variables d'environnement (recommandé pour mots de passe)

```bash
# Linux/Mac
export WMS_DB_PASS="mot_de_passe_sécurisé"
export MYSQL_ROOT_PASS="root_password"

# Windows
set WMS_DB_PASS=mot_de_passe_sécurisé
set MYSQL_ROOT_PASS=root_password
```

---

## 📊 Sorties et codes retour

### Codes de sortie standardisés

| Code | Statut | Signification | Utilisation Zabbix/Nagios |
|------|--------|---------------|---------------------------|
| **0** | OK | Toutes les vérifications réussies | Trigger: Aucun |
| **1** | WARNING | Avertissement non bloquant | Trigger: Warning |
| **2** | CRITICAL | Erreur critique, intervention requise | Trigger: Critical |
| **3** | UNKNOWN | Erreur inattendue, statut indéterminé | Trigger: Unknown |

### Exemple d'intégration Zabbix

```xml
<!-- Item Zabbix -->
<Item>
  <key>ntl.diagnostic.global</key>
  <type>External check</type>
  <command>/opt/ntl-systoolbox/venv/bin/python /opt/ntl-systoolbox/src/module1_diagnostic.py global --json</command>
  <interval>5m</interval>
  <value_type>JSON</value_type>
</Item>

<!-- Trigger Zabbix -->
<Trigger>
  <expression>{ntl-tools:ntl.diagnostic.global.last()}=2</expression>
  <severity>High</severity>
  <description>Diagnostic NTL critique</description>
</Trigger>
```

---

## 🛠️ Développement & Contribution

### Structure de développement

```bash
# Cloner en mode développement
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git
cd ntl-systoolbox

# Créer une branche feature
git checkout -b feature/nouveau-module

# Tests unitaires (si disponibles)
pytest tests/

# Commit avec convention
git commit -m "feat(module3): Ajout détection CentOS Stream"
git push origin feature/nouveau-module
```

### Conventions de code

- **Python** : PEP 8, type hints, docstrings
- **Commits** : Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`)
- **Branches** : `main` (stable), `develop` (intégration), `feature/*`, `fix/*`

---

## 📚 Documentation complète

- **[INSTALL.md](docs/INSTALL.md)** - Procédure installation DSI complète
- **[TECH.md](docs/TECH.md)** - Architecture et choix techniques détaillés
- **[USAGE.md](docs/USAGE.md)** - Guide utilisation avancé de tous les modules
- **[LICENCE.md](LICENCE.md)** - MIT License

---

## 🏢 Contexte NTL

**Nord Transit Logistics** est une PME logistique française opérant 4 sites (Lille siège, Lens, Valenciennes, Arras) avec:
- ~240 employés permanents (jusqu'à 300 en haute saison)
- Horaires critiques: 5h30-18h30 (zéro tolérance downtime)
- Infrastructure centralisée: Active Directory, DNS, WMS MySQL
- Besoins: Diagnostic rapide, sauvegardes automatisées, conformité réglementaire

**NTL-SysToolbox** répond aux enjeux opérationnels quotidiens de la DSI NTL.

---

## 📄 Licence

**MIT License**

Copyright (c) 2026 Nord Transit Logistics - Équipe MSPR ASRBD

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

## 🛠️ Développement & Contribution

### Structure Git

```
main (stable, releases tagged)
  ├── v1 (tag)
  ├── v2 (tag)
  ├── v3 (tag)
  ├── v4 (tag)
  ├── v5 (tag)
  ├── v6 (tag)
  ├── v7 (tag)
  ├── v8 (tag)
  ├── v9 (tag)
  └── v10 (tag)
module-1-diagnostique
  ├── module1_diagnostique.py
  └── requirements.txt
module-2-backups_wms
  ├── module2_wms_backup.py
  └── requirements.txt
module-3-audit
  ├──module3_audit.py
  └── requirements.txt
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

---

## 🎓 Projet académique

Ce projet s'inscrit dans le cadre de la **MSPR (Mise en Situation Professionnelle Reconstituée)** du bloc **E6.1 - Concevoir et tester des solutions applicatives** du programme **Administrateur Systèmes, Réseaux et Bases de Données (ASRBD)** à l'**EPSI**.

**Version** : 1.0.0   
**Année universitaire** : 2026-02-23   
**Équipe** : MSPR-B3-GROUPE 1  
**Client**: Nord Transit Logistics (NTL)  
**Licence**: MIT License 
**Contact**: Administrateur Systèmes & Réseaux
**Durée** : 19 heures de préparation + soutenance orale (50 min) 
**Repository** : https://github.com/Not-mat-collab/ntl-systoolbox

---

<div align="center">

**NTL-SysToolbox** - Fiabilité, Traçabilité, Anticipation

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![EPSI](https://img.shields.io/badge/Projet-EPSI%20MSPR-orange)](https://www.epsi.fr/)

Made in Nathan / Mathis / Maxime
</div>