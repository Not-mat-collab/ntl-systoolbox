# NTL-SysToolbox - Guide d'Utilisation

## Introduction

**NTL-SysToolbox** est un outil en ligne de commande (CLI) conçu pour automatiser les tâches d'exploitation IT de Nord Transit Logistics. Ce guide détaille l'installation, la configuration et l'utilisation de chaque module.

---

## Prérequis

### Environnement requis

| Composant | Version minimale | Recommandé |
|-----------|------------------|------------|
| **Python** | 3.8 | 3.10+ |
| **Système d'exploitation** | Windows 10 / Ubuntu 20.04 | Windows 11 / Ubuntu 22.04 |
| **RAM** | 512 MB | 2 GB |
| **Espace disque** | 100 MB + backups | 10 GB |

### Dépendances Python

Toutes les dépendances sont listées dans `requirements.txt`:
- `psutil` - Monitoring système local
- `pymysql` - Connexion MySQL/MariaDB
- `paramiko` - Client SSH pour Linux distant
- `pypsrp` - Client WinRM pour Windows distant

---

## Installation

### Étape 1: Cloner le dépôt

```bash
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git
cd ntl-systoolbox
```

### Étape 2: Créer un environnement virtuel

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

### Étape 3: Installer les dépendances

```bash
pip install -r requirements.txt
```

### Étape 4: Vérifier l'installation

```bash
python src/main.py
```

Vous devriez voir le menu principal s'afficher.

---

## Configuration

### Fichier de configuration

Le fichier `src/ntl_config.json` centralise toutes les configurations.

**Structure par défaut:**
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

### Configuration initiale

**Option 1: Via le menu**
```bash
python src/main.py
# Choisir [C] Configuration JSON
# Suivre les invites interactives
```

**Option 2: Édition manuelle**
```bash
nano src/ntl_config.json  # Linux/Mac
notepad src\ntl_config.json  # Windows
```

### Sécurité des mots de passe

⚠️ **Ne jamais commiter de mots de passe dans Git!**

**Méthode recommandée: Variables d'environnement**

**Linux/Mac:**
```bash
export WMS_DB_PASS="votre_mot_de_passe"
export MYSQL_ROOT_PASS="root_password"
```

**Windows:**
```cmd
set WMS_DB_PASS=votre_mot_de_passe
set MYSQL_ROOT_PASS=root_password
```

**Permissions restrictives:**
```bash
chmod 600 src/ntl_config.json  # Linux/Mac
```

---

## Utilisation

### Lancement du menu principal

```bash
python src/main.py
```

**Menu affiché:**
```
======================================================================
 NTL-SysToolbox v2.9.0
 Config: 10.5.60.20
======================================================================

MENU PRINCIPAL
----------------------------------------------------------------------
 [1] Module 1 - Diagnostic (menu autonome)
 [2] Module 2 - Sauvegarde WMS
 [3] Module 3 - Audit (À venir)
 [C] Configuration JSON
 [0] Quitter
----------------------------------------------------------------------
Choix:
```

---

## Module 1 - Diagnostic

### Vue d'ensemble

Le Module 1 permet de vérifier l'état de santé des infrastructures critiques:
- **Active Directory / DNS** (contrôleurs de domaine)
- **Base MySQL** (WMS)
- **Serveurs Windows** (local ou distant)
- **Serveurs Ubuntu/Linux** (local ou distant)
- **Diagnostic global** (tous les services NTL)

### Menu Module 1

**Accès:**
```bash
# Via main.py
python src/main.py
# Choisir [1] Module 1 - Diagnostic

# Ou directement
python src/module1_diagnostic.py --menu
```

**Menu affiché:**
```
======================================================================
 NTL-SysToolbox - MODULE 1 DIAGNOSTIC
======================================================================

MODULE 1 - DIAGNOSTIC SYSTÈME
----------------------------------------------------------------------
 [1] AD/DNS DC01 (10.5.60.10)
 [2] AD/DNS DC02 (10.5.60.11)
 [3] MySQL WMS (10.5.60.20:3306)
 [4] Diagnostic Windows (local ou distant)
 [5] Diagnostic Ubuntu/Linux (local ou distant)
 [6] Diagnostic global NTL
 [S] Sauvegarder dernier résultat
 [0] Quitter
----------------------------------------------------------------------
Choix:
```

### Vérification AD/DNS

**Objectif**: Vérifier que les contrôleurs de domaine sont opérationnels.

**Utilisation interactive:**
1. Choisir `[1]` pour DC01 ou `[2]` pour DC02
2. Le test vérifie automatiquement:
   - Port 53 (DNS)
   - Port 389 (LDAP)
   - Port 88 (Kerberos)

**Utilisation en ligne de commande:**
```bash
python src/module1_diagnostic.py ad-dns 10.5.60.10
```

**Sortie JSON:**
```bash
python src/module1_diagnostic.py ad-dns 10.5.60.10 --json
```

**Exemple de résultat:**
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

### Vérification MySQL

**Objectif**: Tester la connectivité et l'état de la base WMS.

**Utilisation interactive:**
1. Choisir `[3]` MySQL WMS
2. Saisir le mot de passe (ou Entrée si configuré)

**Utilisation en ligne de commande:**
```bash
python src/module1_diagnostic.py mysql \
  --host 10.5.60.20 \
  --port 3306 \
  --user wms_user \
  --password "mot_de_passe"
```

**Métriques récupérées:**
- Version MySQL/MariaDB
- Uptime (durée depuis démarrage)
- Connexions actives
- Total de requêtes exécutées

**Exemple de résultat:**
```
[1] MySQL_Database - Statut: OK
----------------------------------------------------------------------
  Hôte: 10.5.60.20:3306
  Version: 10.5.23-MariaDB
  Uptime: 15j 8h 42min
  Connexions actives: 12
  Requêtes totales: 1234567
```

### Diagnostic Windows Server

**Objectif**: Récupérer les métriques système d'un serveur Windows.

#### Mode local (exécuté sur le serveur Windows cible)

**Utilisation interactive:**
1. Choisir `[4]` Diagnostic Windows
2. Appuyer sur Entrée (IP vide = local)

**Utilisation CLI:**
```bash
python src/module1_diagnostic.py windows
```

#### Mode distant (depuis poste d'administration)

**Prérequis serveur distant:**
- WinRM activé
- Port 5985 (HTTP) ou 5986 (HTTPS) ouvert
- Compte administrateur autorisé

**Activer WinRM sur le serveur cible:**
```powershell
# Sur le serveur Windows distant
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM
```

**Utilisation interactive:**
1. Choisir `[4]` Diagnostic Windows
2. Saisir l'IP distante: `10.5.60.10`
3. Saisir le nom d'utilisateur: `administrateur`
4. Saisir le mot de passe

**Utilisation CLI:**
```bash
python src/module1_diagnostic.py windows \
  --ip 10.5.60.10 \
  --user administrateur \
  --password "mot_de_passe"
```

**Métriques récupérées:**
- Version OS et build
- Uptime système
- CPU: Nom, cœurs physiques/logiques, utilisation %
- RAM: Total, utilisé, disponible, utilisation %
- Disques: Lettre, label, capacité, utilisation %

**Exemple de résultat:**
```
[1] Windows_Server - Statut: OK
----------------------------------------------------------------------
  Hostname: WIN-SERVER-01
  Mode: 🌐 Distant
  OS: Microsoft Windows Server 2019 Standard
  Uptime: 42j 15h 23min
  CPU: Intel(R) Xeon(R) CPU E5-2630 v3 (8 cœurs)
  RAM: 28.5 GB / 64.0 GB (44.5%)
  Disques:
    C:\ [System] (E:\): 450.2 GB / 1000.0 GB (45.0%)
    D:\ [Data] (D:\): 1234.5 GB / 2000.0 GB (61.7%)
```

### Diagnostic Ubuntu/Linux Server

**Objectif**: Récupérer les métriques système d'un serveur Linux.

#### Mode local (exécuté sur le serveur Linux cible)

**Utilisation interactive:**
1. Choisir `[5]` Diagnostic Ubuntu/Linux
2. Appuyer sur Entrée (IP vide = local)

**Utilisation CLI:**
```bash
python src/module1_diagnostic.py ubuntu
```

#### Mode distant (SSH)

**Prérequis serveur distant:**
- Service SSH actif (`sudo systemctl status ssh`)
- Port 22 ouvert
- Compte avec permissions sudo

**Utilisation interactive:**
1. Choisir `[5]` Diagnostic Ubuntu/Linux
2. Saisir l'IP distante: `10.5.60.20`
3. Saisir le nom d'utilisateur: `administrateur`
4. Saisir le mot de passe SSH

**Utilisation CLI:**
```bash
python src/module1_diagnostic.py ubuntu \
  --ip 10.5.60.20 \
  --user administrateur \
  --password "mot_de_passe"
```

**Métriques récupérées:**
- Distribution Linux (Ubuntu, Debian, etc.)
- Version kernel
- Uptime système
- CPU: Nombre de cœurs, utilisation %
- RAM: Total, utilisé, disponible, utilisation %
- Disques: Device, point de montage, capacité, utilisation %

**Exemple de résultat:**
```
[1] Ubuntu_Server - Statut: OK
----------------------------------------------------------------------
  Hostname: ubuntu-wms-db
  Mode: 🌐 Distant
  Distribution: Ubuntu 22.04.3 LTS
  OS: Linux 5.15.0-91-generic
  Uptime: 28j 4h 12min
  CPU: 6.2% utilisé (4 cœurs)
  RAM: 2.8 GB / 8.0 GB (35.0%)
  Disques:
    /dev/sda1 (/): 45.2 GB / 100.0 GB (45%)
    /dev/sdb1 (/data): 234.5 GB / 500.0 GB (47%)
```

### Diagnostic global NTL

**Objectif**: Exécuter tous les diagnostics en une seule commande.

**Utilisation:**
1. Choisir `[6]` Diagnostic global NTL
2. Confirmer l'exécution

**Tests effectués:**
- AD/DNS DC01
- AD/DNS DC02
- MySQL WMS
- Serveur local (Windows ou Linux selon l'OS d'exécution)

**Durée estimée:** 15-20 secondes

### Sauvegarde des résultats

**Objectif**: Conserver un historique des diagnostics.

**Utilisation:**
1. Effectuer un diagnostic (options 1 à 6)
2. Choisir `[S]` Sauvegarder dernier résultat

**Arborescence générée:**
```
backups/
├── ad_dns/
│   ├── ad_dns_20260217_183000.json
│   └── ad_dns_20260217_183000.txt
├── mysql/
│   ├── mysql_20260217_183500.json
│   └── mysql_20260217_183500.txt
├── windows/
│   ├── windows_20260217_184000.json
│   └── windows_20260217_184000.txt
├── ubuntu/
│   ├── ubuntu_20260217_184500.json
│   └── ubuntu_20260217_184500.txt
└── global/
    ├── global_20260217_185000.json
    └── global_20260217_185000.txt
```

**Formats:**
- **JSON** (`.json`): Machine-readable, ingestion Zabbix/ELK
- **TXT** (`.txt`): Human-readable, consultation directe

---

## Module 2 - Sauvegarde WMS

### Vue d'ensemble

Le Module 2 effectue deux types de sauvegardes de la base WMS:
1. **Dump SQL complet** (structure + données)
2. **Export CSV** de la table `stock_moves` (mouvements de stock)

### Utilisation

**Via main.py:**
```bash
python src/main.py
# Choisir [2] Module 2 - Sauvegarde WMS
```

**Directement:**
```bash
python src/module2_wms_backup.py
```

### Workflow interactif

1. **Prompt mot de passe:**
   ```
   MariaDB password for wms_user@10.5.60.20:
   ```
   
2. **Exécution:**
   - Connexion à la base
   - Dump SQL (toutes les tables)
   - Export CSV (JOIN `stock_moves` + `products` + `locations`)

3. **Résultat affiché:**
   ```
   === BACKUP WMS ===
   Status : OK
   Message : SQL dump and CSV export completed.
   Code : 0
   ```

### Artefacts générés

**Emplacement:** `backups/wms/`

**Fichiers créés:**
```
backups/wms/
├── wms_dump_2026-02-17_18-30-00_UTC.sql
└── stock_moves_2026-02-17_18-30-00_UTC.csv
```

### Structure du dump SQL

**Contenu du fichier `.sql`:**
```sql
CREATE DATABASE IF NOT EXISTS `wms`;
USE `wms`;

DROP TABLE IF EXISTS `products`;
CREATE TABLE `products` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `sku` VARCHAR(100),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `products` (`id`,`name`,`sku`) VALUES (1,'Produit A','SKU-001');
INSERT INTO `products` (`id`,`name`,`sku`) VALUES (2,'Produit B','SKU-002');
...
```

**Restauration:**
```bash
mysql -u root -p wms < backups/wms/wms_dump_2026-02-17_18-30-00_UTC.sql
```

### Structure du CSV

**Colonnes exportées:**
```csv
move_id,product_name,from_location,to_location,quantity,move_type,moved_at
1234,Produit A,Entrepôt WH1,Quai Expédition,50,outbound,2026-02-15 14:23:00
1235,Produit B,Zone Picking,Entrepôt WH1,20,inbound,2026-02-15 15:12:00
```

**Usage:**
- Import dans Excel/Power BI
- Analyse Python/pandas
- Ingestion dans data warehouse

### Métadonnées JSON

**Chaque sauvegarde produit un JSON détaillé:**
```json
{
  "schema_version": "1.0",
  "module": "module2_wms_backup",
  "timestamp_utc": "2026-02-17T18:30:00Z",
  "execution": {
    "host": "admin-laptop",
    "user": "admin",
    "duration_ms": 1342
  },
  "target": {
    "db_name": "wms",
    "db_host": "10.5.60.20",
    "db_port": 3306,
    "db_user": "wms_user"
  },
  "artifacts": {
    "sql_dump": {
      "status": "OK",
      "file": "wms_dump_2026-02-17_18-30-00_UTC.sql",
      "size_bytes": 2456789,
      "sha256": "7a3f9e2c8b1d4f6a9e3c5d7b2f8a4e1c6d9b3f7a2e5c8d1b4f6a9e3c5d7b"
    },
    "csv_export": {
      "status": "OK",
      "table": "stock_moves",
      "file": "stock_moves_2026-02-17_18-30-00_UTC.csv",
      "rows_exported": 12453,
      "size_bytes": 987654,
      "sha256": "b4e6c1a5f3d7b2a8e1c4f6d9b3a5e7c2f8d1a4b6c9e3f5a7d2b8e1c4f6"
    }
  },
  "summary": {
    "overall_status": "OK",
    "message": "SQL dump and CSV export completed.",
    "warnings": []
  },
  "exit_code": 0
}
```

### Vérification d'intégrité

**Checksum SHA256:**
```bash
# Linux/Mac
sha256sum backups/wms/wms_dump_2026-02-17_18-30-00_UTC.sql

# Windows PowerShell
Get-FileHash backups\wms\wms_dump_2026-02-17_18-30-00_UTC.sql -Algorithm SHA256
```

**Comparer avec le JSON:**
```bash
cat backups/wms/wms_dump_2026-02-17_18-30-00_UTC.json | jq '.artifacts.sql_dump.sha256'
```

### Codes de sortie

| Code | Statut | Signification |
|------|--------|---------------|
| `0` | OK | Sauvegarde complète réussie |
| `1` | WARNING | Sauvegarde partielle (ex: table vide) |
| `2` | CRITICAL | Échec total (connexion impossible) |
| `3` | UNKNOWN | Erreur inattendue |

**Utilisation en script:**
```bash
python src/module2_wms_backup.py
if [ $? -eq 0 ]; then
    echo "Sauvegarde réussie"
else
    echo "Échec sauvegarde - Code: $?"
fi
```

---

## Module 3 - Audit d'obsolescence réseau

### Vue d'ensemble

Le Module 3 permet de :
- **Scanner une plage réseau** (CIDR ou range) pour détecter les hôtes actifs
- **Identifier les systèmes d'exploitation** (Windows, Linux, macOS) avec versions précises
- **Qualifier le statut EOL** (End of Life) de chaque système détecté
- **Générer des rapports** multi-formats (TXT, CSV, JSON)
- **Import/Export CSV** pour enrichir un inventaire existant

### Prérequis spécifiques

⚠️ **CRITIQUE** : Le binaire `nmap` doit être installé sur le système.

```bash
# Vérification nmap
nmap --version  # Attendu: Nmap version 7.80+

# Installation si nécessaire (voir INSTALL.md section 7)
# Linux: sudo apt install nmap
# Windows: winget install Insecure.Nmap
```

⚠️ **Privilèges élevés requis** :
- **Linux** : Exécuter avec `sudo` ou configurer capabilities nmap
- **Windows** : Exécuter PowerShell en Administrateur

### Menu Module 3

**Accès :**

```bash
# Via main.py
python src/main.py
# Choisir [3] Module 3 - Audit obsolescence réseau

# Ou directement
python src/module3_audit.py
```

**Menu affiché :**

```
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

---

### Fonction 1 : Scanner une plage réseau

**Objectif** : Découvrir les hôtes actifs, identifier leurs OS et qualifier leur statut EOL.

#### Utilisation interactive

**Étape 1 : Choisir l'option 1**

```
Votre choix [1-4]: 1

================================================================================
SCAN RÉSEAU
================================================================================
```

**Étape 2 : Saisir la plage IP**

```
Entrez la plage réseau à scanner (CIDR ou range) :
  Exemples : 192.168.1.0/24
             10.5.60.0/24
             192.168.1.1-192.168.1.50
> 10.5.60.0/24
```

**Formats supportés :**
- **CIDR** : `192.168.1.0/24` (256 adresses)
- **Range** : `192.168.1.1-192.168.1.100` (100 adresses)
- **IP unique** : `192.168.1.50`

**Étape 3 : Scan en cours**

```
Scan de la plage réseau: 10.5.60.0/24
Cela peut prendre quelques minutes...
  Hôte détecté: 10.5.60.10 (dc01.ntl.local)
  Hôte détecté: 10.5.60.11 (dc02.ntl.local)
  Hôte détecté: 10.5.60.20 (wms-db.ntl.local)
  Hôte détecté: 10.5.60.21 (wms-app.ntl.local)
  Hôte détecté: 10.5.60.30 (srv-file.ntl.local)
  [...]

45 hôte(s) détecté(s).
```

**Étape 4 : Analyse OS et EOL**

```
Analyse des OS et versions...
  [OK] 10.5.60.10 (dc01.ntl.local) - Windows Server 2019
  [WARN] 10.5.60.11 (dc02.ntl.local) - Windows Server 2016
  [EOL] 10.5.60.30 (srv-file.ntl.local) - Windows Server 2012 R2
  [OK] 10.5.60.20 (wms-db.ntl.local) - Ubuntu 22.04
  [WARN] 10.5.60.21 (wms-app.ntl.local) - Ubuntu 20.04
  [...]

Analyse terminée.
```

**Étape 5 : Export CSV (optionnel)**

```
Souhaitez-vous exporter les résultats en CSV ? (o/n) [n]: o
Nom du fichier CSV [scan_results.csv]: audit_ntl_2026-02-23.csv

Résultats exportés vers: backups/audit/audit_ntl_2026-02-23.csv
```

**Étape 6 : Affichage du rapport**

```
================================================================================
RÉSUMÉ DU SCAN
================================================================================
Total de composants analysés: 45
  ✅ Supportés (> 12 mois avant EOL): 28
  ⚠️  EOL dans moins d'un an: 3
  🔴 EOL proche (< 3 mois): 5
  🔵 Support étendu uniquement: 4
  ⛔ EOL (non supporté): 3
  ❓ Inconnu (non référencé): 2

Répartition par OS:
  Windows: 25 (12 supportés, 2 EOL, 1 EOL proche)
  Linux: 18 (15 supportés, 1 EOL, 2 EOL proche)
  macOS: 2 (1 supporté, 1 EOL)

COMPOSANTS CRITIQUES (action requise):
  10.5.60.30 (srv-file) - Windows Server 2012 R2 - EOL depuis 10/10/2023
  10.5.60.45 (old-app) - Ubuntu 18.04 - EOL depuis 26/04/2023
  [...]

Appuyez sur Entrée pour générer un rapport détaillé...
```

**Étape 7 : Choix du format de rapport**

```
================================================================================
GÉNÉRATION DE RAPPORT DÉTAILLÉ
================================================================================

Sélectionnez le format du rapport:
  [1] TXT (recommandé pour lecture)
  [2] CSV (pour Excel/analyse)
  [3] JSON (pour intégration système)

Format [1]: 1
```

**Étape 8 : Rapport généré**

```
Rapport TXT généré: backups/audit/audit_report_2026-02-23.txt

Le rapport contient:
- Statistiques globales
- Liste des composants critiques (EOL/soon_eol)
- Détail de tous les composants scannés

Appuyez sur Entrée pour revenir au menu...
```

#### Sortie Console complète

```
================================================================================
RAPPORT D'AUDIT D'OBSOLESCENCE
================================================================================
Date de génération: 23/02/2026 10:15:23
Auteur: Module 3 - NTL-SysToolbox v1.0.0

STATISTIQUES GLOBALES
--------------------------------------------------------------------------------
Total de composants analysés: 45
  ✅ Supportés (> 12 mois avant EOL): 28
  ⚠️  EOL dans moins d'un an: 3
  🔴 EOL proche (< 3 mois): 5
  🔵 Support étendu uniquement: 4
  ⛔ EOL (non supporté): 3
  ❓ Inconnu (non référencé): 2

Répartition par OS:
  Windows: 25 composants
    - Supportés: 12
    - Warning (< 1 an): 2
    - EOL proche (< 3 mois): 1
    - Support étendu: 4
    - EOL: 2
    - Inconnu: 4
  Linux: 18 composants
    - Supportés: 15
    - Warning: 1
    - EOL proche: 2
    - EOL: 0
  macOS: 2 composants
    - Supportés: 1
    - EOL: 1

COMPOSANTS NÉCESSITANT UNE ATTENTION IMMÉDIATE
--------------------------------------------------------------------------------

Priorité CRITIQUE (EOL dépassé) :
  10.5.60.30 (srv-file.ntl.local) - Windows Server 2012 R2
    Statut: EOL (non supporté)
    Date EOL Mainstream: 10/10/2018
    Date EOL Extended: 10/10/2023
    Action: Migration urgente requise vers Windows Server 2019/2022

  10.5.60.45 (old-app.ntl.local) - Ubuntu 18.04
    Statut: EOL (non supporté)
    Date EOL: 26/04/2023
    Action: Migration vers Ubuntu 22.04 LTS ou 24.04 LTS

Priorité HAUTE (EOL < 3 mois) :
  10.5.60.25 (workstation-01) - Windows 10 Pro
    Statut: EOL proche (62 jours restants)
    Date EOL: 14/10/2025
    Date EOL Extended: 13/10/2026
    Action: Planifier migration vers Windows 11

  10.5.60.50 (test-server) - Ubuntu 20.04
    Statut: EOL proche (75 jours restants)
    Date EOL: 08/05/2025
    Action: Planifier migration vers Ubuntu 22.04 LTS

DÉTAIL DES COMPOSANTS
--------------------------------------------------------------------------------
IP           | Hostname        | OS Family | Version           | Statut       | EOL Date   | Jours
-------------|-----------------|-----------|-------------------|--------------|------------|---------
10.5.60.10   | dc01            | Windows   | Server 2019       | Support éten | 09/01/2024 | N/A
10.5.60.11   | dc02            | Windows   | Server 2016       | Support éten | 11/01/2022 | N/A
10.5.60.20   | wms-db          | Linux     | Ubuntu 22.04      | Supporté     | 21/04/2027 | 789
10.5.60.21   | wms-app         | Linux     | Ubuntu 20.04      | Warning      | 08/05/2025 | 439
10.5.60.30   | srv-file        | Windows   | Server 2012 R2    | EOL          | 10/10/2023 | N/A
[...]

================================================================================
FIN DU RAPPORT
================================================================================
```

#### Durée typique de scan

| Plage réseau | Hôtes actifs | Durée estimation |
|--------------|--------------|------------------|
| /29 (8 IPs) | 3-5 hôtes | 30-60 secondes |
| /28 (16 IPs) | 5-10 hôtes | 1-2 minutes |
| /27 (32 IPs) | 10-20 hôtes | 2-4 minutes |
| /24 (254 IPs) | 20-50 hôtes | 5-10 minutes |
| /24 (254 IPs) | 100+ hôtes | 15-30 minutes |

---

### Fonction 2 : Lister les versions d'un OS et leurs dates EOL

**Objectif** : Consulter la base de données EOL intégrée pour planifier les migrations.

#### Utilisation interactive

**Étape 1 : Choisir l'option 2**

```
Votre choix [1-4]: 2

================================================================================
CONSULTER LA BASE DE DONNÉES EOL
================================================================================
```

**Étape 2 : Sélectionner la famille d'OS**

```
Sélectionnez la famille d'OS:
  [1] Windows
  [2] Linux
  [3] macOS

Votre choix [1-3]: 1
```

**Étape 3 : Affichage des versions**

```
================================================================================
VERSIONS ET DATES EOL POUR WINDOWS
================================================================================

13 version(s) trouvée(s):

Windows 11
  Date de release: 05/10/2021
  Date EOL (Mainstream): Non définie / Support continu
  Date EOL (Extended): Non définie
  Statut: Supporté

Windows 10
  Date de release: 29/07/2015
  Date EOL (Mainstream): 14/10/2025 (589 jours restants)
  Date EOL (Extended): 13/10/2026 (954 jours restants)
  Statut: EOL proche (mainstream) / Support actif (extended)

Windows Server 2022
  Date de release: 18/08/2021
  Date EOL (Mainstream): 13/10/2026 (964 jours restants)
  Date EOL (Extended): 14/10/2031 (2790 jours restants)
  Statut: Supporté

Windows Server 2019
  Date de release: 02/10/2018
  Date EOL (Mainstream): 09/01/2024 (Dépassé)
  Date EOL (Extended): 09/01/2029 (1051 jours restants)
  Statut: Support étendu uniquement

Windows Server 2016
  Date de release: 12/10/2016
  Date EOL (Mainstream): 11/01/2022 (Dépassé)
  Date EOL (Extended): 12/01/2027 (721 jours restants)
  Statut: Support étendu uniquement

Windows Server 2012 R2
  Date de release: 18/10/2013
  Date EOL (Mainstream): 09/10/2018 (Dépassé)
  Date EOL (Extended): 10/10/2023 (Dépassé)
  Statut: EOL (non supporté)

Windows Server 2012
  Date de release: 04/09/2012
  Date EOL (Mainstream): 09/10/2018 (Dépassé)
  Date EOL (Extended): 10/10/2023 (Dépassé)
  Statut: EOL (non supporté)

Windows Server 2008 R2
  Date de release: 22/10/2009
  Date EOL (Mainstream): 13/01/2015 (Dépassé)
  Date EOL (Extended): 14/01/2020 (Dépassé)
  Statut: EOL (non supporté)

[...]

Appuyez sur Entrée pour revenir au menu...
```

#### Exemple avec Linux

```
Votre choix [1-3]: 2

================================================================================
VERSIONS ET DATES EOL POUR LINUX
================================================================================

14 version(s) trouvée(s):

Ubuntu 24.04 LTS
  Date de release: 25/04/2024
  Date EOL: 25/04/2029 (1887 jours restants)
  Statut: Supporté

Ubuntu 22.04 LTS
  Date de release: 21/04/2022
  Date EOL: 21/04/2027 (789 jours restants)
  Statut: Supporté

Ubuntu 20.04 LTS
  Date de release: 23/04/2020
  Date EOL: 08/05/2025 (439 jours restants)
  Statut: Warning (< 1 an)

Ubuntu 18.04 LTS
  Date de release: 26/04/2018
  Date EOL: 26/04/2023 (Dépassé)
  Date EOL (Extended Security Maintenance): 26/04/2028
  Statut: EOL Mainstream / ESM disponible

Debian 12 (Bookworm)
  Date de release: 10/06/2023
  Date EOL: 10/06/2028 (1569 jours restants)
  Statut: Supporté

Debian 11 (Bullseye)
  Date de release: 14/08/2021
  Date EOL: 14/08/2026 (539 jours restants)
  Statut: Supporté

Debian 10 (Buster)
  Date de release: 06/07/2019
  Date EOL: 30/06/2024 (Dépassé)
  Date EOL (Extended LTS): 30/06/2029
  Statut: Support étendu uniquement

CentOS 9 Stream
  Date de release: 01/12/2021
  Date EOL: 31/05/2027 (828 jours restants)
  Statut: Supporté

CentOS 8 Stream
  Date de release: 01/09/2019
  Date EOL: 31/05/2024 (Dépassé)
  Statut: EOL (non supporté)

[...]
```

#### Cas d'usage

- **Planification de migrations** : Identifier les versions approchant EOL
- **Validation de standards** : Vérifier que les OS déployés sont supportés
- **Budget prévisionnel** : Estimer le nombre de migrations à budgéter

---

### Fonction 3 : Analyser un fichier CSV

**Objectif** : Enrichir un inventaire existant (export GLPI, Excel, etc.) avec les dates EOL.

#### Format CSV d'entrée

**Colonnes requises minimales :**
```csv
ip,hostname,os_family,os_version
192.168.1.10,dc01,Windows,Windows Server 2019
192.168.1.20,wms-db,Linux,Ubuntu 22.04
192.168.1.30,srv-file,Windows,Windows Server 2012 R2
```

**Colonnes optionnelles (conservées dans l'export) :**
- `location`, `department`, `owner`, `serial_number`, `purchase_date`, etc.

**Séparateurs supportés :**
- Virgule (`,`) - Standard
- Point-virgule (`;`) - Excel France
- Tabulation (`\t`) - TSV

#### Utilisation interactive

**Étape 1 : Choisir l'option 3**

```
Votre choix [1-4]: 3

================================================================================
ANALYSER UN FICHIER CSV
================================================================================
```

**Étape 2 : Saisir le chemin du fichier**

```
Entrez le chemin vers le fichier CSV à analyser:
  Exemple: ./inventaire_ntl.csv
           C:\Users\admin\Downloads\export_glpi.csv
           /home/admin/inventaire_2026.csv

Chemin du fichier: ./inventaire_ntl_2026-02.csv
```

**Étape 3 : Validation et lecture**

```
Lecture du fichier CSV...
Fichier lu: 45 composant(s) détectés
Validation des données...
  ✅ Toutes les colonnes requises présentes (ip, os_family, os_version)
  ✅ Toutes les IPs sont valides
  ✅ Fichier valide

Analyse des dates EOL en cours...
```

**Étape 4 : Choix du format de rapport**

```
================================================================================
GÉNÉRATION DE RAPPORT
================================================================================

Sélectionnez le format du rapport:
  [1] TXT (recommandé pour lecture humaine)
  [2] CSV (enrichi avec colonnes EOL, pour Excel)
  [3] JSON (pour intégration système)

Format [1]: 2
```

**Étape 5 : Rapport généré**

```
Traitement en cours...

Rapport CSV généré: ./inventaire_ntl_2026-02_enriched.csv

Le fichier CSV enrichi contient les colonnes suivantes:
- Colonnes originales préservées
- Statut EOL
- Date EOL Mainstream
- Date EOL Extended
- Jours restants avant EOL
- Recommandations

Résumé:
  Total: 45 composants
  Supportés: 28
  Warning (< 1 an): 3
  EOL proche (< 3 mois): 5
  Support étendu: 4
  EOL: 3
  Inconnu: 2

Appuyez sur Entrée pour revenir au menu...
```

#### CSV enrichi - Exemple de sortie

**Fichier d'entrée (`inventaire_ntl.csv`) :**
```csv
ip,hostname,os_family,os_version,location,department
192.168.1.10,dc01,Windows,Windows Server 2019,Lille,IT
192.168.1.20,wms-db,Linux,Ubuntu 22.04,Lille,Logistique
192.168.1.30,srv-file,Windows,Windows Server 2012 R2,Lens,Administration
```

**Fichier de sortie (`inventaire_ntl_enriched.csv`) :**
```csv
ip,hostname,os_family,os_version,location,department,statut_eol,date_eol_mainstream,date_eol_extended,jours_restants_mainstream,jours_restants_extended,recommandation
192.168.1.10,dc01,Windows,Windows Server 2019,Lille,IT,Support étendu uniquement,2024-01-09,2029-01-09,Dépassé,1051,Planifier migration vers 2022 à moyen terme
192.168.1.20,wms-db,Linux,Ubuntu 22.04,Lille,Logistique,Supporté,2027-04-21,,789,,Support actif - RAS
192.168.1.30,srv-file,Windows,Windows Server 2012 R2,Lens,Administration,EOL (non supporté),2018-10-09,2023-10-10,Dépassé,Dépassé,CRITIQUE - Migration urgente requise
```

#### Cas d'usage

**Scénario 1 : Audit annuel avec export GLPI**

1. Exporter l'inventaire GLPI au format CSV
2. Importer dans NTL-SysToolbox Module 3
3. Générer rapport enrichi avec dates EOL
4. Présentation au management pour budget migrations

**Scénario 2 : Validation post-migration**

1. Export inventaire **avant** migration (CSV1)
2. Migration de 10 serveurs
3. Export inventaire **après** migration (CSV2)
4. Comparaison des deux rapports enrichis pour valider disparition des EOL

**Scénario 3 : Suivi trimestriel**

1. Export CSV tous les 3 mois
2. Analyse évolution du statut EOL
3. Tracking des composants approchant EOL (warning → soon_eol → eol)

---

### Formats de rapports

#### 1. Rapport TXT (Human-readable)

**Structure :**
```
================================================================================
RAPPORT D'AUDIT D'OBSOLESCENCE
================================================================================
[Header avec date, auteur]

STATISTIQUES GLOBALES
[Compteurs par statut, répartition par OS]

COMPOSANTS NÉCESSITANT UNE ATTENTION IMMÉDIATE
[Liste priorisée: CRITIQUE → HAUTE]

DÉTAIL DES COMPOSANTS
[Tableau complet de tous les composants]
```

**Usage :** Lecture directe, présentation management, archivage documentation

#### 2. Rapport CSV (Excel-compatible)

**Colonnes :**
```csv
IP,Hostname,Famille OS,Version OS,Statut,Date EOL,Date EOL Extended,Jours restants,Ports ouverts,MAC,Vendor
```

**Usage :** Import Excel/Power BI, pivot tables, graphiques, analyses croisées

#### 3. Rapport JSON (Machine-readable)

**Structure :**
```json
{
  "generation_date": "ISO 8601",
  "generator": "NTL-SysToolbox Module 3",
  "statistics": {
    "total": 45,
    "supported": 28,
    "warning": 3,
    "soon_eol": 5,
    "extended_support": 4,
    "eol": 3,
    "unknown": 2,
    "by_os_family": {...},
    "critical": [...]
  },
  "components": [
    {
      "ip": "...",
      "hostname": "...",
      "os_info": {...},
      "eol_info": {...}
    }
  ]
}
```

**Usage :** Intégration CMDB, ingestion ELK/Splunk, automatisation, APIs

---

### Codes de sortie (exit codes)

| Code | Statut | Signification |
|------|--------|---------------|
| **0** | OK | Scan et rapport générés avec succès |
| **1** | WARNING | Scan partiel (timeout réseau, hôtes injoignables) |
| **2** | CRITICAL | Échec scan (nmap absent, permissions insuffisantes) |
| **3** | UNKNOWN | Erreur inattendue |

**Utilisation en scripts :**

```bash
#!/bin/bash
python src/module3_audit.py --scan 10.5.60.0/24 --output csv
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Scan réussi"
elif [ $EXIT_CODE -eq 1 ]; then
    echo "⚠️  Scan partiel - Vérifier logs"
elif [ $EXIT_CODE -eq 2 ]; then
    echo "🔴 Échec scan - Vérifier nmap et permissions"
    mail -s "AUDIT FAILED" admin@ntl.local < scan.log
fi
```

---

### Bonnes pratiques

#### 1. Planification des scans

**Fréquence recommandée :**
- **Audit complet** : Trimestriel (Q1, Q2, Q3, Q4)
- **Scans ciblés** : Mensuel (nouveaux équipements)
- **Scan express** : Hebdomadaire (serveurs critiques uniquement)

**Fenêtres de scan :**
- **Heures creuses** : 22h00-06h00 (impact réseau minimal)
- **Weekends** : Samedi/Dimanche matin
- **Hors production** : Éviter 08h00-18h00 jours ouvrés

#### 2. Gestion des privilèges

**Linux - Capabilities (RECOMMANDÉ) :**
```bash
# Configuration une seule fois
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Ensuite, utilisation sans sudo
python src/module3_audit.py
```

**Linux - Sudoers (POUR AUTOMATISATION) :**
```bash
# Éditer sudoers
sudo visudo

# Ajouter ligne
administrateur ALL=(ALL) NOPASSWD: /usr/bin/nmap

# Test
nmap -O localhost  # Ne demande plus de mot de passe
```

**Windows - Tâche planifiée avec privilèges élevés :**
```powershell
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\ntl-systoolbox\src\module3_audit.py"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Saturday -At 2am
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "NTL Audit Obsolescence" -RunLevel Highest
```

#### 3. Optimisation des scans

**Scan rapide (ping sweep uniquement) :**
```bash
# Détection hôtes actifs sans scan ports
nmap -sn 192.168.1.0/24
```

**Scan ciblé (ports critiques uniquement) :**
```bash
# Uniquement ports RDP, SMB, SSH
python src/module3_audit.py --ports 22,445,3389
```

**Scan par sous-réseaux :**
```bash
# Découper /16 en /24 pour performances
for i in {0..255}; do
    python src/module3_audit.py --scan 10.5.$i.0/24
done
```

#### 4. Archivage et historique

**Convention de nommage :**
```
audit_[site]_[YYYY-MM-DD].csv
audit_lille_2026-02-23.csv
audit_lens_2026-02-23.csv
audit_consolidé_2026-Q1.csv
```

**Rotation automatique :**
```bash
# Garder 12 mois d'historique
find backups/audit/ -name "audit_*.csv" -mtime +365 -delete
```

---

### Dépannage Module 3

#### Erreur : "nmap program was not found in path"

**Cause :** Binaire nmap non installé ou pas dans le PATH.

**Solution :**
```bash
# Linux
sudo apt install nmap
which nmap  # Vérifier présence

# Windows
winget install Insecure.Nmap
nmap --version  # Vérifier installation
```

#### Erreur : "Permission denied" lors du scan

**Cause :** Scan SYN stealth nécessite privilèges élevés.

**Solution :**
```bash
# Linux - Utiliser sudo
sudo python src/module3_audit.py

# Ou configurer capabilities (recommandé)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

# Windows - Lancer PowerShell en Administrateur
```

#### Erreur : "Timeout during scan"

**Cause :** Réseau lent ou pare-feu bloquant les paquets.

**Solution :**
```bash
# Augmenter le timeout dans ntl_config.json
{
  "module3_audit": {
    "nmap_timeout": 600,  # 10 minutes au lieu de 5
    "detection_timeout": 5  # 5 secondes au lieu de 3
  }
}
```

#### Scan très lent (> 30 min pour /24)

**Causes possibles :**
- Réseau lent (< 10 Mbps)
- Pare-feu avec rate-limiting
- Nombre d'hôtes actifs > 100

**Solutions :**
1. Réduire la plage scannée (découper en sous-réseaux)
2. Limiter les ports scannés (`--ports 22,445,3389`)
3. Utiliser scan TCP connect au lieu de SYN stealth (plus lent mais sans privilèges)

#### OS non détecté (status "Unknown")

**Causes :**
- Pare-feu bloquant les sondes nmap
- OS non référencé dans base EOL
- Fingerprint OS ambigu

**Solutions :**
1. Vérifier connectivité : `ping <ip>` puis `telnet <ip> <port>`
2. Scan manuel : `nmap -O -v <ip>`
3. Ajouter manuellement dans CSV avec os_version connue

---

## Planification des tâches

### Cron (Linux)

**Backup quotidien à 2h du matin:**
```bash
crontab -e
# Ajouter:
0 2 * * * /chemin/vers/venv/bin/python /chemin/vers/src/module2_wms_backup.py >> /var/log/ntl-backup.log 2>&1
```

**Diagnostic global hebdomadaire (dimanche 3h):**
```bash
0 3 * * 0 /chemin/vers/venv/bin/python /chemin/vers/src/module1_diagnostic.py windows --json >> /var/log/ntl-diag.log 2>&1
```

### Tâche planifiée (Windows)

**Backup quotidien:**
```cmd
schtasks /create /tn "NTL WMS Backup" /tr "C:\ntl-systoolbox\venv\Scripts\python.exe C:\ntl-systoolbox\src\module2_wms_backup.py" /sc daily /st 02:00
```

**Diagnostic hebdomadaire:**
```cmd
schtasks /create /tn "NTL Diagnostic" /tr "C:\ntl-systoolbox\venv\Scripts\python.exe C:\ntl-systoolbox\src\module1_diagnostic.py windows" /sc weekly /d SUN /st 03:00
```

---

## Intégration Zabbix

### Création d'un item Zabbix

**Template:** `NTL-SysToolbox`

**Item 1: AD/DNS DC01 Health**
```yaml
Type: External check
Key: ntl.diag.addns[{HOST.IP}]
Type of information: Numeric (unsigned)
Interval: 5m
```

**Script externe (`/usr/lib/zabbix/externalscripts/ntl_diag_addns.sh`):**
```bash
#!/bin/bash
IP=$1
cd /opt/ntl-systoolbox
source venv/bin/activate
python src/module1_diagnostic.py ad-dns $IP --json | jq -r '.checks[0].status' | grep -q "OK" && echo 1 || echo 0
```

**Trigger:**
```
{NTL-SysToolbox:ntl.diag.addns[{HOST.IP}].last()}=0
```

**Item 2: MySQL WMS Uptime**
```yaml
Type: External check
Key: ntl.mysql.uptime
Interval: 10m
```

**Script:**
```bash
#!/bin/bash
cd /opt/ntl-systoolbox
source venv/bin/activate
export MYSQL_PASS="secret"
python src/module1_diagnostic.py mysql --json | jq -r '.checks[0].details.uptime_seconds'
```

---

## Dépannage

### Erreur: "pypsrp non installé"

**Cause:** Dépendance manquante

**Solution:**
```bash
pip install pypsrp
```

### Erreur WinRM: "Connection refused"

**Causes possibles:**
1. WinRM non activé sur le serveur cible
2. Pare-feu bloquant le port 5985/5986
3. Mauvais credentials

**Solutions:**

**1. Vérifier WinRM sur le serveur:**
```powershell
Get-Service WinRM
# Si "Stopped":
Start-Service WinRM
Enable-PSRemoting -Force
```

**2. Autoriser WinRM dans le pare-feu:**
```powershell
New-NetFirewallRule -Name "WinRM-HTTP" -DisplayName "WinRM (HTTP-In)" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985
```

**3. Tester manuellement:**
```powershell
Test-WSMan -ComputerName 10.5.60.10
```

### Erreur SSH: "Authentication failed"

**Causes:**
- Mauvais mot de passe
- Clé SSH non autorisée
- Permissions incorrectes sur `~/.ssh/authorized_keys`

**Solutions:**

**1. Vérifier SSH actif:**
```bash
sudo systemctl status ssh
```

**2. Tester connexion manuelle:**
```bash
ssh administrateur@10.5.60.20
```

**3. Réparer permissions SSH:**
```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### Erreur MySQL: "Access denied"

**Solution:**
```bash
# Tester connexion manuelle
mysql -h 10.5.60.20 -u wms_user -p wms

# Vérifier permissions
GRANT ALL PRIVILEGES ON wms.* TO 'wms_user'@'%' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
```

### Backups absents

**Vérifier dossiers créés:**
```bash
# Linux/Mac
ls -la backups/

# Windows
dir backups\
```

**Créer manuellement si nécessaire:**
```bash
mkdir -p backups/{ad_dns,mysql,windows,ubuntu,global,wms}
```

---

## Bonnes pratiques

### Sécurité

1. **Ne jamais commiter les mots de passe**
   ```bash
   # .gitignore
   src/ntl_config.json
   backups/
   ```

2. **Utiliser des variables d'environnement**
   ```bash
   export WMS_DB_PASS=$(cat /etc/secrets/wms_pass)
   ```

3. **Activer TLS pour WinRM**
   ```python
   # Modifier module1_diagnostic.py
   client = Client(remote_ip, username=username, password=password, ssl=True)
   ```

4. **Chiffrer les backups sensibles**
   ```bash
   gpg --symmetric backups/wms/wms_dump_2026-02-17.sql
   ```

### Performance

1. **Limiter les diagnostics concurrents**
   - Diagnostic global: max 1 par heure
   - Backups WMS: fenêtre nocturne uniquement

2. **Rotation des backups**
   ```bash
   # Garder 7 jours de backups
   find backups/wms/ -name "*.sql" -mtime +7 -delete
   ```

3. **Compression SQL dumps**
   ```bash
   gzip backups/wms/*.sql
   ```

### Monitoring

1. **Surveiller les exit codes**
   ```bash
   python src/module2_wms_backup.py
   if [ $? -ne 0 ]; then
       mail -s "BACKUP FAILED" admin@ntl.local < backup.log
   fi
   ```

2. **Alertes Zabbix**
   - Trigger si backup > 24h
   - Trigger si espace disque < 10%

---

## Support et ressources

### Documentation

- **TECH.md** - Architecture et choix techniques
- **README.md** - Introduction et quickstart
- **LICENCE.md** - MIT License

### Logs et debug

**Activer logs verbeux:**
```bash
export NTL_DEBUG=1
python src/module1_diagnostic.py windows --json
```

**Localisation des logs:**
- **Linux:** `/var/log/ntl-systoolbox.log`
- **Windows:** `C:\ntl-systoolbox\logs\`

### Contact

**Issues GitHub:** `https://github.com/Not-mat-collab/ntl-systoolbox/issues`  
**Équipe:** Administrateur Systèmes & Réseaux NTL

---

## Annexe: Exemples complets

### Script de sauvegarde automatique

```bash
#!/bin/bash
# /opt/ntl-systoolbox/scripts/daily_backup.sh

set -e

LOG_FILE="/var/log/ntl-backup.log"
BACKUP_DIR="/backups/wms"
RETENTION_DAYS=7

echo "[$(date)] Démarrage sauvegarde WMS" >> $LOG_FILE

cd /opt/ntl-systoolbox
source venv/bin/activate

export WMS_DB_PASS=$(cat /etc/secrets/wms_pass)

python src/module2_wms_backup.py >> $LOG_FILE 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo "[$(date)] Sauvegarde réussie" >> $LOG_FILE
    
    # Rotation des backups
    find $BACKUP_DIR -name "*.sql" -mtime +$RETENTION_DAYS -delete
    find $BACKUP_DIR -name "*.csv" -mtime +$RETENTION_DAYS -delete
    
    # Compression
    gzip $BACKUP_DIR/*.sql 2>/dev/null || true
else
    echo "[$(date)] ERREUR: Sauvegarde échouée (code $EXIT_CODE)" >> $LOG_FILE
    mail -s "BACKUP FAILED" admin@ntl.local < $LOG_FILE
fi
```

### Script de diagnostic multi-sites

```python
# scripts/check_all_sites.py
import subprocess
import json
from datetime import datetime

SITES = {
    "DC01": "10.5.60.10",
    "DC02": "10.5.60.11",
    "WMS-DB": "10.5.60.20"
}

results = {"timestamp": datetime.now().isoformat(), "sites": {}}

for name, ip in SITES.items():
    cmd = ["python", "src/module1_diagnostic.py", "ad-dns", ip, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    results["sites"][name] = json.loads(result.stdout)

with open(f"reports/multi_site_{datetime.now().strftime('%Y%m%d')}.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"Rapport généré: {len(SITES)} sites vérifiés")
```

---

## Support et contacts

**Documentation complète:** `docs/USAGE.md`  
**Architecture technique:** `docs/TECH.md`  
**Issues GitHub:** `https://github.com/Not-mat-collab/ntl-systoolbox/issues`

---

**Version:** 1.0.0  
**Date de publication:** 2026-02-23  
**Auteur:** Équipe MSPR GROUPE 1
**Client**: Nord Transit Logistics (NTL)  
**Licence**: MIT License  
**Contact**: Administrateur Systèmes & Réseaux
