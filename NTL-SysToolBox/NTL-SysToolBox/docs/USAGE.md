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
- `python-nmap` 0.7.1
- `pandas` 2.1.4`
- `python-dateutil` 2.8.2
- `requests` 2.31.0
- `openpyxl` 3.1.2


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

### Étape 3: Installer les dépendances

```bash
pip install -r requirements.txt
```

### Étape 4: Vérifier l'installation

```bash
python main.py
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
python main.py
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

**Permissions restrictives:**
```bash
chmod 600 src/ntl_config.json  # Linux/Mac
```

---

## Utilisation

### Lancement du menu principal

```bash
python main.py
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
python main.py
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
python main.py
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

## Module 3 - Audit d'obsolescence

### Statut

⚠️ **Non implémenté dans la version actuelle (v10)**

### Fonctionnalités prévues

Le Module 3 permettra de:
1. Scanner une plage réseau (ex: `192.168.10.0/24`)
2. Identifier l'OS des machines détectées
3. Interroger une base EOL (End-of-Life) publique
4. Générer un rapport d'obsolescence

### Usage prévu

```bash
python src/module3_audit.py --network 192.168.10.0/24
```

**Rapport généré:**
```csv
ip,hostname,os,version,eol_date,status,days_remaining
192.168.10.10,DC01,Windows Server 2012 R2,6.3.9600,2023-10-10,CRITICAL,-1215
192.168.10.20,WMS-DB,Ubuntu 18.04 LTS,18.04.6,2023-05-31,CRITICAL,-1353
192.168.10.30,APP-SRV,Windows Server 2019,10.0.17763,2029-01-09,OK,1057
```

**Roadmap:** Version 3.0 (Q4 2026)

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

- **INSTALL.md** - Installation du programme détaillé
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

**Version:** 10  
**Dernière mise à jour:** 2026-02-17  
**Auteur:** Équipe MSPR GRP 1
