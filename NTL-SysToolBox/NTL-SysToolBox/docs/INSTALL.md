# NTL-SysToolbox - Procédure d'Installation DSI

## Vue d'ensemble

Ce document décrit les procédures d'installation de **NTL-SysToolbox** sur les environnements d'exploitation de Nord Transit Logistics. Il est destiné aux administrateurs système et aux équipes DSI.

---

## Table des matières

1. [Prérequis matériels et logiciels](#1-prérequis-matériels-et-logiciels)
2. [Installation sur serveur Linux](#2-installation-sur-serveur-linux)
3. [Installation sur serveur Windows](#3-installation-sur-serveur-windows)
4. [Configuration post-installation](#4-configuration-post-installation)
5. [Vérification de l'installation](#5-vérification-de-linstallation)
6. [Configuration des accès distants](#6-configuration-des-accès-distants)
7. [Dépannage](#9-dépannage)

---

## 1. Prérequis matériels et logiciels

### 1.1 Environnement matériel

| Composant | Minimum | Recommandé | Production |
|-----------|---------|------------|------------|
| **CPU** | 1 vCPU / 1 core | 2 vCPU / 2 cores | 4 vCPU / 4 cores |
| **RAM** | 512 MB | 2 GB | 4 GB |
| **Stockage** | 5 GB | 20 GB | 50 GB + espace backups |
| **Réseau** | 100 Mbps | 1 Gbps | 1 Gbps |

### 1.2 Systèmes d'exploitation supportés

**Linux:**
- Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS
- Debian 10 / 11 / 12
- CentOS 7 / 8 / Rocky Linux 8/9
- Red Hat Enterprise Linux 7 / 8 / 9

**Windows:**
- Windows Server 2016 / 2019 / 2022
- Windows 10 Pro / Enterprise (21H2+)
- Windows 11 Pro / Enterprise

### 1.3 Prérequis logiciels

| Composant | Version minimum | Version recommandée |
|-----------|----------------|---------------------|
| **Python** | 3.8 | 3.10+ |
| **pip** | 20.0 | 23.0+ |
| **Git** | 2.20 | 2.40+ |

### 1.4 Accès réseau requis

**Ports sortants (depuis le serveur NTL-SysToolbox):**

| Service | Port | Protocole | Destination | Usage |
|---------|------|-----------|-------------|-------|
| DNS | 53 | TCP/UDP | 10.5.60.10/11 | Test AD/DNS |
| LDAP | 389 | TCP | 10.5.60.10/11 | Test Active Directory |
| Kerberos | 88 | TCP | 10.5.60.10/11 | Test AD |
| MySQL | 3306 | TCP | 10.5.60.20 | Diagnostic + Backup WMS |
| SSH | 22 | TCP | Serveurs Linux | Diagnostic distant |
| WinRM HTTP | 5985 | TCP | Serveurs Windows | Diagnostic distant |
| WinRM HTTPS | 5986 | TCP | Serveurs Windows | Diagnostic distant (TLS) |

**Accès Internet (optionnel):**
- GitHub (clonage du dépôt): `github.com:443`
- PyPI (installation packages): `pypi.org:443`

---

## 2. Installation sur serveur Linux

### 2.1 Installation Python et dépendances système

#### Ubuntu/Debian

```bash
# Mise à jour des paquets système
sudo apt update && sudo apt upgrade -y

# Installation Python 3, pip, venv et Git
sudo apt install -y python3 python3-pip python3-venv git

# Vérification des versions
python3 --version  # Attendu: Python 3.8+
pip3 --version     # Attendu: pip 20.0+
git --version      # Attendu: git 2.20+
```

### 2.2 Clonage du projet

**Option A: Clonage HTTPS**

```bash
# Création du répertoire d'installation
sudo mkdir -p /opt/ntl-systoolbox
sudo chown $(whoami):$(whoami) /opt/ntl-systoolbox

# Clonage du dépôt GitHub
cd /opt
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git

# Vérification
cd ntl-systoolbox
ls -la
```

### 2.3 Création de l'environnement virtuel Python

```bash
cd /opt/ntl-systoolbox

# Création du venv
python3 -m venv venv

# Activation (session courante)
source venv/bin/activate

# Vérification
which python  # Doit pointer vers /opt/ntl-systoolbox/venv/bin/python
```

### 2.4 Installation des dépendances Python

```bash
# Activation du venv (si non déjà fait)
source /opt/ntl-systoolbox/venv/bin/activate

# Mise à jour de pip
pip install --upgrade pip

# Installation des packages requis
pip install -r requirements.txt

# Vérification des installations
pip list | grep -E "psutil|pymysql|paramiko|pypsrp"
```

**Sortie attendue:**
```
psutil>=5.9.0
pymysql>=1.1.0
paramiko>=3.4.0
pypsrp>=0.8.1
python-nmap>=0.7.1
pandas>=2.1.4
python-dateutil>=2.8.2
requests>=2.31.0
openpyxl>=3.1.2
```

### 2.5 Configuration des permissions

```bash
# Propriétaire: utilisateur d'exploitation (ex: administrateur)
sudo chown -R administrateur:administrateur /opt/ntl-systoolbox

# Permissions restrictives sur les fichiers
chmod 700 /opt/ntl-systoolbox
chmod 600 /opt/ntl-systoolbox/src/ntl_config.json

# Création des répertoires de backups
mkdir -p /opt/ntl-systoolbox/backups/{ad_dns,mysql,windows,ubuntu,global,wms}
chmod 750 /opt/ntl-systoolbox/backups
```

---

## 3. Installation sur serveur Windows

### 3.1 Installation Python

**Option A: Winget (Windows 10 1809+ / Windows Server 2019+)**

```powershell
# Ouvrir PowerShell en Administrateur
winget install Python3

# Vérification
python --version  # Attendu: Python 3.x.x
pip --version
```

**Option B: Installateur officiel**

1. Télécharger Python depuis [python.org](https://www.python.org/downloads/windows/)
2. Exécuter l'installateur
3. ✅ **Cocher "Add Python to PATH"**
4. Installer

### 3.2 Installation Nmap

**Option A: Winget (Windows 10 1809+ / Windows Server 2019+)**

```powershell
# Ouvrir PowerShell en Administrateur
winget install nmap

# Vérification
nmap --version

# Ajouter au Path via PowerShell
[System.Environment]::SetEnvironmentVariable('Path', $env:Path + ";C:\Program Files (x86)\Nmap", [System.EnvironmentVariableTarget]::Machine)

# Reboot le serveur
```

**Option B: Installateur officiel**

1. Télécharger nmap depuis [nmap.org](https://nmap.org/dist/nmap-7.98-setup.exe)
2. Exécuter l'installateur
3. Installer

### 3.4 Clonage du projet

**Option A: Clonage Git**

```powershell
# Création du répertoire
New-Item -ItemType Directory -Path "C:\ntl-systoolbox"
cd C:\ntl-systoolbox

# Clonage
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git .
```

### 3.5 Installation des dépendances

```powershell
# Mise à jour pip
python -m pip install --upgrade pip

# Installation des packages
pip install -r requirements.txt

# Vérification
pip list | Select-String "psutil|pymysql|paramiko|pypsrp"
```

---

## 4. Configuration post-installation

### 4.1 Configuration du fichier ntl_config.json

**Édition du fichier:**

**Linux:**
```bash
nano /opt/ntl-systoolbox/src/ntl_config.json
```

**Windows:**
```powershell
notepad C:\ntl-systoolbox\src\ntl_config.json
```

**Contenu à personnaliser:**

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

### 4.2 Test de connectivité MySQL

**Linux:**
```bash
# Test de connexion manuelle
mysql -h 10.5.60.20 -u wms_user -p wms

# Si succès, affichage:
# MariaDB [wms]>
```

**Windows:**
```cmd
REM Installation du client MySQL (si absent)
winget install Oracle.MySQL

REM Test
mysql -h 10.5.60.20 -u wms_user -p wms
```

**Si erreur "Access denied":**

```sql
-- Sur le serveur MySQL (10.5.60.20), en root:
GRANT ALL PRIVILEGES ON wms.* TO 'wms_user'@'%' IDENTIFIED BY 'password'; -- % permet les connexion externe
FLUSH PRIVILEGES;
```

### 4.3 Configuration du pare-feu

**Linux (UFW - Ubuntu/Debian):**

```bash
# Autoriser connexions sortantes (par défaut: autorisé)
# Vérification règles
sudo ufw status verbose

# Si besoin, autoriser sortie MySQL
sudo ufw allow out 3306/tcp comment 'NTL-SysToolbox to MySQL WMS'
```

**Windows Firewall:**

```powershell
# Règle sortante MySQL (normalement autorisée par défaut)
New-NetFirewallRule -DisplayName "NTL-SysToolbox to MySQL" `
  -Direction Outbound `
  -Protocol TCP `
  -RemoteAddress 10.5.60.20 `
  -RemotePort 3306 `
  -Action Allow
```

---

## 5. Vérification de l'installation

### 5.1 Test de lancement

**Linux:**
```bash
cd /opt/ntl-systoolbox
source venv/bin/activate
python main.py
```

**Windows:**
```powershell
cd C:\ntl-systoolbox
python main.py
```

**Sortie attendue:**
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

### 5.2 Test Module 1 - Diagnostic local

**Commande:**
```bash
python src/module1_diagnostic.py windows  # Sur Windows
python src/module1_diagnostic.py ubuntu   # Sur Linux
```

**Résultat attendu:**
```
======================================================================
MODULE DIAGNOSTIC - RÉSULTATS
======================================================================
Horodatage: 2026-02-17T19:45:00

[1] Windows_Server - Statut: OK
----------------------------------------------------------------------
  Hostname: NTL-ADMIN-01
  Mode: 💻 Local
  OS: Microsoft Windows Server 2019 Standard
  Uptime: 5j 12h 34min
  CPU: Intel(R) Xeon(R) E-2288G (8 cœurs) - 12.3%
  RAM: 4.2 GB / 16.0 GB (26.2%)
  Disques:
    C:\ [System]: 85.3 GB / 250.0 GB (34.1%)
```

### 5.3 Test Module 2 - Backup WMS

**Commande:**
```bash
python src/module2_wms_backup.py
```

**Interaction:**
```
MariaDB password for wms_user@10.5.60.20:
[Saisir mot de passe]

=== BACKUP WMS ===
Status : OK
Message : SQL dump and CSV export completed.
Code : 0
```

**Vérification des fichiers générés:**

**Linux:**
```bash
ls -lh /opt/ntl-systoolbox/backups/wms/
```

**Windows:**
```powershell
Get-ChildItem C:\ntl-systoolbox\backups\wms\
```

**Sortie attendue:**
```
wms_dump_2026-02-17_19-45-00_UTC.sql      (2.5 MB)
stock_moves_2026-02-17_19-45-00_UTC.csv   (1.2 MB)
wms_dump_2026-02-17_19-45-00_UTC.json     (15 KB)
```

### 5.4 Checklist de vérification finale

- [ ] Python 3.8+ installé et accessible
- [ ] Environnement virtuel créé et activable
- [ ] Tous les packages Python installés (psutil, pymysql, paramiko, pypsrp)
- [ ] Fichier `ntl_config.json` configuré avec les bonnes IPs
- [ ] Variables d'environnement pour mots de passe configurées
- [ ] Menu principal (`main.py`) s'affiche correctement
- [ ] Module 1 diagnostic local fonctionne
- [ ] Module 2 backup WMS génère les fichiers SQL/CSV
- [ ] Répertoires `backups/` créés avec bonnes permissions
- [ ] Tâches planifiées (cron/schtasks) configurées
- [ ] Tests de connectivité réseau OK (MySQL, AD/DNS)

---

## 6. Configuration des accès distants

### 6.1 Activation WinRM sur serveurs Windows cibles (par defaut sur les serveurs)

**Sur chaque serveur Windows à diagnostiquer:**

```powershell
# Ouvrir PowerShell en Administrateur
Enable-PSRemoting -Force

# Configuration TrustedHosts (environnement workgroup)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Redémarrage du service
Restart-Service WinRM

# Vérification
Get-Service WinRM  # Status: Running
Test-WSMan -ComputerName localhost
```

**Configuration du pare-feu Windows:**

```powershell
# Règle pare-feu WinRM HTTP
New-NetFirewallRule -Name "WinRM-HTTP-In" `
  -DisplayName "Windows Remote Management (HTTP-In)" `
  -Enabled True `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 5985 `
  -Action Allow
```

### 6.2 Configuration SSH sur serveurs Linux cibles

**Installation et activation SSH (si absent):**

**Ubuntu/Debian:**
```bash
sudo apt install -y openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh
```

**Configuration sécurisée (`/etc/ssh/sshd_config`):**

```bash
sudo nano /etc/ssh/sshd_config
```

**Paramètres recommandés:**
```
Port 22
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
```

**Application des changements:**
```bash
sudo systemctl restart sshd
```
---

## 7. Dépannage

### 7.1 Problèmes Python

**Erreur: "python: command not found"**

**Linux:**
```bash
# Vérifier installation
which python3
sudo apt install python3  # Ubuntu/Debian
```

**Windows:**
```powershell
# Réinstaller Python
winget install Python3

# Ou ajouter au PATH manuellement
$env:Path += ";C:\Python3xx;C:\Python3xx\Scripts"
```

**Erreur: "No module named 'X'"**

```bash
# Réinstallation des dépendances
pip install -r requirements.txt --force-reinstall
```

### 7.2 Problèmes de connectivité

**Test de port MySQL:**

```bash
# Linux
nc -zv 10.5.60.20 3306
telnet 10.5.60.20 3306

# Windows
Test-NetConnection -ComputerName 10.5.60.20 -Port 3306
```

**Test WinRM:**

```powershell
# Depuis Windows
Test-WSMan -ComputerName 10.5.60.10

# Test d'authentification
Enter-PSSession -ComputerName 10.5.60.10 -Credential administrateur
```

**Test SSH:**

```bash
# Test de connexion
ssh -v administrateur@10.5.60.20

# Test de port
telnet 10.5.60.20 22
```

### 7.3 Problèmes de permissions

**Linux - Erreur "Permission denied":**

```bash
# Vérifier propriétaire
ls -la /opt/ntl-systoolbox

# Corriger si nécessaire
sudo chown -R administrateur:administrateur /opt/ntl-systoolbox
chmod 700 /opt/ntl-systoolbox
chmod 600 /opt/ntl-systoolbox/src/ntl_config.json
```

**Windows - Erreur "Access Denied":**

```powershell
# Vérifier permissions
Get-Acl C:\ntl-systoolbox | Format-List

# Réattribuer permissions
$acl = Get-Acl C:\ntl-systoolbox
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("ntladmin", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl C:\ntl-systoolbox $acl
```

### 9.4 Logs et debug

**Activation du mode debug:**

**Linux:**
```bash
export NTL_DEBUG=1
python src/module1_diagnostic.py windows --json 2>&1 | tee debug.log
```

**Windows:**
```powershell
$env:NTL_DEBUG = "1"
python src\module1_diagnostic.py windows --json 2>&1 | Tee-Object debug.log
```

**Consultation des logs système:**

**Linux systemd:**
```bash
journalctl -u ntl-backup.service -f
```

**Windows Event Viewer:**
```powershell
Get-EventLog -LogName Application -Source "NTL-SysToolbox" -Newest 50
```

---

## Support et contacts

**Documentation complète:** `docs/USAGE.md`  
**Architecture technique:** `docs/TECH.md`  
**Issues GitHub:** `https://github.com/Not-mat-collab/ntl-systoolbox/issues`


---

**Version:** 10  
**Date de publication:** 2026-02-17  
**Auteur:** Équipe MSPR GRP 1 - Administrateur Systèmes & Réseaux NTL
