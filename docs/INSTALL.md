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
7. [Installation nmap (Module 3)](#7-installation-nmap-module-3)
8. [Dépannage](#8-dépannage)

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
| **Python** | 3.9 | 3.11+ |
| **pip** | 20.0 | 23.0+ |
| **Git** | 2.20 | 2.40+ |
| **nmap** (Module 3) | 7.80 | 7.94+ |

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
| **Scans réseau (Module 3)** | **Multiples** | **TCP/UDP** | **Plages IP ciblées** | **Audit obsolescence** |

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
sudo apt install -y python3 python3-pip python3-venv python3-nmap git

# Vérification des versions
python3 --version  # Attendu: Python 3.9+
pip3 --version     # Attendu: pip 20.0+
git --version      # Attendu: git 2.20+
nmap --version
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
pip list | grep -E "psutil|pymysql|paramiko|pypsrp|python-nmap|pandas|requests"
```

**Sortie attendue:**
```
pandas           2.1.0
paramiko         3.4.0
psutil           5.9.8
pymysql          1.1.0
pypsrp           0.8.1
python-nmap      0.7.1
requests         2.31.0
python-dateutil  2.8.2
openpyxl         3.1.2
```

### 2.5 Configuration des permissions

```bash
# Propriétaire: utilisateur d'exploitation (ex: administrateur)
sudo chown -R administrateur:administrateur /opt/ntl-systoolbox

# Permissions restrictives sur les fichiers
chmod 700 /opt/ntl-systoolbox
chmod 600 /opt/ntl-systoolbox/src/ntl_config.json

# Création des répertoires de backups
mkdir -p /opt/ntl-systoolbox/backups/{ad_dns,mysql,windows,ubuntu,global,wms,audit}
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
python --version  # Attendu: Python 3.11.x
pip --version
```

**Option B: Installateur officiel**

1. Télécharger Python depuis [python.org](https://www.python.org/downloads/windows/)
2. Exécuter l'installateur
3. ✅ **Cocher "Add Python to PATH"**
4. Installer

### 3.2 Installation Git

```powershell
winget install Git.Git
# Ou télécharger depuis https://git-scm.com/download/win
```

### 3.3 Clonage du projet

```powershell
# Création du répertoire
New-Item -ItemType Directory -Path "C:\ntl-systoolbox"
cd C:\ntl-systoolbox

# Clonage
git clone https://github.com/Not-mat-collab/ntl-systoolbox.git .
```

### 3.4 Installation des dépendances

```powershell
# Mise à jour pip
python -m pip install --upgrade pip

# Installation des packages
pip install -r requirements.txt

# Vérification
pip list | Select-String "psutil|pymysql|paramiko|pypsrp|python-nmap|pandas|requests"
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
**main.py:**
```powershell
Selectionner le choix [C]
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
  },
}
```

### 4.2 Configuration des variables d'environnement (optionel)

**Linux:**
```bash
# Éditer ~/.bashrc ou ~/.profile
nano ~/.bashrc

# Ajouter:
export WMS_DB_PASS="mot_de_passe_sécurisé"
export MYSQL_ROOT_PASS="root_password"

# Appliquer
source ~/.bashrc
```

**Windows:**
```powershell
# Variables utilisateur (persiste après redémarrage)
[System.Environment]::SetEnvironmentVariable('WMS_DB_PASS', 'mot_de_passe_sécurisé', 'User')
[System.Environment]::SetEnvironmentVariable('MYSQL_ROOT_PASS', 'root_password', 'User')

# Ou temporaire (session courante)
$env:WMS_DB_PASS = "mot_de_passe_sécurisé"
$env:MYSQL_ROOT_PASS = "root_password"
```

### 4.3 Test de connectivité MySQL

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
GRANT ALL PRIVILEGES ON wms.* TO 'wms_user'@'%' IDENTIFIED BY 'password';
FLUSH PRIVILEGES;
```

### 4.4 Configuration du pare-feu

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
 NTL-SysToolbox v1.0.0
 Config: 10.5.60.20
======================================================================

MENU PRINCIPAL
----------------------------------------------------------------------
 [1] Module 1 - Diagnostic (menu autonome)
 [2] Module 2 - Sauvegarde WMS
 [3] Module 3 - Audit obsolescence réseau
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
Horodatage: 2026-02-23T09:45:00

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
wms_dump_2026-02-23_09-45-00_UTC.sql      (2.5 MB)
stock_moves_2026-02-23_09-45-00_UTC.csv   (1.2 MB)
wms_dump_2026-02-23_09-45-00_UTC.json     (15 KB)
```

### 5.4 Test Module 3 - Audit obsolescence

**Vérification nmap installé:**

**Linux:**
```bash
nmap --version
# Attendu: Nmap version 7.80+
```

**Windows:**
```powershell
nmap --version
# Attendu: Nmap version 7.94+
```

**Test de l'interface Module 3:**

```bash
python src/module3_audit.py
```

**Menu attendu:**
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

### 5.5 Checklist de vérification finale

- [ ] Python 3.9+ installé et accessible
- [ ] Environnement virtuel créé et activable
- [ ] Tous les packages Python installés (psutil, pymysql, paramiko, pypsrp, python-nmap, pandas, requests)
- [ ] **nmap binaire installé sur le système (Module 3)**
- [ ] Fichier `ntl_config.json` configuré avec les bonnes IPs
- [ ] Variables d'environnement pour mots de passe configurées
- [ ] Menu principal (`main.py`) s'affiche correctement
- [ ] Module 1 diagnostic local fonctionne
- [ ] Module 2 backup WMS génère les fichiers SQL/CSV
- [ ] **Module 3 menu s'affiche sans erreur**
- [ ] Répertoires `backups/` créés avec bonnes permissions (incluant `backups/audit/`)
- [ ] Tests de connectivité réseau OK (MySQL, AD/DNS)

---

## 6. Configuration des accès distants (optionel)

### 6.1 Activation WinRM sur serveurs Windows cibles

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

## 7. Installation nmap (Module 3)

⚠️ **PRÉREQUIS CRITIQUE pour le Module 3** : `nmap` doit être installé sur le système. Le package Python `python-nmap` est un simple wrapper et ne contient PAS le binaire nmap.

### 7.1 Installation sur Linux

#### Ubuntu/Debian

```bash
# Installation
sudo apt update
sudo apt install -y nmap

# Vérification
nmap --version
```

**Sortie attendue:**
```
Nmap version 7.80 ( https://nmap.org )
Platform: x86_64-pc-linux-gnu
Compiled with: liblua-5.3.3 openssl-1.1.1f libz-1.2.11 libpcre-8.39 libpcap-1.9.1 nmap-libdnet-1.12 ipv6
```

#### CentOS/RHEL/Rocky Linux

```bash
# Installation
sudo yum install -y nmap

# Vérification
nmap --version
```

#### Compilation depuis les sources (si version repo trop ancienne)

```bash
# Dépendances
sudo apt install -y build-essential libssl-dev

# Téléchargement (dernière version stable)
cd /tmp
wget https://nmap.org/dist/nmap-7.94.tar.bz2
tar xjf nmap-7.94.tar.bz2
cd nmap-7.94

# Compilation et installation
./configure
make
sudo make install

# Vérification
nmap --version
```

### 7.2 Installation sur Windows

#### Option A: Téléchargement officiel (RECOMMANDÉ)

1. Télécharger l'installateur depuis [https://nmap.org/download.html](https://nmap.org/download.html)
2. Choisir **nmap-7.94-setup.exe** (dernière version stable)
3. Exécuter l'installateur **en tant qu'Administrateur**
4. ✅ Cocher **"Add Nmap to the system PATH for all users"**
5. Installation complète (incluant Zenmap, Ncat, Nping)

#### Option B: Winget

```powershell
# Installation via Winget
winget install Insecure.Nmap

# Vérification
nmap --version
```

#### Option C: Chocolatey

```powershell
# Installation via Chocolatey
choco install nmap

# Vérification
nmap --version
```

### 7.3 Vérification post-installation

**Test de scan basique:**

**Linux:**
```bash
# Scan localhost (ne nécessite pas sudo)
nmap -sn localhost

# Scan avec détection OS (nécessite sudo/root)
sudo nmap -O localhost
```

**Windows (PowerShell Administrateur):**
```powershell
# Scan localhost
nmap -sn localhost

# Scan avec détection OS
nmap -O localhost
```

**Sortie attendue:**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2026-02-23 10:00 CET
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000011s latency).
Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds
```

### 7.4 Permissions requises pour scan réseau

**Linux - Privilèges élevés requis:**

Le Module 3 utilise des scans SYN stealth (`-sS`) et détection OS (`-O`) qui nécessitent des privilèges root/sudo car ils utilisent des raw sockets.

**Options:**

**Option A: Exécuter avec sudo (RECOMMANDÉ pour tests):**
```bash
sudo python src/module3_audit.py
```

**Option B: Capabilities Linux (RECOMMANDÉ++ pour production):**
```bash
# Accorder capacité CAP_NET_RAW à nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Vérification
getcap $(which nmap)
# Attendu: /usr/bin/nmap = cap_net_admin,cap_net_bind_service,cap_net_raw+eip

# Maintenant, utilisation sans sudo
python src/module3_audit.py
```

**Option C: Sudoers sans mot de passe (POUR AUTOMATISATION):**
```bash
# Éditer sudoers
sudo visudo

# Ajouter:
administrateur ALL=(ALL) NOPASSWD: /usr/bin/nmap

# Test
nmap -sS -O 127.0.0.1  # Ne demande plus de mot de passe
```

**Windows - Exécution en tant qu'Administrateur:**

```powershell
# Lancer PowerShell en Administrateur
# Ou clic droit sur cmd.exe → "Exécuter en tant qu'administrateur"

cd C:\ntl-systoolbox
python src\module3_audit.py
```

### 7.5 Dépannage nmap

**Erreur "nmap: command not found" (Linux):**

```bash
# Vérifier PATH
which nmap

# Si absent, ajouter au PATH
export PATH=$PATH:/usr/local/bin

# Permanent (ajouter à ~/.bashrc)
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

**Erreur "nmap: command not found" (Windows):**

```powershell
# Vérifier PATH
$env:Path -split ';' | Select-String "nmap"

# Si absent, ajouter manuellement
$newPath = "C:\Program Files (x86)\Nmap"
[System.Environment]::SetEnvironmentVariable("Path", $env:Path + ";$newPath", [System.EnvironmentVariableTarget]::Machine)

# Redémarrer PowerShell
```

**Erreur "Operation not permitted" (Linux sans sudo):**

```bash
# Utiliser capabilities (voir section 7.4)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

# Ou exécuter avec sudo
sudo python src/module3_audit.py
```

---

## 8. Dépannage

### 8.1 Problèmes Python

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
winget install Python.Python.3.11

# Ou ajouter au PATH manuellement
$env:Path += ";C:\Python311;C:\Python311\Scripts"
```

**Erreur: "No module named 'X'"**

```bash
# Réinstallation des dépendances
pip install -r requirements.txt --force-reinstall
```

### 8.2 Problèmes de connectivité

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

### 8.3 Problèmes Module 3 - nmap

**Erreur python-nmap: "nmap program was not found in path"**

**Cause:** Le binaire nmap n'est pas installé ou pas dans le PATH.

**Solution:**
```bash
# Linux
sudo apt install nmap
which nmap  # Vérifier présence

# Windows
winget install Insecure.Nmap
nmap --version  # Vérifier présence
```

**Erreur: "Permission denied" lors du scan**

**Cause:** Scan SYN stealth nécessite privilèges élevés.

**Solution:**
```bash
# Linux - Utiliser sudo
sudo python src/module3_audit.py

# Ou configurer capabilities (recommandé)
sudo setcap cap_net_raw,cap_net_admin+eip $(which nmap)

# Windows - Lancer PowerShell en Administrateur
```

**Erreur: "Timeout during scan"**

**Cause:** Réseau lent ou pare-feu bloquant les paquets.

**Solution:**
```bash
# Augmenter le timeout dans ntl_config.json
{
  "module3_audit": {
    "nmap_timeout": 600,  # 10 minutes au lieu de 5
    "detection_timeout": 5  # 5 secondes au lieu de 3
  }
}
```

### 8.4 Problèmes de permissions

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
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("administrateur", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl C:\ntl-systoolbox $acl
```

### 8.5 Logs et debug

**Activation du mode debug:**

**Linux:**
```bash
export NTL_DEBUG=1
python src/module3_audit.py 2>&1 | tee debug.log
```

**Windows:**
```powershell
$env:NTL_DEBUG = "1"
python src\module3_audit.py 2>&1 | Tee-Object debug.log
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
