#!/usr/bin/env python3
"""
NTL-SysToolbox - Interface principale allégée
Garde config JSON + menu global → dispatch vers modules autonomes
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime

CONFIG_FILE = Path("ntl_config.json")

class NTLConfig:
    """Gestionnaire config (extrait de l'original)"""
    
    DEFAULT_CONFIG = {
        "infrastructure": {
            "dc01_ip": "192.168.10.10",
            "dc02_ip": "192.168.10.11",
            "wms_db_host": "192.168.10.21",
            "wms_db_port": 3306,
            "wms_db_user": "ntlsystoolbox",
            "wms_db_pass": "",
            "windows_default_user": "Administrator",
            "ubuntu_default_user": "admin",
        },
        "module2_wms": {
            "db_name": "wms",
            "db_host": "10.5.60.20",
            "db_port": 3306,
            "db_user": "wms_user",
            "table_to_export": "stock_moves",
            "backup_dir": "backups",
        },
    }
    
    @classmethod
    def load(cls):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    data = json.load(f)
                cfg = json.loads(json.dumps(cls.DEFAULT_CONFIG))
                for section, value in data.items():
                    if isinstance(value, dict) and section in cfg:
                        cfg[section].update(value)
                return cfg
            except:
                pass
        return json.loads(json.dumps(cls.DEFAULT_CONFIG))
    
    @classmethod
    def setup(cls):
        print("\n" + "="*70)
        print("CONFIGURATION NTL-SysToolbox")
        print("="*70)
        config = cls.load()
        infra = config["infrastructure"]
        m2 = config["module2_wms"]
        
        # Inputs interactifs (même logique originale)
        print("\nServeurs AD/DNS:")
        infra["dc01_ip"] = input(f"DC01 [{infra['dc01_ip']}]: ").strip() or infra["dc01_ip"]
        infra["dc02_ip"] = input(f"DC02 [{infra['dc02_ip']}]: ").strip() or infra["dc02_ip"]
        
        print("\nMySQL WMS:")
        infra["wms_db_host"] = input(f"Hôte [{infra['wms_db_host']}]: ").strip() or infra["wms_db_host"]
        port = input(f"Port [{infra['wms_db_port']}]: ").strip()
        if port: infra["wms_db_port"] = int(port)
        infra["wms_db_user"] = input(f"User [{infra['wms_db_user']}]: ").strip() or infra["wms_db_user"]
        infra["wms_db_pass"] = input("Mot de passe: ").strip()
        
        print("\nUsers défaut:")
        infra["windows_default_user"] = input(f"Windows [{infra['windows_default_user']}]: ").strip() or infra["windows_default_user"]
        infra["ubuntu_default_user"] = input(f"Ubuntu [{infra['ubuntu_default_user']}]: ").strip() or infra["ubuntu_default_user"]
        
        print("\nModule 2 WMS:")
        m2["db_host"] = input(f"Hôte [{m2['db_host']}]: ").strip() or m2["db_host"]
        p2 = input(f"Port [{m2['db_port']}]: ").strip()
        if p2: m2["db_port"] = int(p2)
        m2["db_user"] = input(f"User [{m2['db_user']}]: ").strip() or m2["db_user"]
        m2["table_to_export"] = input(f"Table [{m2['table_to_export']}]: ").strip() or m2["table_to_export"]
        m2["backup_dir"] = input(f"Dossier [{m2['backup_dir']}]: ").strip() or m2["backup_dir"]
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Config sauvée: {CONFIG_FILE}")
        return config

class MainCLI:
    def __init__(self):
        self.config = NTLConfig.load()
        self._setup_backups()
    
    def _setup_backups(self):
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)
    
    def _clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")
    
    def _banner(self):
        self._clear_screen()
        print("=" * 70)
        print(" NTL-SysToolbox v2.9.0")
        print(f" Config: {self.config['infrastructure']['wms_db_host']}")
        print("=" * 70)
        print()
    
    def main_menu(self):
        while True:
            self._banner()
            print("MENU PRINCIPAL")
            print("-" * 70)
            print("  [1] Module 1 - Diagnostic (menu autonome)")
            print("  [2] Module 2 - Sauvegarde WMS")
            print("  [3] Module 3 - Audit (À venir)")
            print("  [C] Configuration JSON")
            print("  [0] Quitter")
            print("-" * 70)
            
            choice = input("Choix: ").strip().upper()
            
            if choice == "0":
                print("\nAu revoir!")
                sys.exit(0)
            elif choice == "C":
                self.config = NTLConfig.setup()
            elif choice == "1":
                # Lance menu Module1 autonome
                subprocess.run([sys.executable, "module_diagnostic.py", "--menu"])
            elif choice == "2":
                # Module2 avec config
                self._run_module2()
            elif choice == "3":
                print("\n[!] Module 3 non implémenté.")
                input("Entrée...")
            else:
                print("\n[!] Option invalide.")
                input("Entrée...")
    
    def _run_module2(self):
        """Lance module2 avec config injectée"""
        self._banner()
        m2 = self.config.get("module2_wms", {})
        print("MODULE 2 - SAUVEGARDE WMS")
        print(f"Hôte: {m2['db_host']}:{m2['db_port']} | User: {m2['db_user']}")
        print(f"Table: {m2['table_to_export']} | Dossier: {m2['backup_dir']}")
        
        if input("\nLancer? (o/n) [o]: ").strip().lower() != "n":
            # Injecte config via variables d'environnement (ou args si module2 CLI)
            env = os.environ.copy()
            env.update({
                'WMS_DB_HOST': m2['db_host'],
                'WMS_DB_PORT': str(m2['db_port']),
                'WMS_DB_USER': m2['db_user'],
                'WMS_DB_NAME': m2['db_name'],
                'WMS_TABLE_EXPORT': m2['table_to_export'],
                'WMS_BACKUP_DIR': m2['backup_dir']
            })
            result = subprocess.run([sys.executable, "module2_wms_backup.py"], 
                                  env=env, capture_output=True, text=True)
            print(result.stdout)
            if result.stderr: print("ERREUR:", result.stderr)
            print(f"Code: {result.returncode}")
        input("\nEntrée...")

def main():
    app = MainCLI()
    app.main_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterruption.")
        sys.exit(0)