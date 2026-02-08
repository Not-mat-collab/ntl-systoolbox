!/usr/bin/env python3
"""
NTL-SysToolbox - Outil de diagnostic et gestion pour Nord Transit Logistics
Interface CLI avec CONFIGURATION INFRASTRUCTURE
Module 1 + Module 2 (wrapper sans modification du module2)
"""

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# S'assurer que le répertoire du script est dans sys.path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Importer le module diagnostic (Module 1)
try:
    from module_diagnostic import DiagnosticModule
except ImportError:
    print("ERREUR: Le module 'module_diagnostic.py' doit être dans le même répertoire")
    sys.exit(1)

# Importer le module 2 (sans modification)
try:
    import module2_wms_backup
except ImportError:
    print("ERREUR: Le module 'module2_wms_backup.py' doit être dans le même répertoire")
    sys.exit(1)

CONFIG_FILE = Path("ntl_config.json")


class NTLConfig:
    """Gestionnaire de configuration infrastructure"""

    DEFAULT_CONFIG = {
        "infrastructure": {
            "dc01_ip": "192.168.10.10",
            "dc02_ip": "192.168.10.11",
            "wms_db_host": "192.168.10.21",
            "wms_db_port": 3306,
            "wms_db_user": "ntlsystoolbox",
            "wms_db_pass": "",
            "wms_db_ssl": False,
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
                cfg = json.loads(json.dumps(cls.DEFAULT_CONFIG))  # deep copy
                for section, value in data.items():
                    if isinstance(value, dict) and section in cfg:
                        cfg[section].update(value)
                    else:
                        cfg[section] = value
                return cfg
            except Exception:
                pass
        return json.loads(json.dumps(cls.DEFAULT_CONFIG))

    @classmethod
    def save(cls, config):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"✓ Configuration sauvegardée dans {CONFIG_FILE}")

    @classmethod
    def setup(cls):
        print("\n" + "="*70)
        print("CONFIGURATION INFRASTRUCTURE NTL")
        print("="*70)

        config = cls.load()
        infra = config["infrastructure"]
        m2 = config["module2_wms"]

        print("\nServeurs AD/DNS (Contrôleurs de domaine)")
        infra["dc01_ip"] = input(f"DC01 IP [{infra['dc01_ip']}]: ").strip() or infra["dc01_ip"]
        infra["dc02_ip"] = input(f"DC02 IP [{infra['dc02_ip']}]: ").strip() or infra["dc02_ip"]

        print("\nServeur WMS-DB (MySQL)")
        infra["wms_db_host"] = input(f"Hôte MySQL [{infra['wms_db_host']}]: ").strip() or infra["wms_db_host"]
        port = input(f"Port MySQL [{infra['wms_db_port']}]: ").strip()
        if port:
            infra["wms_db_port"] = int(port)
        infra["wms_db_user"] = input(f"Utilisateur MySQL [{infra['wms_db_user']}]: ").strip() or infra["wms_db_user"]
        infra["wms_db_pass"] = input("Mot de passe MySQL (vide si aucun): ").strip()
        ssl = input("SSL/TLS MySQL ? (o/n) [n]: ").strip().lower()
        infra["wms_db_ssl"] = ssl == "o"

        print("\nUtilisateurs par défaut")
        infra["windows_default_user"] = input(f"User Windows [{infra['windows_default_user']}]: ").strip() or infra["windows_default_user"]
        infra["ubuntu_default_user"] = input(f"User Ubuntu [{infra['ubuntu_default_user']}]: ").strip() or infra["ubuntu_default_user"]

        print("\nModule 2 - Sauvegarde WMS")
        m2["db_host"] = input(f"Hôte WMS [{m2['db_host']}]: ").strip() or m2["db_host"]
        p2 = input(f"Port WMS [{m2['db_port']}]: ").strip()
        if p2:
            m2["db_port"] = int(p2)
        m2["db_user"] = input(f"User WMS [{m2['db_user']}]: ").strip() or m2["db_user"]
        m2["table_to_export"] = input(f"Table exporter [{m2['table_to_export']}]: ").strip() or m2["table_to_export"]
        m2["backup_dir"] = input(f"Dossier backups [{m2['backup_dir']}]: ").strip() or m2["backup_dir"]

        cls.save(config)
        return config


class NTLSysToolboxCLI:
    def __init__(self):
        self.version = "2.1.0-CONFIG"
        self.backup_base_dir = "backups"
        self.backup_folders = {
            'ad_dns': os.path.join(self.backup_base_dir, 'ad_dns'),
            'mysql': os.path.join(self.backup_base_dir, 'mysql'),
            'windows': os.path.join(self.backup_base_dir, 'windows'),
            'ubuntu': os.path.join(self.backup_base_dir, 'ubuntu'),
            'global': os.path.join(self.backup_base_dir, 'global'),
        }
        self.current_diagnostic = None
        self.current_diagnostic_type = None
        self.config = NTLConfig.load()
        self.setup_backup_folders()

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def banner(self):
        print("=" * 70)
        print(f" NTL-SysToolbox v{self.version}")
        print(" Nord Transit Logistics - Diagnostic CLI")
        print(f" Config: {self.config['infrastructure']['wms_db_host']} (modif: [C])")
        print("=" * 70)
        print()

    def pause(self):
        input("\nAppuyez sur Entrée pour continuer...")

    def setup_backup_folders(self):
        if not os.path.exists(self.backup_base_dir):
            os.makedirs(self.backup_base_dir)
        for _, folder_path in self.backup_folders.items():
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

    def save_results_auto(self):
        if not self.current_diagnostic:
            print("\n[!] Aucun résultat à sauvegarder.")
            return
        backup_folder = self.backup_folders.get(self.current_diagnostic_type, self.backup_base_dir)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"{self.current_diagnostic_type}_{timestamp}"
        json_filename = os.path.join(backup_folder, f"{base_filename}.json")
        txt_filename = os.path.join(backup_folder, f"{base_filename}.txt")
        try:
            with open(json_filename, "w", encoding="utf-8") as f:
                f.write(self.current_diagnostic.get_results_json())
            with open(txt_filename, "w", encoding="utf-8") as f:
                f.write(self.current_diagnostic.get_results_human())
            print("\n✓ Résultats sauvegardés:")
            print(f"  JSON: {json_filename}")
            print(f"  TXT:  {txt_filename}")
        except Exception as e:
            print(f"\n[!] Erreur sauvegarde: {e}")

    def main_menu(self):
        while True:
            self.clear_screen()
            self.banner()
            print("MENU PRINCIPAL")
            print("-" * 70)
            print("  [1] Module 1 - Diagnostic")
            print("  [2] Module 2 - Sauvegarde WMS")
            print("  [3] Module 3 - Audit d'obsolescence (À venir)")
            print("  [C] Configuration infrastructure")
            print("  [0] Quitter")
            print("-" * 70)
            choice = input("Sélectionnez une option : ").strip().upper()

            if choice == "0":
                print("\nFermeture...")
                sys.exit(0)
            elif choice == "C":
                self.config = NTLConfig.setup()
            elif choice == "1":
                self.menu_diagnostic()
            elif choice == "2":
                self.run_module2_wms()
            elif choice == "3":
                print("\n[!] Module non implémenté.")
                self.pause()
            else:
                print("\n[!] Option invalide.")
                self.pause()

    def run_module2_wms(self):
        """Lance module2_wms_backup.main() avec surcharge des constantes depuis config."""
        self.clear_screen()
        self.banner()
        m2 = self.config.get("module2_wms", {})
        print("MODULE 2 - SAUVEGARDE WMS")
        print("-" * 70)
        print(f"Hôte WMS : {m2.get('db_host','10.5.60.20')}:{m2.get('db_port',3306)}")
        print(f"User WMS : {m2.get('db_user','wms_user')}")
        print(f"Table    : {m2.get('table_to_export','stock_moves')}")
        print(f"Dossier  : {m2.get('backup_dir','backups')}")
        print("-" * 70)
        if input("Lancer la sauvegarde WMS ? (o/n) [o] : ").strip().lower() == "n":
            return

        # Surcharge les constantes du module2 depuis la config
        module2_wms_backup.DB_HOST = m2.get('db_host', '10.5.60.20')
        module2_wms_backup.DB_PORT = m2.get('db_port', 3306)
        module2_wms_backup.DB_USER = m2.get('db_user', 'wms_user')
        module2_wms_backup.DB_NAME = m2.get('db_name', 'wms')
        module2_wms_backup.BACKUP_DIR = m2.get('backup_dir', 'backups')
        module2_wms_backup.TABLE_TO_EXPORT = m2.get('table_to_export', 'stock_moves')

        print("\n[+] Lancement Module 2...")
        try:
            # Lance ton module2.main() inchangé
            exit_code = module2_wms_backup.main()
            print(f"\n✓ Module 2 terminé (code: {exit_code})")
        except Exception as e:
            print(f"\n[!] Erreur Module 2: {e}")
            exit_code = 1
        self.pause()

    def menu_diagnostic(self):
        while True:
            self.clear_screen()
            self.banner()
            print("MODULE 1 - DIAGNOSTIC SYSTÈME")
            print("-" * 70)
            print(f"  [1] AD/DNS DC01 ({self.config['infrastructure']['dc01_ip']})")
            print(f"  [2] AD/DNS DC02 ({self.config['infrastructure']['dc02_ip']})")
            print(f"  [3] MySQL WMS ({self.config['infrastructure']['wms_db_host']}:{self.config['infrastructure']['wms_db_port']})")
            print("  [4] Diagnostic Windows (local ou distant)")
            print("  [5] Diagnostic Ubuntu/Linux (local ou distant)")
            print("  [6] Diagnostic global NTL")
            print("  [S] Sauvegarder dernier résultat")
            print("  [0] Retour")
            print("-" * 70)
            choice = input("Sélectionnez une option : ").strip().upper()

            if choice == "0":
                break
            elif choice == "1":
                self.cli_check_ad_dns(self.config["infrastructure"]["dc01_ip"])
            elif choice == "2":
                self.cli_check_ad_dns(self.config["infrastructure"]["dc02_ip"])
            elif choice == "3":
                self.cli_check_mysql_config()
            elif choice == "4":
                self.cli_check_windows()
            elif choice == "5":
                self.cli_check_ubuntu()
            elif choice == "6":
                self.cli_diagnostic_global()
            elif choice == "S":
                self.save_results_auto()
                self.pause()
            else:
                print("\n[!] Option invalide.")
                self.pause()

    def cli_check_ad_dns(self, ip):
        self.clear_screen()
        self.banner()
        print(f"VÉRIFICATION AD/DNS sur {ip}")
        print("-" * 70)
        print("\n[+] Analyse en cours...")
        diag = DiagnosticModule()
        diag.check_ad_dns_service(ip)
        self.current_diagnostic = diag
        self.current_diagnostic_type = "ad_dns"
        print(diag.get_results_human())
        self.pause()

    def cli_check_mysql_config(self):
        self.clear_screen()
        self.banner()
        print("TEST MYSQL WMS (Configuration sauvegardée)")
        print("-" * 70)
        infra = self.config["infrastructure"]
        print(f"Host: {infra['wms_db_host']}:{infra['wms_db_port']}")
        print(f"User: {infra['wms_db_user']}")
        print(f"SSL: {'Oui' if infra['wms_db_ssl'] else 'Non'}")
        override_pass = input("Mot de passe MySQL (Entrée pour config) : ").strip()
        password = override_pass if override_pass else infra.get("wms_db_pass", "")
        print("\n[+] Connexion en cours...")
        diag = DiagnosticModule()
        diag.check_mysql_database(
            infra["wms_db_host"],
            infra["wms_db_port"],
            None,
            infra["wms_db_user"],
            password,
            infra["wms_db_ssl"]
        )
        self.current_diagnostic = diag
        self.current_diagnostic_type = "mysql"
        print(diag.get_results_human())
        self.pause()

    def cli_check_windows(self):
        self.clear_screen()
        self.banner()
        print("DIAGNOSTIC WINDOWS")
        print("-" * 70)
        infra = self.config["infrastructure"]
        remote_ip = input(f"IP serveur (Entrée=local) : ").strip()
        if remote_ip:
            user = input(f"User [{infra['windows_default_user']}] : ").strip()
            if not user:
                user = infra["windows_default_user"]
            password = input("Mot de passe : ").strip()
        else:
            user = password = None
        print("\n[+] Diagnostic en cours...")
        diag = DiagnosticModule()
        diag.check_windows_server(None, remote_ip or None, user, password)
        self.current_diagnostic = diag
        self.current_diagnostic_type = "windows"
        print(diag.get_results_human())
        self.pause()

    def cli_check_ubuntu(self):
        self.clear_screen()
        self.banner()
        print("DIAGNOSTIC UBUNTU/LINUX")
        print("-" * 70)
        infra = self.config["infrastructure"]
        remote_ip = input(f"IP serveur (Entrée=local) : ").strip()
        if remote_ip:
            user = input(f"User SSH [{infra['ubuntu_default_user']}] : ").strip()
            if not user:
                user = infra["ubuntu_default_user"]
            password = input("Mot de passe SSH : ").strip()
        else:
            user = password = None
        print("\n[+] Diagnostic en cours...")
        diag = DiagnosticModule()
        diag.check_ubuntu_server(None, remote_ip or None, user, password)
        self.current_diagnostic = diag
        self.current_diagnostic_type = "ubuntu"
        print(diag.get_results_human())
        self.pause()

    def cli_diagnostic_global(self):
        self.clear_screen()
        self.banner()
        print("DIAGNOSTIC GLOBAL NTL")
        print("-" * 70)
        print("Vérification complète :")
        print(f"  DC01: {self.config['infrastructure']['dc01_ip']}")
        print(f"  DC02: {self.config['infrastructure']['dc02_ip']}")
        print(f"  MySQL: {self.config['infrastructure']['wms_db_host']}")
        print("  Serveur local")
        if input("\nContinuer ? (o/n) [o] : ").strip().lower() != "n":
            print("\n[+] Diagnostic global en cours...")
            diag = DiagnosticModule()
            diag.check_ad_dns_service(self.config["infrastructure"]["dc01_ip"])
            diag.check_ad_dns_service(self.config["infrastructure"]["dc02_ip"])
            diag.check_mysql_database(
                self.config["infrastructure"]["wms_db_host"],
                self.config["infrastructure"]["wms_db_port"],
                None,
                self.config["infrastructure"]["wms_db_user"],
                self.config["infrastructure"]["wms_db_pass"],
                self.config["infrastructure"]["wms_db_ssl"]
            )
            import platform
            if platform.system() == "Windows":
                diag.check_windows_server()
            else:
                diag.check_ubuntu_server()
            self.current_diagnostic = diag
            self.current_diagnostic_type = "global"
            print(diag.get_results_human())
        self.pause()


def main():
    app = NTLSysToolboxCLI()
    app.main_menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterruption utilisateur.")
        sys.exit(0)
    except Exception as e:
        print(f"\nERREUR : {e}")
        sys.exit(1)
