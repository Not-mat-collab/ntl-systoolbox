from .config import load_config
from . import diagnostic, backup_wms, audit_obsolescence
from .utils import ExitCode

def main_cli():
    cfg = load_config()

    while True:
        print("\n=== NTL-SysToolbox ===")
        print("1) Module Diagnostic")
        print("2) Module Sauvegarde WMS")
        print("3) Module Audit d'obsolescence")
        print("0) Quitter")

        choice = input("Votre choix: ").strip()

        if choice == "1":
            run_diagnostic_menu(cfg)
        elif choice == "2":
            run_backup_menu(cfg)
        elif choice == "3":
            run_audit_menu(cfg)
        elif choice == "0":
            break
        else:
            print("Choix invalide.")

def run_diagnostic_menu(cfg: dict):
    print("\n--- Diagnostic ---")
    print("1) Vérifier AD/DNS")
    print("2) Tester base MySQL")
    print("3) Etat serveur Windows")
    print("4) Etat serveur Ubuntu")

    choice = input("Votre choix: ").strip()
    if choice == "1":
        exit_code = diagnostic.check_ad_dns(cfg)
    elif choice == "2":
        exit_code = diagnostic.check_mysql(cfg)
    elif choice == "3":
        server = input("Nom/IP serveur Windows: ").strip()
        exit_code = diagnostic.check_windows_server(cfg, server)
    elif choice == "4":
        server = input("Nom/IP serveur Ubuntu: ").strip()
        exit_code = diagnostic.check_ubuntu_server(cfg, server)
    else:
        print("Choix invalide.")
        return

    raise SystemExit(exit_code)

def run_backup_menu(cfg: dict):
    print("\n--- Sauvegarde WMS ---")
    print("1) Sauvegarde complète base WMS (SQL)")
    print("2) Export d'une table en CSV")

    choice = input("Votre choix: ").strip()
    if choice == "1":
        exit_code = backup_wms.full_backup(cfg)
    elif choice == "2":
        table = input("Nom de la table: ").strip()
        exit_code = backup_wms.export_table_csv(cfg, table)
    else:
        print("Choix invalide.")
        return

    raise SystemExit(exit_code)

def run_audit_menu(cfg: dict):
    print("\n--- Audit d'obsolescence ---")
    print("1) Scan plage réseau + découverte OS")
    print("2) Lister versions / EOL pour un OS")
    print("3) Analyser un CSV de composants (OS / version)")

    choice = input("Votre choix: ").strip()
    if choice == "1":
        subnet = input("Plage (ex: 10.5.60.0/24) [ENTER = config]: ").strip() or cfg["audit"]["subnet"]
        exit_code = audit_obsolescence.scan_subnet(cfg, subnet)
    elif choice == "2":
        os_name = input("Nom OS (ex: Windows Server, Ubuntu): ").strip()
        exit_code = audit_obsolescence.list_os_eol(cfg, os_name)
    elif choice == "3":
        csv_path = input("Chemin du CSV à analyser: ").strip()
        exit_code = audit_obsolescence.audit_from_csv(cfg, csv_path)
    else:
        print("Choix invalide.")
        return

    raise SystemExit(exit_code)
