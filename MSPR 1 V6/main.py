#!/usr/bin/env python3
# main.py → Interface globale
import subprocess
import sys

def main():
    print("NTL-SysToolbox")
    print("[1] Module 1 Diagnostic → python module_diagnostic.py --menu")
    print("[2] Module 2 Sauvegarde → python module2_wms_backup.py")
    choice = input("Choix: ")
    if choice == "1":
        subprocess.run([sys.executable, "module_diagnostic.py", "--menu"])
    elif choice == "2":
        subprocess.run([sys.executable, "module2_wms_backup.py"])

if __name__ == "__main__":
    main()
