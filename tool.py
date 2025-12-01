import tkinter as tk
from tkinter import scrolledtext, ttk
import Arp_poisening
import ipaddress
import socket
import re
import uuid
import threading


class AttackGUI:
    def __init__(self, root):
        self.root = root
        root.title("Attack Toolkit")

        # Input Fields
        tk.Label(root, text="Victim IP: (optional)").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.victim_entry = tk.Entry(root, width=25)
        self.victim_entry.grid(row=0, column=1, padx=5, pady=5)

        # Attack Selection
        tk.Label(root, text="Select Attack:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        self.attack_choice = ttk.Combobox(
            root,
            values=["ARP Poisoning", "DNS Spoofing", "MITM (With SSL stripping)"],
            state="readonly",
            width=23
        )
        self.attack_choice.grid(row=2, column=1, padx=5, pady=5)
        self.attack_choice.current(0)
        self.attack_choice.bind("<<ComboboxSelected>>", self.update_attack_options)

        # ARP Options 
        self.arp_frame = tk.Frame(root)

        tk.Label(self.arp_frame, text="ARP Mode:").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.arp_mode = ttk.Combobox(
            self.arp_frame,
            values=["silent", "all-out"],
            state="readonly",
            width=20
        )
        self.arp_mode.grid(row=0, column=1, padx=5, pady=3)
        self.arp_mode.current(1)

        # Spoof MAC
        tk.Label(self.arp_frame, text="Spoof As MAC:").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        self.spoof_entry = tk.Entry(self.arp_frame, width=23)
        self.spoof_entry.grid(row=1, column=1, padx=5, pady=3)
        self.spoof_entry.insert(0, self.get_attacker_mac())

        # Start Button
        self.btn_start = tk.Button(root, text="Start Attack", command=self.start_attack)
        self.btn_start.grid(row=3, column=0, columnspan=2, sticky="we", padx=5, pady=10)

        # Packet Log
        tk.Label(root, text="Packet Log:").grid(row=4, column=0, columnspan=2)
        self.log_area = scrolledtext.ScrolledText(root, width=70, height=18)
        self.log_area.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

        # Initially show ARP options since default is ARP
        self.update_attack_options()

    # Thread-safe Logging
    def log(self, text):
        self.root.after(0, lambda: (
            self.log_area.insert(tk.END, text + "\n"),
            self.log_area.see(tk.END)
        ))

    # IP validation
    def is_valid_ip(self, ip):
        ip = ip.strip()
        if ip == "":
            return True
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    # MAC validation
    def is_valid_mac(self, mac):
        mac = mac.strip()
        if mac == "":
            return True
        return re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac) is not None

    def validate_inputs(self):
        victim = self.victim_entry.get().strip()

        if not self.is_valid_ip(victim):
            self.log(f"ERROR: Invalid victim IP '{victim}'.")
            return False

        if self.attack_choice.get() == "ARP Poisoning":
            spoof_mac = self.spoof_entry.get().strip()
            if not self.is_valid_mac(spoof_mac):
                self.log(f"ERROR: Invalid spoof-as MAC '{spoof_mac}'.")
                return False

        return True

    def get_ip_or_none(self, txt):
        txt = txt.strip()
        return txt if txt != "" else None

    def get_attacker_mac(self):
        try:
            mac = uuid.getnode()
            return ':'.join(f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8))
        except:
            return "00:00:00:00:00:00"

    # attack options
    def update_attack_options(self, event=None):
        attack = self.attack_choice.get()
        self.arp_frame.grid_forget()

        if attack == "ARP Poisoning":
            self.arp_frame.grid(row=2, column=2, rowspan=2, padx=10)

    def start_attack(self):
        if not self.validate_inputs():
            return

        victim = self.get_ip_or_none(self.victim_entry.get())
        attack = self.attack_choice.get()

        # Worker thread for running attacks
        def worker():
            if attack == "ARP Poisoning":
                mode = self.arp_mode.get()
                spoof_mac = self.spoof_entry.get().strip()

                self.log("Starting ARP poisoning:")
                self.log(f"  Victim:    {victim}")
                self.log(f"  Mode:      {mode}")
                self.log(f"  Spoof As:  {spoof_mac}")

                Arp_poisening.arp_poisoning(
                    victim,
                    spoof_as_mac=spoof_mac,
                    mode=mode,
                    logger=self.log
                )

            elif attack == "DNS Spoofing":
                self.log(f"Starting DNS spoofing: Victim={victim}")
                # call DNS spoofing

            elif attack == "MITM (With SSL stripping)":
                self.log(f"Starting SSL stripping: Victim={victim}")
                # call SSL stripping

        # Start thread
        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    gui = AttackGUI(root)
    root.mainloop()