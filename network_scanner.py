from scapy.all import ARP, Ether, srp
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests

# Get MAC vendor info using macvendors.co API
def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return "Unknown"
    return "Unknown"

# Scan the network and get devices
def scan_network(network_range, result_tree):
    result_tree.delete(*result_tree.get_children())
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=2, verbose=0)[0]
    except PermissionError:
        messagebox.showerror("Permission Error", "You need to run this script as administrator/root.")
        return

    for sent, received in result:
        mac = received.hwsrc
        vendor = get_vendor(mac)
        result_tree.insert("", "end", values=(received.psrc, mac, vendor))

# UI setup
def start_scan(entry, tree):
    network_range = entry.get()
    if not network_range:
        messagebox.showwarning("Input Error", "Please enter a network range, e.g. 192.168.1.0/24")
        return
    threading.Thread(target=scan_network, args=(network_range, tree), daemon=True).start()

root = tk.Tk()
root.title("Wi-Fi Device Scanner")
root.geometry("600x400")

frame = tk.Frame(root)
frame.pack(pady=10)

label = tk.Label(frame, text="Enter Network Range (e.g., 192.168.1.0/24):")
label.pack(side=tk.LEFT)

entry = tk.Entry(frame, width=20)
entry.pack(side=tk.LEFT, padx=5)
entry.insert(0, "192.168.1.0/24")

scan_button = tk.Button(frame, text="Scan", command=lambda: start_scan(entry, tree))
scan_button.pack(side=tk.LEFT)

columns = ("IP Address", "MAC Address", "Vendor")
tree = ttk.Treeview(root, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=180)

tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

root.mainloop()
