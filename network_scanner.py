#!/usr/bin/env python3
"""
WiFi Network Scanner with Device Blocking
Simplified version with blocking functionality.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import socket
import platform
import re
from concurrent.futures import ThreadPoolExecutor
import time
import json
import os


class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.blocked_devices = self.load_blocked_devices()
        self.local_ip = self.get_local_ip()
        self.network_base = '.'.join(self.local_ip.split('.')[:-1])

    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.100"

    def load_blocked_devices(self):
        """Load blocked devices from file"""
        try:
            if os.path.exists('blocked_devices.json'):
                with open('blocked_devices.json', 'r') as f:
                    return set(json.load(f))
        except:
            pass
        return set()

    def save_blocked_devices(self):
        """Save blocked devices to file"""
        try:
            with open('blocked_devices.json', 'w') as f:
                json.dump(list(self.blocked_devices), f)
        except Exception as e:
            print(f"Error saving blocked devices: {e}")

    def ping_host(self, ip):
        """Check if host responds to ping with multiple attempts"""
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "2", "-w", "2000", ip]  # 2 pings, 2 second timeout
            else:
                cmd = ["ping", "-c", "2", "-W", "2", ip]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            print(f"Ping error for {ip}: {e}")
            return False

    def check_port_scan(self, ip):
        """Quick port scan to detect devices that don't respond to ping"""
        common_ports = [22, 23, 53, 80, 135, 139, 443, 445, 8080]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:  # Port is open
                    return True
            except:
                continue
        return False

    def scan_arp_table(self):
        """Scan existing ARP table for known devices"""
        devices = []
        try:
            system = platform.system().lower()
            if system == "windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    # Look for lines with IP and MAC
                    if re.search(r'\d+\.\d+\.\d+\.\d+', line) and re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', line,
                                                                            re.I):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac_match = re.search(r'([0-9a-f]{2}[:-]){5}[0-9a-f]{2}', line, re.I)
                            if mac_match and ip.startswith(self.network_base):
                                mac = mac_match.group(0).replace('-', ':').upper()
                                devices.append({'ip': ip, 'mac': mac})
            else:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 4 and ':' in parts[3]:
                        ip = parts[1].strip('()')
                        mac = parts[3].upper()
                        if ip.startswith(self.network_base):
                            devices.append({'ip': ip, 'mac': mac})
        except Exception as e:
            print(f"ARP table scan error: {e}")

        return devices

    def get_device_info(self, ip):
        """Get device hostname and MAC"""
        hostname = f"Device-{ip.split('.')[-1]}"
        mac = "Unknown"

        # Get hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        # Get MAC address using ARP
        try:
            system = platform.system().lower()
            if system == "windows":
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=5)
                # Look for MAC address pattern in ARP output
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', line, re.I)
                        if mac_match:
                            mac = mac_match.group(0).replace('-', ':').upper()
                            break
            else:
                # For Linux/Mac
                result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and ':' in parts[2]:
                        mac = parts[2].upper()
                        break
        except Exception as e:
            print(f"ARP lookup error for {ip}: {e}")

        return hostname, mac

    def get_device_type(self, hostname):
        """Determine device type from hostname"""
        hostname_lower = hostname.lower()
        if any(word in hostname_lower for word in ['router', 'gateway']):
            return "Router"
        elif any(word in hostname_lower for word in ['phone', 'iphone', 'android']):
            return "Phone"
        elif any(word in hostname_lower for word in ['laptop', 'pc', 'computer']):
            return "Computer"
        elif any(word in hostname_lower for word in ['tv', 'roku', 'chromecast']):
            return "Media"
        return "Unknown"

    def scan_ip(self, ip):
        """Scan single IP address with multiple detection methods"""
        is_alive = False

        # Method 1: Try ping first
        if self.ping_host(ip):
            is_alive = True
        # Method 2: If ping fails, try port scanning
        elif self.check_port_scan(ip):
            is_alive = True

        if is_alive:
            hostname, mac = self.get_device_info(ip)
            return {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'type': self.get_device_type(hostname),
                'status': 'Blocked' if mac in self.blocked_devices else 'Online'
            }
        return None

    def scan_network(self, progress_callback=None):
        """Scan entire network using multiple methods"""
        self.devices = []
        found_ips = set()

        # Method 1: Quick ARP table scan for known devices
        print("Scanning ARP table for known devices...")
        arp_devices = self.scan_arp_table()
        for arp_device in arp_devices:
            ip = arp_device['ip']
            if ip not in found_ips:
                hostname, _ = self.get_device_info(ip)  # Get fresh hostname
                device = {
                    'ip': ip,
                    'hostname': hostname,
                    'mac': arp_device['mac'],
                    'type': self.get_device_type(hostname),
                    'status': 'Blocked' if arp_device['mac'] in self.blocked_devices else 'Online'
                }
                self.devices.append(device)
                found_ips.add(ip)
                if progress_callback:
                    progress_callback(device)

        print(f"Found {len(arp_devices)} devices in ARP table")

        # Method 2: Full network scan for remaining IPs
        print("Performing full network scan...")

        def scan_range(start, end):
            local_devices = []
            for i in range(start, end + 1):
                ip = f"{self.network_base}.{i}"
                if ip not in found_ips:  # Skip already found IPs
                    device = self.scan_ip(ip)
                    if device:
                        local_devices.append(device)
                        found_ips.add(ip)
                        if progress_callback:
                            progress_callback(device)
            return local_devices

        # Scan remaining IPs in chunks
        with ThreadPoolExecutor(max_workers=15) as executor:
            chunk_size = 20
            futures = []

            for start in range(1, 255, chunk_size):
                end = min(start + chunk_size - 1, 254)
                futures.append(executor.submit(scan_range, start, end))

            # Collect results from all chunks
            for future in futures:
                try:
                    chunk_devices = future.result(timeout=45)
                    self.devices.extend(chunk_devices)
                except Exception as e:
                    print(f"Error in scan chunk: {e}")

        # Method 3: Re-scan common device IPs that might have been missed
        common_ips = [1, 2, 10, 100, 101, 150, 200, 254]  # Common router/device IPs
        print("Re-scanning common device IPs...")

        for ip_suffix in common_ips:
            ip = f"{self.network_base}.{ip_suffix}"
            if ip not in found_ips:
                # More aggressive scan for common IPs
                for attempt in range(2):  # Try twice
                    device = self.scan_ip(ip)
                    if device:
                        self.devices.append(device)
                        found_ips.add(ip)
                        if progress_callback:
                            progress_callback(device)
                        break
                    time.sleep(0.5)  # Brief pause between attempts

        self.devices.sort(key=lambda x: int(x['ip'].split('.')[-1]))
        print(f"Total devices found: {len(self.devices)}")
        return self.devices

    def block_device(self, mac_address):
        """Block device by MAC address"""
        if not mac_address or mac_address == "Unknown":
            return False, "Cannot block device without MAC address"

        self.blocked_devices.add(mac_address)
        self.save_blocked_devices()

        # Try to apply actual network blocking
        success = self.apply_router_block(mac_address)

        if success:
            return True, "Device blocked successfully at network level"
        else:
            return True, "Device added to block list. For full blocking, you may need to:\n• Run as administrator/sudo\n• Configure your router manually\n• Check console for blocking attempts"

    def unblock_device(self, mac_address):
        """Unblock device by MAC address"""
        if mac_address in self.blocked_devices:
            self.blocked_devices.remove(mac_address)
            self.save_blocked_devices()

            success = self.apply_router_unblock(mac_address)
            if success:
                return True, "Device unblocked successfully at network level"
            else:
                return True, "Device removed from block list. Check console for unblocking attempts"
        return False, "Device not in blocked list"

    def apply_router_block(self, mac_address):
        """Apply blocking at router level using multiple methods"""
        blocked = False
        methods_tried = []

        # Method 1: Try iptables (Linux/Mac with admin rights)
        try:
            if platform.system() != "Windows":
                # Block by MAC using iptables
                result = subprocess.run([
                    "sudo", "iptables", "-A", "INPUT", "-m", "mac",
                    "--mac-source", mac_address, "-j", "DROP"
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    blocked = True
                    methods_tried.append("iptables")
                else:
                    methods_tried.append("iptables (failed)")
        except Exception as e:
            methods_tried.append(f"iptables (error: {str(e)[:50]})")

        # Method 2: Try Windows netsh (Windows only)
        try:
            if platform.system() == "Windows":
                # Create Windows firewall rule to block MAC
                rule_name = f"Block_{mac_address.replace(':', '_')}"
                result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=in", "action=block",
                    f"remoteip={self.get_ip_by_mac(mac_address)}"
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    blocked = True
                    methods_tried.append("netsh firewall")
                else:
                    methods_tried.append("netsh (failed)")
        except Exception as e:
            methods_tried.append(f"netsh (error: {str(e)[:50]})")

        # Method 3: Try common router web interfaces
        router_ips = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "192.168.2.1"]
        for router_ip in router_ips:
            try:
                # Try to ping router first
                if self.ping_host(router_ip):
                    methods_tried.append(f"router {router_ip} (found but API unknown)")
                    # Note: Actual router blocking would require specific API calls
                    # This varies greatly between router manufacturers
                    break
            except:
                continue

        print(f"Block attempt for {mac_address}: {', '.join(methods_tried)}")
        return blocked

    def apply_router_unblock(self, mac_address):
        """Remove blocking at router level"""
        unblocked = False
        methods_tried = []

        # Method 1: Remove iptables rule (Linux/Mac)
        try:
            if platform.system() != "Windows":
                result = subprocess.run([
                    "sudo", "iptables", "-D", "INPUT", "-m", "mac",
                    "--mac-source", mac_address, "-j", "DROP"
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    unblocked = True
                    methods_tried.append("iptables")
                else:
                    methods_tried.append("iptables (rule not found)")
        except Exception as e:
            methods_tried.append(f"iptables (error: {str(e)[:50]})")

        # Method 2: Remove Windows firewall rule
        try:
            if platform.system() == "Windows":
                rule_name = f"Block_{mac_address.replace(':', '_')}"
                result = subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    unblocked = True
                    methods_tried.append("netsh firewall")
                else:
                    methods_tried.append("netsh (rule not found)")
        except Exception as e:
            methods_tried.append(f"netsh (error: {str(e)[:50]})")

        print(f"Unblock attempt for {mac_address}: {', '.join(methods_tried)}")
        return unblocked

    def get_ip_by_mac(self, mac_address):
        """Find IP address for given MAC address"""
        for device in self.devices:
            if device['mac'] == mac_address:
                return device['ip']
        return None


class WiFiScannerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("WiFi Scanner with Blocking")
        self.root.geometry("1000x650")
        self.scanner = NetworkScanner()
        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title and info
        ttk.Label(main_frame, text="WiFi Network Scanner with Blocking",
                  font=('Arial', 16, 'bold')).pack(pady=(0, 10))

        ttk.Label(main_frame,
                  text=f"Network: {self.scanner.network_base}.1-254 | Local IP: {self.scanner.local_ip}").pack()

        # Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=10)

        self.quick_scan_btn = ttk.Button(control_frame, text="Quick Scan (ARP)", command=self.quick_scan)
        self.quick_scan_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.scan_btn = ttk.Button(control_frame, text="Deep Scan", command=self.start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.status_label = ttk.Label(control_frame, text="Ready")
        self.status_label.pack(side=tk.RIGHT)

        # Device list
        list_frame = ttk.LabelFrame(main_frame, text="Devices", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ('IP', 'Name', 'MAC', 'Type', 'Status')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)

        for col in columns:
            self.tree.heading(col, text=col)

        self.tree.column('IP', width=120)
        self.tree.column('Name', width=200)
        self.tree.column('MAC', width=150)
        self.tree.column('Type', width=100)
        self.tree.column('Status', width=80)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Quick Scan", command=self.quick_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Deep Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Block Device", command=self.block_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Unblock Device", command=self.unblock_device).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy IP", command=self.copy_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Show Blocked", command=self.show_blocked).pack(side=tk.LEFT, padx=5)

        self.count_label = ttk.Label(btn_frame, text="Devices: 0")
        self.count_label.pack(side=tk.RIGHT)

    def quick_scan(self):
        """Quick scan using only ARP table"""
        self.scan_btn.config(state='disabled')
        self.quick_scan_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Quick scanning...")
        self.tree.delete(*self.tree.get_children())

        threading.Thread(target=self.quick_scan_thread, daemon=True).start()

    def quick_scan_thread(self):
        """Quick scan background thread"""
        try:
            print("Starting quick ARP scan...")
            self.scanner.devices = []

            # Only scan ARP table for quick results
            arp_devices = self.scanner.scan_arp_table()
            count = 0

            for arp_device in arp_devices:
                ip = arp_device['ip']
                hostname, _ = self.scanner.get_device_info(ip)
                device = {
                    'ip': ip,
                    'hostname': hostname,
                    'mac': arp_device['mac'],
                    'type': self.scanner.get_device_type(hostname),
                    'status': 'Blocked' if arp_device['mac'] in self.scanner.blocked_devices else 'Online'
                }
                self.scanner.devices.append(device)
                count += 1
                self.root.after(0, lambda d=device: self.add_device(d))
                self.root.after(0, lambda c=count: self.count_label.config(text=f"Devices: {c}"))

            print(f"Quick scan completed. Found {len(arp_devices)} devices.")
            self.root.after(0, self.scan_complete)
        except Exception as e:
            print(f"Quick scan error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Quick scan failed: {e}"))
            self.root.after(0, self.scan_complete)

    def start_scan(self):
        """Start full deep network scan"""
        self.scan_btn.config(state='disabled')
        self.quick_scan_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Deep scanning...")
        self.tree.delete(*self.tree.get_children())

        threading.Thread(target=self.scan_thread, daemon=True).start()

    def scan_thread(self):
        count = 0

        def callback(device):
            nonlocal count
            count += 1
            self.root.after(0, lambda d=device: self.add_device(d))
            self.root.after(0, lambda c=count: self.count_label.config(text=f"Devices: {c}"))

        try:
            print("Starting network scan...")
            devices = self.scanner.scan_network(callback)
            print(f"Scan completed. Found {len(devices)} devices.")
            self.root.after(0, self.scan_complete)
        except Exception as e:
            print(f"Scan error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {e}"))
            self.root.after(0, self.scan_complete)

    def add_device(self, device):
        # Color blocked devices red
        tags = ('blocked',) if device['status'] == 'Blocked' else ()
        self.tree.insert('', 'end', values=(
            device['ip'], device['hostname'], device['mac'],
            device['type'], device['status']
        ), tags=tags)

        # Configure blocked device appearance
        self.tree.tag_configure('blocked', background='#ffcccc')

    def scan_complete(self):
        self.progress.stop()
        self.scan_btn.config(state='normal')
        self.quick_scan_btn.config(state='normal')
        self.status_label.config(text="Scan complete")

    def block_device(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to block.")
            return

        values = self.tree.item(selection[0], 'values')
        mac = values[2]
        name = values[1]

        if messagebox.askyesno("Confirm Block", f"Block device '{name}' ({mac})?"):
            success, message = self.scanner.block_device(mac)
            if success:
                self.tree.set(selection[0], 'Status', 'Blocked')
                self.tree.item(selection[0], tags=('blocked',))
                messagebox.showinfo("Block Status", message)
            else:
                messagebox.showerror("Error", message)

    def unblock_device(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to unblock.")
            return

        values = self.tree.item(selection[0], 'values')
        mac = values[2]
        name = values[1]

        if messagebox.askyesno("Confirm Unblock", f"Unblock device '{name}' ({mac})?"):
            success, message = self.scanner.unblock_device(mac)
            if success:
                self.tree.set(selection[0], 'Status', 'Online')
                self.tree.item(selection[0], tags=())
                messagebox.showinfo("Success", message)
            else:
                messagebox.showinfo("Info", message)

    def copy_ip(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device.")
            return

        ip = self.tree.item(selection[0], 'values')[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        messagebox.showinfo("Copied", f"IP {ip} copied to clipboard.")

    def show_blocked(self):
        if not self.scanner.blocked_devices:
            messagebox.showinfo("Blocked Devices", "No devices are currently blocked.")
            return

        blocked_list = "\n".join(f"• {mac}" for mac in self.scanner.blocked_devices)
        messagebox.showinfo("Blocked Devices", f"Blocked MAC addresses:\n\n{blocked_list}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    print("WiFi Scanner with Blocking")
    print("=" * 30)

    try:
        app = WiFiScannerGUI()
        print(f"Network: {app.scanner.network_base}.1-254")
        print("Starting application...")
        app.run()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
