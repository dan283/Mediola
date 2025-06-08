#!/usr/bin/env python3
"""
Simple WiFi Network Scanner
A more reliable, cross-platform network device scanner.
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

class SimpleNetworkScanner:
    def __init__(self):
        self.devices = []
        self.local_ip = self.get_local_ip()
        self.network_base = self.get_network_base()
        
    def get_local_ip(self):
        """Get the local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "192.168.1.100"  # Fallback
    
    def get_network_base(self):
        """Get network base (e.g., 192.168.1)"""
        ip_parts = self.local_ip.split('.')
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
    
    def ping_host(self, ip):
        """Ping a host to check if it's alive"""
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            return result.returncode == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return f"Device-{ip.split('.')[-1]}"
    
    def get_mac_address(self, ip):
        """Get MAC address using ARP"""
        try:
            system = platform.system().lower()
            if system == "windows":
                result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if ip in line:
                        # Look for MAC address pattern
                        mac_match = re.search(r'([0-9a-f]{2}[:-]){5}([0-9a-f]{2})', line, re.I)
                        if mac_match:
                            return mac_match.group(0).replace('-', ':').upper()
            else:
                result = subprocess.run(["arp", ip], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and ':' in parts[2]:
                        return parts[2].upper()
        except:
            pass
        return "Unknown"
    
    def scan_single_ip(self, ip):
        """Scan a single IP address"""
        if self.ping_host(ip):
            hostname = self.get_hostname(ip)
            mac = self.get_mac_address(ip)
            
            # Determine device type based on hostname/MAC
            device_type = "Unknown"
            if "router" in hostname.lower() or "gateway" in hostname.lower():
                device_type = "Router"
            elif "phone" in hostname.lower() or "iphone" in hostname.lower() or "android" in hostname.lower():
                device_type = "Phone"
            elif "laptop" in hostname.lower() or "pc" in hostname.lower() or "computer" in hostname.lower():
                device_type = "Computer"
            elif "tv" in hostname.lower() or "roku" in hostname.lower() or "chromecast" in hostname.lower():
                device_type = "Media Device"
            
            return {
                'ip': ip,
                'hostname': hostname,
                'mac': mac,
                'type': device_type,
                'status': 'Online'
            }
        return None
    
    def scan_network(self, progress_callback=None):
        """Scan the entire network"""
        self.devices = []
        
        def scan_ip_range(start, end):
            local_devices = []
            for i in range(start, end + 1):
                ip = f"{self.network_base}.{i}"
                device = self.scan_single_ip(ip)
                if device:
                    local_devices.append(device)
                    if progress_callback:
                        progress_callback(device)
            return local_devices
        
        # Scan in chunks using thread pool
        with ThreadPoolExecutor(max_workers=20) as executor:
            # Split the 1-254 range into chunks
            chunk_size = 25
            futures = []
            
            for start in range(1, 255, chunk_size):
                end = min(start + chunk_size - 1, 254)
                futures.append(executor.submit(scan_ip_range, start, end))
            
            # Collect results
            for future in futures:
                chunk_devices = future.result()
                self.devices.extend(chunk_devices)
        
        # Sort by IP address
        self.devices.sort(key=lambda x: int(x['ip'].split('.')[-1]))
        return self.devices

class SimpleWiFiGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Simple WiFi Network Scanner")
        self.root.geometry("900x600")
        
        self.scanner = SimpleNetworkScanner()
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="WiFi Network Scanner", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Info frame
        info_frame = ttk.LabelFrame(main_frame, text="Network Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 10))
        
        info_text = f"Local IP: {self.scanner.local_ip}\nScanning Range: {self.scanner.network_base}.1-254"
        ttk.Label(info_frame, text=info_text, font=('Arial', 10)).pack()
        
        # Control frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_button = ttk.Button(control_frame, text="Scan Network", 
                                     command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        self.status_label = ttk.Label(control_frame, text="Ready")
        self.status_label.pack(side=tk.RIGHT)
        
        # Device list frame
        list_frame = ttk.LabelFrame(main_frame, text="Discovered Devices", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview
        columns = ('IP', 'Hostname', 'MAC', 'Type', 'Status')
        self.tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.tree.heading('IP', text='IP Address')
        self.tree.heading('Hostname', text='Device Name')
        self.tree.heading('MAC', text='MAC Address')
        self.tree.heading('Type', text='Device Type')
        self.tree.heading('Status', text='Status')
        
        self.tree.column('IP', width=120)
        self.tree.column('Hostname', width=200)
        self.tree.column('MAC', width=150)
        self.tree.column('Type', width=120)
        self.tree.column('Status', width=80)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(action_frame, text="Refresh Selected", 
                  command=self.refresh_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(action_frame, text="Copy IP", 
                  command=self.copy_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export List", 
                  command=self.export_list).pack(side=tk.LEFT, padx=5)
        
        # Device count label
        self.count_label = ttk.Label(action_frame, text="Devices: 0")
        self.count_label.pack(side=tk.RIGHT)
    
    def start_scan(self):
        """Start network scan"""
        self.scan_button.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Scanning...")
        self.tree.delete(*self.tree.get_children())
        self.count_label.config(text="Devices: 0")
        
        # Start scan in background
        scan_thread = threading.Thread(target=self.scan_thread)
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_thread(self):
        """Background scanning thread"""
        device_count = 0
        
        def progress_callback(device):
            nonlocal device_count
            device_count += 1
            # Update UI from main thread
            self.root.after(0, lambda: self.add_device(device))
            self.root.after(0, lambda: self.count_label.config(text=f"Devices: {device_count}"))
        
        try:
            self.scanner.scan_network(progress_callback)
            self.root.after(0, self.scan_complete)
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
    
    def add_device(self, device):
        """Add device to the list"""
        self.tree.insert('', 'end', values=(
            device['ip'],
            device['hostname'],
            device['mac'],
            device['type'],
            device['status']
        ))
    
    def scan_complete(self):
        """Scan completed"""
        self.progress.stop()
        self.scan_button.config(state='normal')
        self.status_label.config(text=f"Scan complete")
    
    def scan_error(self, error):
        """Scan error occurred"""
        self.progress.stop()
        self.scan_button.config(state='normal')
        self.status_label.config(text="Scan failed")
        messagebox.showerror("Scan Error", f"Scan failed: {error}")
    
    def refresh_selected(self):
        """Refresh selected device"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device to refresh.")
            return
        
        item = selection[0]
        ip = self.tree.item(item, 'values')[0]
        
        # Refresh in background
        def refresh_thread():
            device = self.scanner.scan_single_ip(ip)
            if device:
                self.root.after(0, lambda: self.update_device(item, device))
            else:
                self.root.after(0, lambda: self.tree.set(item, 'Status', 'Offline'))
        
        threading.Thread(target=refresh_thread, daemon=True).start()
    
    def update_device(self, item, device):
        """Update device in tree"""
        self.tree.set(item, 'Hostname', device['hostname'])
        self.tree.set(item, 'MAC', device['mac'])
        self.tree.set(item, 'Type', device['type'])
        self.tree.set(item, 'Status', device['status'])
    
    def copy_ip(self):
        """Copy selected IP to clipboard"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a device.")
            return
        
        item = selection[0]
        ip = self.tree.item(item, 'values')[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        messagebox.showinfo("Copied", f"IP address {ip} copied to clipboard.")
    
    def export_list(self):
        """Export device list to text file"""
        if not self.scanner.devices:
            messagebox.showwarning("No Data", "No devices to export. Please scan first.")
            return
        
        try:
            filename = f"network_devices_{int(time.time())}.txt"
            with open(filename, 'w') as f:
                f.write("Network Device Scan Results\n")
                f.write("=" * 40 + "\n")
                f.write(f"Scan Time: {time.ctime()}\n")
                f.write(f"Network: {self.scanner.network_base}.0/24\n")
                f.write(f"Total Devices: {len(self.scanner.devices)}\n\n")
                
                for device in self.scanner.devices:
                    f.write(f"IP: {device['ip']}\n")
                    f.write(f"Name: {device['hostname']}\n")
                    f.write(f"MAC: {device['mac']}\n")
                    f.write(f"Type: {device['type']}\n")
                    f.write(f"Status: {device['status']}\n")
                    f.write("-" * 30 + "\n")
            
            messagebox.showinfo("Export Complete", f"Device list exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
    
    def run(self):
        """Start the application"""
        self.root.mainloop()

if __name__ == "__main__":
    print("Simple WiFi Network Scanner")
    print("=" * 30)
    print("Initializing...")
    
    try:
        app = SimpleWiFiGUI()
        print(f"Local IP detected: {app.scanner.local_ip}")
        print(f"Will scan: {app.scanner.network_base}.1-254")
        print("Starting GUI...")
        app.run()
    except Exception as e:
        print(f"Error: {e}")
        input("Press Enter to exit...")
