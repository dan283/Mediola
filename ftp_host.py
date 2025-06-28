#!/usr/bin/env python3
"""
Simple FTP Server
Creates an FTP server to share a folder with other computers on your network
"""

import os
import sys
import socket
import threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json


class SimpleFTPServer:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple FTP Server")
        self.root.geometry("600x500")

        self.server = None
        self.server_thread = None
        self.running = False

        # Configuration
        self.config_file = "ftp_server_config.json"
        self.config = self.load_config()

        self.setup_ui()
        self.load_saved_config()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Server Configuration
        config_frame = ttk.LabelFrame(main_frame, text="Server Configuration", padding=10)
        config_frame.pack(fill=tk.X, pady=(0, 10))

        # Shared folder
        ttk.Label(config_frame, text="Shared Folder:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.folder_var = tk.StringVar(value=self.config.get('folder', os.getcwd()))
        folder_frame = ttk.Frame(config_frame)
        folder_frame.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=(10, 0), pady=5)

        self.folder_entry = ttk.Entry(folder_frame, textvariable=self.folder_var, width=40)
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).pack(side=tk.RIGHT, padx=(5, 0))

        # Server settings
        ttk.Label(config_frame, text="Server IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.ip_var = tk.StringVar(value=self.config.get('ip', self.get_local_ip()))
        self.ip_entry = ttk.Entry(config_frame, textvariable=self.ip_var, width=20)
        self.ip_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)

        ttk.Label(config_frame, text="Port:").grid(row=1, column=2, sticky=tk.W, padx=(20, 0), pady=5)
        self.port_var = tk.StringVar(value=str(self.config.get('port', 21)))
        self.port_entry = ttk.Entry(config_frame, textvariable=self.port_var, width=10)
        self.port_entry.grid(row=1, column=3, sticky=tk.W, padx=(10, 0), pady=5)

        # User Configuration
        user_frame = ttk.LabelFrame(main_frame, text="User Configuration", padding=10)
        user_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(user_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.username_var = tk.StringVar(value=self.config.get('username', 'user'))
        self.username_entry = ttk.Entry(user_frame, textvariable=self.username_var, width=20)
        self.username_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)

        ttk.Label(user_frame, text="Password:").grid(row=0, column=2, sticky=tk.W, padx=(20, 0), pady=5)
        self.password_var = tk.StringVar(value=self.config.get('password', 'password'))
        self.password_entry = ttk.Entry(user_frame, textvariable=self.password_var, show="*", width=20)
        self.password_entry.grid(row=0, column=3, sticky=tk.W, padx=(10, 0), pady=5)

        # Permissions
        perm_frame = ttk.Frame(user_frame)
        perm_frame.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(10, 0))

        ttk.Label(perm_frame, text="Permissions:").pack(side=tk.LEFT)

        self.read_var = tk.BooleanVar(value=self.config.get('read_perm', True))
        ttk.Checkbutton(perm_frame, text="Read", variable=self.read_var).pack(side=tk.LEFT, padx=(10, 0))

        self.write_var = tk.BooleanVar(value=self.config.get('write_perm', True))
        ttk.Checkbutton(perm_frame, text="Write", variable=self.write_var).pack(side=tk.LEFT, padx=(10, 0))

        self.delete_var = tk.BooleanVar(value=self.config.get('delete_perm', False))
        ttk.Checkbutton(perm_frame, text="Delete", variable=self.delete_var).pack(side=tk.LEFT, padx=(10, 0))

        # Anonymous access
        self.anonymous_var = tk.BooleanVar(value=self.config.get('anonymous', False))
        ttk.Checkbutton(user_frame, text="Allow Anonymous Access", variable=self.anonymous_var).grid(row=2, column=0,
                                                                                                     columnspan=4,
                                                                                                     sticky=tk.W,
                                                                                                     pady=(10, 0))

        # Control buttons
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_btn = ttk.Button(control_frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = ttk.Button(control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(control_frame, text="Save Config", command=self.save_config).pack(side=tk.LEFT, padx=(0, 10))

        ttk.Button(control_frame, text="Test Connection", command=self.test_connection).pack(side=tk.LEFT)

        # Status and Info
        info_frame = ttk.LabelFrame(main_frame, text="Server Information", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="Server stopped")
        ttk.Label(info_frame, textvariable=self.status_var, font=('Arial', 10, 'bold')).pack(anchor=tk.W, pady=(0, 10))

        # Connection info
        self.info_text = tk.Text(info_frame, height=10, width=70, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(info_frame, orient=tk.VERTICAL, command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=scrollbar.set)

        self.info_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.update_connection_info()

        # Configure grid weights
        config_frame.columnconfigure(1, weight=1)
        user_frame.columnconfigure(1, weight=1)

    def get_local_ip(self):
        try:
            # Connect to a remote address to get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def save_config(self):
        config = {
            'folder': self.folder_var.get(),
            'ip': self.ip_var.get(),
            'port': int(self.port_var.get()),
            'username': self.username_var.get(),
            'password': self.password_var.get(),
            'read_perm': self.read_var.get(),
            'write_perm': self.write_var.get(),
            'delete_perm': self.delete_var.get(),
            'anonymous': self.anonymous_var.get()
        }

        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            messagebox.showinfo("Success", "Configuration saved successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {str(e)}")

    def load_saved_config(self):
        # Config is already loaded in __init__, just update UI if needed
        pass

    def browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self.folder_var.get())
        if folder:
            self.folder_var.set(folder)

    def start_server(self):
        if self.running:
            return

        try:
            # Validate inputs
            folder = self.folder_var.get()
            if not os.path.exists(folder) or not os.path.isdir(folder):
                messagebox.showerror("Error", "Please select a valid folder to share")
                return

            port = int(self.port_var.get())
            if port < 1 or port > 65535:
                raise ValueError("Invalid port number")

            # Create authorizer
            authorizer = DummyAuthorizer()

            # Build permissions string
            permissions = ""
            if self.read_var.get():
                permissions += "elr"  # list, read
            if self.write_var.get():
                permissions += "adfmw"  # append, delete, mkdir, write
            if self.delete_var.get():
                permissions += "d"  # delete (already included above, but explicitly)

            if not permissions:
                permissions = "elr"  # At least read permissions

            # Add user
            if not self.anonymous_var.get():
                authorizer.add_user(
                    self.username_var.get(),
                    self.password_var.get(),
                    folder,
                    perm=permissions
                )
            else:
                authorizer.add_anonymous(folder, perm=permissions)

            # Create handler and server
            handler = FTPHandler
            handler.authorizer = authorizer
            handler.banner = "Simple Python FTP Server ready."

            self.server = FTPServer((self.ip_var.get(), port), handler)

            # Start server in separate thread
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()

            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_var.set(f"Server running on {self.ip_var.get()}:{port}")

            self.update_connection_info()
            messagebox.showinfo("Success", f"FTP Server started successfully!\nListening on {self.ip_var.get()}:{port}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")

    def stop_server(self):
        if not self.running:
            return

        try:
            if self.server:
                self.server.close_all()
                self.server = None

            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_var.set("Server stopped")

            self.update_connection_info()
            messagebox.showinfo("Success", "FTP Server stopped successfully")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop server: {str(e)}")

    def test_connection(self):
        if not self.running:
            messagebox.showwarning("Warning", "Server is not running")
            return

        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.ip_var.get(), int(self.port_var.get()))

            if self.anonymous_var.get():
                ftp.login()
            else:
                ftp.login(self.username_var.get(), self.password_var.get())

            files = ftp.nlst()
            ftp.quit()

            messagebox.showinfo("Success", f"Connection test successful!\nFound {len(files)} items in shared folder")

        except Exception as e:
            messagebox.showerror("Connection Test Failed", f"Failed to connect: {str(e)}")

    def update_connection_info(self):
        self.info_text.delete(1.0, tk.END)

        info = "=== FTP Server Information ===\n\n"

        if self.running:
            info += f"Status: RUNNING\n"
            info += f"Server Address: {self.ip_var.get()}:{self.port_var.get()}\n"
            info += f"Shared Folder: {self.folder_var.get()}\n\n"

            info += "=== Connection Instructions ===\n\n"
            info += "To connect from other computers:\n\n"

            info += "Using FTP Client (like the one you created):\n"
            info += f"  Host: {self.ip_var.get()}\n"
            info += f"  Port: {self.port_var.get()}\n"

            if self.anonymous_var.get():
                info += "  Username: (leave empty or 'anonymous')\n"
                info += "  Password: (leave empty)\n\n"
            else:
                info += f"  Username: {self.username_var.get()}\n"
                info += f"  Password: {self.password_var.get()}\n\n"

            info += "Using Windows Explorer:\n"
            if self.anonymous_var.get():
                info += f"  ftp://{self.ip_var.get()}:{self.port_var.get()}\n\n"
            else:
                info += f"  ftp://{self.username_var.get()}:{self.password_var.get()}@{self.ip_var.get()}:{self.port_var.get()}\n\n"

            info += "Using Command Line:\n"
            info += f"  ftp {self.ip_var.get()} {self.port_var.get()}\n\n"

            info += "=== Security Notes ===\n"
            info += "• FTP sends passwords in plain text - use only on trusted networks\n"
            info += "• Consider using SFTP/SCP for better security\n"
            info += "• Firewall may need to be configured to allow connections\n"
            info += f"• Make sure port {self.port_var.get()} is not blocked\n\n"

            info += "=== Permissions ===\n"
            perms = []
            if self.read_var.get():
                perms.append("Read/Download")
            if self.write_var.get():
                perms.append("Write/Upload")
            if self.delete_var.get():
                perms.append("Delete")
            info += f"  Allowed: {', '.join(perms) if perms else 'None'}\n"

        else:
            info += "Status: STOPPED\n\n"
            info += "Configure the settings above and click 'Start Server' to begin sharing files.\n\n"
            info += "=== Quick Setup Guide ===\n\n"
            info += "1. Choose a folder to share\n"
            info += "2. Set username and password (or enable anonymous access)\n"
            info += "3. Configure permissions as needed\n"
            info += "4. Click 'Start Server'\n"
            info += "5. Share the connection details with others\n\n"
            info += "Note: You may need to configure your firewall to allow incoming\n"
            info += "connections on the specified port.\n"

        self.info_text.insert(1.0, info)


def main():
    # Check if pyftpdlib is installed
    try:
        import pyftpdlib
    except ImportError:
        print("Error: pyftpdlib is required but not installed.")
        print("Please install it using: pip install pyftpdlib")
        sys.exit(1)

    root = tk.Tk()
    app = SimpleFTPServer(root)

    # Handle window closing
    def on_closing():
        if app.running:
            app.stop_server()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
