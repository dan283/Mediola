#!/usr/bin/env python3
"""
Simple but Powerful FTP Client
Similar to FileZilla - GUI-based FTP client with essential features
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import ftplib
import os
import threading
from datetime import datetime
import json
import sys


class FTPClient:
    def __init__(self, root):
        self.root = root
        self.root.title("FTP Client - FileZilla Style")
        self.root.geometry("1000x700")

        # FTP connection
        self.ftp = None
        self.connected = False
        self.current_remote_path = "/"
        self.current_local_path = os.getcwd()

        # Connection profiles
        self.profiles_file = "ftp_profiles.json"
        self.profiles = self.load_profiles()

        self.setup_ui()
        self.update_local_files()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Connection frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection", padding=10)
        conn_frame.pack(fill=tk.X, pady=(0, 5))

        # Connection controls
        ttk.Label(conn_frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.host_var = tk.StringVar()
        self.host_entry = ttk.Entry(conn_frame, textvariable=self.host_var, width=20)
        self.host_entry.grid(row=0, column=1, padx=(0, 10))

        ttk.Label(conn_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.port_var = tk.StringVar(value="21")
        self.port_entry = ttk.Entry(conn_frame, textvariable=self.port_var, width=8)
        self.port_entry.grid(row=0, column=3, padx=(0, 10))

        ttk.Label(conn_frame, text="Username:").grid(row=0, column=4, sticky=tk.W, padx=(0, 5))
        self.user_var = tk.StringVar()
        self.user_entry = ttk.Entry(conn_frame, textvariable=self.user_var, width=15)
        self.user_entry.grid(row=0, column=5, padx=(0, 10))

        ttk.Label(conn_frame, text="Password:").grid(row=0, column=6, sticky=tk.W, padx=(0, 5))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(conn_frame, textvariable=self.pass_var, show="*", width=15)
        self.pass_entry.grid(row=0, column=7, padx=(0, 10))

        # Connection buttons
        btn_frame = ttk.Frame(conn_frame)
        btn_frame.grid(row=0, column=8, padx=(10, 0))

        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.connect_ftp)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self.disconnect_ftp, state=tk.DISABLED)
        self.disconnect_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.save_profile_btn = ttk.Button(btn_frame, text="Save Profile", command=self.save_profile)
        self.save_profile_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.load_profile_btn = ttk.Button(btn_frame, text="Load Profile", command=self.load_profile)
        self.load_profile_btn.pack(side=tk.LEFT)

        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 5))

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT)

        # Progress bar
        self.progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.progress.pack(side=tk.RIGHT, padx=(10, 0))

        # File manager frame
        files_frame = ttk.Frame(main_frame)
        files_frame.pack(fill=tk.BOTH, expand=True)

        # Local files frame
        local_frame = ttk.LabelFrame(files_frame, text="Local Files", padding=5)
        local_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 2.5))

        # Local path
        local_path_frame = ttk.Frame(local_frame)
        local_path_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(local_path_frame, text="Path:").pack(side=tk.LEFT)
        self.local_path_var = tk.StringVar(value=self.current_local_path)
        self.local_path_entry = ttk.Entry(local_path_frame, textvariable=self.local_path_var)
        self.local_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        self.local_path_entry.bind('<Return>', self.change_local_path)

        ttk.Button(local_path_frame, text="Browse", command=self.browse_local_path).pack(side=tk.RIGHT)

        # Local files listbox
        local_list_frame = ttk.Frame(local_frame)
        local_list_frame.pack(fill=tk.BOTH, expand=True)

        self.local_listbox = tk.Listbox(local_list_frame, selectmode=tk.EXTENDED)
        local_scrollbar = ttk.Scrollbar(local_list_frame, orient=tk.VERTICAL, command=self.local_listbox.yview)
        self.local_listbox.configure(yscrollcommand=local_scrollbar.set)

        self.local_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        local_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.local_listbox.bind('<Double-1>', self.local_double_click)
        self.local_listbox.bind('<Button-3>', self.local_right_click)

        # Remote files frame
        remote_frame = ttk.LabelFrame(files_frame, text="Remote Files", padding=5)
        remote_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(2.5, 0))

        # Remote path
        remote_path_frame = ttk.Frame(remote_frame)
        remote_path_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(remote_path_frame, text="Path:").pack(side=tk.LEFT)
        self.remote_path_var = tk.StringVar(value=self.current_remote_path)
        self.remote_path_entry = ttk.Entry(remote_path_frame, textvariable=self.remote_path_var, state=tk.DISABLED)
        self.remote_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        self.remote_path_entry.bind('<Return>', self.change_remote_path)

        ttk.Button(remote_path_frame, text="Refresh", command=self.update_remote_files).pack(side=tk.RIGHT)

        # Remote files listbox
        remote_list_frame = ttk.Frame(remote_frame)
        remote_list_frame.pack(fill=tk.BOTH, expand=True)

        self.remote_listbox = tk.Listbox(remote_list_frame, selectmode=tk.EXTENDED)
        remote_scrollbar = ttk.Scrollbar(remote_list_frame, orient=tk.VERTICAL, command=self.remote_listbox.yview)
        self.remote_listbox.configure(yscrollcommand=remote_scrollbar.set)

        self.remote_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        remote_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.remote_listbox.bind('<Double-1>', self.remote_double_click)
        self.remote_listbox.bind('<Button-3>', self.remote_right_click)

        # Transfer buttons frame
        transfer_frame = ttk.Frame(main_frame)
        transfer_frame.pack(fill=tk.X, pady=5)

        ttk.Button(transfer_frame, text="Upload →", command=self.upload_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(transfer_frame, text="← Download", command=self.download_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(transfer_frame, text="Delete Local", command=self.delete_local_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(transfer_frame, text="Delete Remote", command=self.delete_remote_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(transfer_frame, text="Create Remote Dir", command=self.create_remote_dir).pack(side=tk.LEFT, padx=5)

    def load_profiles(self):
        try:
            if os.path.exists(self.profiles_file):
                with open(self.profiles_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return {}

    def save_profiles(self):
        try:
            with open(self.profiles_file, 'w') as f:
                json.dump(self.profiles, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save profiles: {str(e)}")

    def save_profile(self):
        if not self.host_var.get():
            messagebox.showwarning("Warning", "Please enter host information first")
            return

        name = simpledialog.askstring("Save Profile", "Enter profile name:")
        if name:
            self.profiles[name] = {
                'host': self.host_var.get(),
                'port': self.port_var.get(),
                'username': self.user_var.get(),
                'password': self.pass_var.get()
            }
            self.save_profiles()
            messagebox.showinfo("Success", f"Profile '{name}' saved successfully")

    def load_profile(self):
        if not self.profiles:
            messagebox.showinfo("Info", "No saved profiles found")
            return

        profile_names = list(self.profiles.keys())

        # Create selection dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Load Profile")
        dialog.geometry("300x200")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Select a profile:").pack(pady=10)

        profile_var = tk.StringVar()
        profile_combo = ttk.Combobox(dialog, textvariable=profile_var, values=profile_names, state="readonly")
        profile_combo.pack(pady=5)

        def load_selected():
            if profile_var.get():
                profile = self.profiles[profile_var.get()]
                self.host_var.set(profile['host'])
                self.port_var.set(profile['port'])
                self.user_var.set(profile['username'])
                self.pass_var.set(profile['password'])
                dialog.destroy()

        ttk.Button(dialog, text="Load", command=load_selected).pack(pady=10)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack()

    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()

    def start_progress(self):
        self.progress.start()

    def stop_progress(self):
        self.progress.stop()

    def connect_ftp(self):
        if not self.host_var.get():
            messagebox.showerror("Error", "Please enter host")
            return

        self.start_progress()
        self.update_status("Connecting...")

        def connect_thread():
            try:
                self.ftp = ftplib.FTP()
                self.ftp.connect(self.host_var.get(), int(self.port_var.get()))
                self.ftp.login(self.user_var.get(), self.pass_var.get())

                self.connected = True
                self.root.after(0, self.on_connect_success)

            except Exception as e:
                self.root.after(0, lambda: self.on_connect_error(str(e)))

        threading.Thread(target=connect_thread, daemon=True).start()

    def on_connect_success(self):
        self.stop_progress()
        self.update_status(f"Connected to {self.host_var.get()}")
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.remote_path_entry.config(state=tk.NORMAL)
        self.update_remote_files()

    def on_connect_error(self, error):
        self.stop_progress()
        self.update_status("Connection failed")
        messagebox.showerror("Connection Error", f"Failed to connect: {error}")

    def disconnect_ftp(self):
        if self.ftp:
            try:
                self.ftp.quit()
            except:
                pass
            self.ftp = None

        self.connected = False
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.remote_path_entry.config(state=tk.DISABLED)
        self.remote_listbox.delete(0, tk.END)
        self.update_status("Disconnected")

    def update_local_files(self):
        self.local_listbox.delete(0, tk.END)

        try:
            # Add parent directory option
            if self.current_local_path != "/":
                self.local_listbox.insert(tk.END, "../")

            # List directories first, then files
            items = os.listdir(self.current_local_path)
            dirs = [item for item in items if os.path.isdir(os.path.join(self.current_local_path, item))]
            files = [item for item in items if os.path.isfile(os.path.join(self.current_local_path, item))]

            for d in sorted(dirs):
                self.local_listbox.insert(tk.END, f"[{d}]")
            for f in sorted(files):
                self.local_listbox.insert(tk.END, f)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to list local files: {str(e)}")

    def update_remote_files(self):
        if not self.connected:
            return

        self.remote_listbox.delete(0, tk.END)
        self.start_progress()

        def list_remote():
            try:
                # Add parent directory option
                if self.current_remote_path != "/":
                    self.root.after(0, lambda: self.remote_listbox.insert(tk.END, "../"))

                files = []
                self.ftp.retrlines('LIST', files.append)

                dirs = []
                regular_files = []

                for line in files:
                    parts = line.split()
                    if len(parts) >= 9:
                        filename = ' '.join(parts[8:])
                        if line.startswith('d'):
                            dirs.append(f"[{filename}]")
                        else:
                            regular_files.append(filename)

                self.root.after(0, lambda: self.populate_remote_list(dirs, regular_files))

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to list remote files: {str(e)}"))
            finally:
                self.root.after(0, self.stop_progress)

        threading.Thread(target=list_remote, daemon=True).start()

    def populate_remote_list(self, dirs, files):
        for d in sorted(dirs):
            self.remote_listbox.insert(tk.END, d)
        for f in sorted(files):
            self.remote_listbox.insert(tk.END, f)

    def local_double_click(self, event):
        selection = self.local_listbox.curselection()
        if selection:
            item = self.local_listbox.get(selection[0])

            if item == "../":
                self.current_local_path = os.path.dirname(self.current_local_path)
            elif item.startswith('[') and item.endswith(']'):
                dirname = item[1:-1]
                self.current_local_path = os.path.join(self.current_local_path, dirname)

            self.local_path_var.set(self.current_local_path)
            self.update_local_files()

    def remote_double_click(self, event):
        if not self.connected:
            return

        selection = self.remote_listbox.curselection()
        if selection:
            item = self.remote_listbox.get(selection[0])

            if item == "../":
                self.current_remote_path = '/'.join(self.current_remote_path.rstrip('/').split('/')[:-1])
                if not self.current_remote_path:
                    self.current_remote_path = "/"
            elif item.startswith('[') and item.endswith(']'):
                dirname = item[1:-1]
                if self.current_remote_path.endswith('/'):
                    self.current_remote_path += dirname
                else:
                    self.current_remote_path += '/' + dirname

                try:
                    self.ftp.cwd(self.current_remote_path)
                    self.remote_path_var.set(self.current_remote_path)
                    self.update_remote_files()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to change directory: {str(e)}")

    def change_local_path(self, event):
        new_path = self.local_path_var.get()
        if os.path.exists(new_path) and os.path.isdir(new_path):
            self.current_local_path = new_path
            self.update_local_files()
        else:
            messagebox.showerror("Error", "Invalid local path")
            self.local_path_var.set(self.current_local_path)

    def change_remote_path(self, event):
        if not self.connected:
            return

        new_path = self.remote_path_var.get()
        try:
            self.ftp.cwd(new_path)
            self.current_remote_path = new_path
            self.update_remote_files()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change remote directory: {str(e)}")
            self.remote_path_var.set(self.current_remote_path)

    def browse_local_path(self):
        path = filedialog.askdirectory(initialdir=self.current_local_path)
        if path:
            self.current_local_path = path
            self.local_path_var.set(path)
            self.update_local_files()

    def upload_files(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return

        selections = self.local_listbox.curselection()
        if not selections:
            messagebox.showwarning("Warning", "Please select files to upload")
            return

        files_to_upload = []
        for i in selections:
            item = self.local_listbox.get(i)
            if not item.startswith('[') and item != "../":
                files_to_upload.append(item)

        if not files_to_upload:
            messagebox.showwarning("Warning", "No files selected for upload")
            return

        self.start_progress()
        self.update_status("Uploading files...")

        def upload_thread():
            try:
                for filename in files_to_upload:
                    local_path = os.path.join(self.current_local_path, filename)
                    with open(local_path, 'rb') as f:
                        self.ftp.storbinary(f'STOR {filename}', f)

                self.root.after(0, self.on_upload_success)

            except Exception as e:
                self.root.after(0, lambda: self.on_upload_error(str(e)))

        threading.Thread(target=upload_thread, daemon=True).start()

    def on_upload_success(self):
        self.stop_progress()
        self.update_status("Upload completed")
        self.update_remote_files()
        messagebox.showinfo("Success", "Files uploaded successfully")

    def on_upload_error(self, error):
        self.stop_progress()
        self.update_status("Upload failed")
        messagebox.showerror("Upload Error", f"Failed to upload files: {error}")

    def download_files(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return

        selections = self.remote_listbox.curselection()
        if not selections:
            messagebox.showwarning("Warning", "Please select files to download")
            return

        files_to_download = []
        for i in selections:
            item = self.remote_listbox.get(i)
            if not item.startswith('[') and item != "../":
                files_to_download.append(item)

        if not files_to_download:
            messagebox.showwarning("Warning", "No files selected for download")
            return

        self.start_progress()
        self.update_status("Downloading files...")

        def download_thread():
            try:
                for filename in files_to_download:
                    local_path = os.path.join(self.current_local_path, filename)
                    with open(local_path, 'wb') as f:
                        self.ftp.retrbinary(f'RETR {filename}', f.write)

                self.root.after(0, self.on_download_success)

            except Exception as e:
                self.root.after(0, lambda: self.on_download_error(str(e)))

        threading.Thread(target=download_thread, daemon=True).start()

    def on_download_success(self):
        self.stop_progress()
        self.update_status("Download completed")
        self.update_local_files()
        messagebox.showinfo("Success", "Files downloaded successfully")

    def on_download_error(self, error):
        self.stop_progress()
        self.update_status("Download failed")
        messagebox.showerror("Download Error", f"Failed to download files: {error}")

    def delete_local_files(self):
        selections = self.local_listbox.curselection()
        if not selections:
            messagebox.showwarning("Warning", "Please select files to delete")
            return

        files_to_delete = []
        for i in selections:
            item = self.local_listbox.get(i)
            if not item.startswith('[') and item != "../":
                files_to_delete.append(item)

        if not files_to_delete:
            messagebox.showwarning("Warning", "No files selected for deletion")
            return

        if messagebox.askyesno("Confirm Delete", f"Delete {len(files_to_delete)} local file(s)?"):
            try:
                for filename in files_to_delete:
                    local_path = os.path.join(self.current_local_path, filename)
                    os.remove(local_path)

                self.update_local_files()
                messagebox.showinfo("Success", "Files deleted successfully")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete files: {str(e)}")

    def delete_remote_files(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return

        selections = self.remote_listbox.curselection()
        if not selections:
            messagebox.showwarning("Warning", "Please select files to delete")
            return

        files_to_delete = []
        for i in selections:
            item = self.remote_listbox.get(i)
            if not item.startswith('[') and item != "../":
                files_to_delete.append(item)

        if not files_to_delete:
            messagebox.showwarning("Warning", "No files selected for deletion")
            return

        if messagebox.askyesno("Confirm Delete", f"Delete {len(files_to_delete)} remote file(s)?"):
            try:
                for filename in files_to_delete:
                    self.ftp.delete(filename)

                self.update_remote_files()
                messagebox.showinfo("Success", "Files deleted successfully")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete files: {str(e)}")

    def create_remote_dir(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server")
            return

        dirname = simpledialog.askstring("Create Directory", "Enter directory name:")
        if dirname:
            try:
                self.ftp.mkd(dirname)
                self.update_remote_files()
                messagebox.showinfo("Success", f"Directory '{dirname}' created successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create directory: {str(e)}")

    def local_right_click(self, event):
        try:
            self.local_listbox.selection_clear(0, tk.END)
            self.local_listbox.selection_set(self.local_listbox.nearest(event.y))

            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Upload", command=self.upload_files)
            menu.add_command(label="Delete", command=self.delete_local_files)
            menu.add_separator()
            menu.add_command(label="Refresh", command=self.update_local_files)

            menu.tk_popup(event.x_root, event.y_root)
        except:
            pass

    def remote_right_click(self, event):
        if not self.connected:
            return

        try:
            self.remote_listbox.selection_clear(0, tk.END)
            self.remote_listbox.selection_set(self.remote_listbox.nearest(event.y))

            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="Download", command=self.download_files)
            menu.add_command(label="Delete", command=self.delete_remote_files)
            menu.add_separator()
            menu.add_command(label="Create Directory", command=self.create_remote_dir)
            menu.add_command(label="Refresh", command=self.update_remote_files)

            menu.tk_popup(event.x_root, event.y_root)
        except:
            pass


def main():
    root = tk.Tk()
    app = FTPClient(root)
    root.mainloop()


if __name__ == "__main__":
    main()
