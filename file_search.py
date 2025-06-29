import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
from pathlib import Path
import fnmatch

class FileSearchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Search Tool")
        self.root.geometry("900x650")
        
        # Variables
        self.search_path = tk.StringVar()
        self.search_pattern = tk.StringVar(value="*.*")
        self.is_searching = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Path selection
        ttk.Label(main_frame, text="Search Location:").grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        path_frame = ttk.Frame(main_frame)
        path_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        path_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.search_path, width=50)
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        ttk.Button(path_frame, text="Browse", command=self.browse_folder).grid(row=0, column=1)
        
        # Search pattern
        ttk.Label(main_frame, text="File Pattern:").grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        
        pattern_frame = ttk.Frame(main_frame)
        pattern_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        pattern_frame.columnconfigure(0, weight=1)
        
        self.pattern_entry = ttk.Entry(pattern_frame, textvariable=self.search_pattern, width=30)
        self.pattern_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        
        self.search_button = ttk.Button(pattern_frame, text="Search", command=self.start_search)
        self.search_button.grid(row=0, column=1, padx=(0, 5))
        
        self.clear_button = ttk.Button(pattern_frame, text="Clear", command=self.clear_results)
        self.clear_button.grid(row=0, column=2)
        
        # Help text
        help_text = "Examples: *.txt, *.pdf, myfile.*, *report*, *.py"
        ttk.Label(main_frame, text=help_text, font=("TkDefaultFont", 8), foreground="gray").grid(
            row=3, column=0, columnspan=3, sticky=tk.W, pady=(25, 0))
        
        # Results tree
        tree_frame = ttk.Frame(main_frame)
        tree_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Treeview with scrollbars
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Path"), show="tree headings", selectmode="extended")
        self.tree.heading("#0", text="File Name")
        self.tree.heading("Size", text="Size")
        self.tree.heading("Path", text="Full Path")
        
        self.tree.column("#0", width=200, minwidth=150)
        self.tree.column("Size", width=100, minwidth=80)
        self.tree.column("Path", width=400, minwidth=200)
        
        # Bind double-click and selection events
        self.tree.bind("<Double-1>", self.on_item_double_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_selection_change)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid scrollbars and tree
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # File actions frame
        actions_frame = ttk.Frame(main_frame)
        actions_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Delete buttons
        self.delete_selected_button = ttk.Button(actions_frame, text="Delete Selected Files", 
                                               command=self.delete_selected_files, state="disabled")
        self.delete_selected_button.grid(row=0, column=0, padx=(0, 10))
        
        self.select_all_button = ttk.Button(actions_frame, text="Select All", command=self.select_all_files)
        self.select_all_button.grid(row=0, column=1, padx=(0, 10))
        
        self.deselect_all_button = ttk.Button(actions_frame, text="Deselect All", command=self.deselect_all_files)
        self.deselect_all_button.grid(row=0, column=2)
        
        # Selection info label
        self.selection_var = tk.StringVar(value="No files selected")
        selection_label = ttk.Label(actions_frame, textvariable=self.selection_var, font=("TkDefaultFont", 8))
        selection_label.grid(row=0, column=3, padx=(20, 0))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        
    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.search_path.set(folder)
    
    def format_size(self, size_bytes):
        """Convert bytes to human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
    
    def search_files(self):
        """Search for files matching the pattern"""
        try:
            search_dir = self.search_path.get()
            pattern = self.search_pattern.get()
            
            if not search_dir or not os.path.exists(search_dir):
                messagebox.showerror("Error", "Please select a valid directory")
                return
            
            if not pattern:
                pattern = "*.*"
            
            files_found = []
            total_size = 0
            
            # Walk through directory tree
            for root, dirs, files in os.walk(search_dir):
                for file in files:
                    if fnmatch.fnmatch(file.lower(), pattern.lower()):
                        file_path = os.path.join(root, file)
                        try:
                            file_size = os.path.getsize(file_path)
                            files_found.append({
                                'name': file,
                                'path': file_path,
                                'size': file_size
                            })
                            total_size += file_size
                        except (OSError, IOError):
                            # Skip files that can't be accessed
                            continue
            
            # Update UI in main thread
            self.root.after(0, self.update_results, files_found, total_size)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Search failed: {str(e)}"))
        finally:
            self.root.after(0, self.search_complete)
    
    def update_results(self, files, total_size):
        """Update the results tree with found files"""
        # Clear existing results
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Sort files by size (largest first)
        files.sort(key=lambda x: x['size'], reverse=True)
        
        # Add files to tree
        for file_info in files:
            self.tree.insert("", "end", 
                           text=file_info['name'],
                           values=(self.format_size(file_info['size']), file_info['path']))
        
        # Update status
        count = len(files)
        self.status_var.set(f"Found {count} file(s) - Total size: {self.format_size(total_size)}")
    
    def start_search(self):
        """Start the search in a separate thread"""
        if self.is_searching:
            return
        
        self.is_searching = True
        self.search_button.config(state="disabled")
        self.progress.start()
        self.status_var.set("Searching...")
        
        # Start search in background thread
        search_thread = threading.Thread(target=self.search_files)
        search_thread.daemon = True
        search_thread.start()
    
    def search_complete(self):
        """Called when search is complete"""
        self.is_searching = False
        self.search_button.config(state="normal")
        self.progress.stop()
    
    def clear_results(self):
        """Clear the results tree"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Ready")
        self.selection_var.set("No files selected")
        self.delete_selected_button.config(state="disabled")
    
    def on_item_double_click(self, event):
        """Handle double-click on tree item"""
        item = self.tree.selection()[0]
        file_path = self.tree.item(item, "values")[1]  # Get full path
        
        # Try to open file location in file explorer
        try:
            if os.name == 'nt':  # Windows
                os.startfile(os.path.dirname(file_path))
            elif os.name == 'posix':  # macOS and Linux
                import subprocess
                if os.uname().sysname == 'Darwin':  # macOS
                    subprocess.call(['open', os.path.dirname(file_path)])
                else:  # Linux
                    subprocess.call(['xdg-open', os.path.dirname(file_path)])
        except:
            messagebox.showinfo("Info", f"Cannot open file location:\n{file_path}")
    
    def on_selection_change(self, event):
        """Handle selection change in tree"""
        selected_items = self.tree.selection()
        count = len(selected_items)
        
        if count == 0:
            self.selection_var.set("No files selected")
            self.delete_selected_button.config(state="disabled")
        elif count == 1:
            self.selection_var.set("1 file selected")
            self.delete_selected_button.config(state="normal")
        else:
            self.selection_var.set(f"{count} files selected")
            self.delete_selected_button.config(state="normal")
    
    def select_all_files(self):
        """Select all files in the tree"""
        all_items = self.tree.get_children()
        self.tree.selection_set(all_items)
    
    def deselect_all_files(self):
        """Deselect all files in the tree"""
        self.tree.selection_remove(self.tree.selection())
    
    def delete_selected_files(self):
        """Delete the selected files"""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        # Get file paths
        files_to_delete = []
        total_size = 0
        
        for item in selected_items:
            file_path = self.tree.item(item, "values")[1]
            file_name = self.tree.item(item, "text")
            try:
                file_size = os.path.getsize(file_path)
                files_to_delete.append({
                    'item': item,
                    'path': file_path,
                    'name': file_name,
                    'size': file_size
                })
                total_size += file_size
            except (OSError, IOError):
                # File might not exist anymore
                continue
        
        if not files_to_delete:
            messagebox.showwarning("Warning", "No valid files selected for deletion.")
            return
        
        # Create confirmation dialog
        count = len(files_to_delete)
        if count == 1:
            message = f"Are you sure you want to delete this file?\n\n{files_to_delete[0]['name']}\n\nThis action cannot be undone."
        else:
            message = f"Are you sure you want to delete {count} files?\n\nTotal size: {self.format_size(total_size)}\n\nThis action cannot be undone."
        
        # Show detailed list for multiple files
        if count > 1:
            file_list = "\n".join([f"• {f['name']}" for f in files_to_delete[:10]])
            if count > 10:
                file_list += f"\n... and {count - 10} more files"
            message += f"\n\nFiles to delete:\n{file_list}"
        
        result = messagebox.askyesno("Confirm Deletion", message, icon="warning")
        
        if result:
            # Perform deletion
            successful_deletions = []
            failed_deletions = []
            
            for file_info in files_to_delete:
                try:
                    os.remove(file_info['path'])
                    successful_deletions.append(file_info)
                except Exception as e:
                    failed_deletions.append((file_info, str(e)))
            
            # Remove successfully deleted files from tree
            for file_info in successful_deletions:
                self.tree.delete(file_info['item'])
            
            # Update status and show results
            if successful_deletions and not failed_deletions:
                count = len(successful_deletions)
                self.status_var.set(f"Successfully deleted {count} file(s)")
                messagebox.showinfo("Success", f"Successfully deleted {count} file(s).")
            elif successful_deletions and failed_deletions:
                success_count = len(successful_deletions)
                fail_count = len(failed_deletions)
                self.status_var.set(f"Deleted {success_count} file(s), {fail_count} failed")
                
                error_details = "\n".join([f"• {f[0]['name']}: {f[1]}" for f in failed_deletions[:5]])
                if len(failed_deletions) > 5:
                    error_details += f"\n... and {len(failed_deletions) - 5} more errors"
                
                messagebox.showwarning("Partial Success", 
                                     f"Successfully deleted {success_count} file(s).\n"
                                     f"Failed to delete {fail_count} file(s):\n\n{error_details}")
            else:
                self.status_var.set("Deletion failed")
                error_details = "\n".join([f"• {f[0]['name']}: {f[1]}" for f in failed_deletions[:5]])
                if len(failed_deletions) > 5:
                    error_details += f"\n... and {len(failed_deletions) - 5} more errors"
                
                messagebox.showerror("Deletion Failed", 
                                   f"Failed to delete {len(failed_deletions)} file(s):\n\n{error_details}")

def main():
    root = tk.Tk()
    app = FileSearchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
