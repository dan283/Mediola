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
        self.root.geometry("800x600")
        
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
        self.tree = ttk.Treeview(tree_frame, columns=("Size", "Path"), show="tree headings")
        self.tree.heading("#0", text="File Name")
        self.tree.heading("Size", text="Size")
        self.tree.heading("Path", text="Full Path")
        
        self.tree.column("#0", width=200, minwidth=150)
        self.tree.column("Size", width=100, minwidth=80)
        self.tree.column("Path", width=400, minwidth=200)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid scrollbars and tree
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        
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

def main():
    root = tk.Tk()
    app = FileSearchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
