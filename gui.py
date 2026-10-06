"""
gui.py - Tkinter interface for the Security Toolkit.
Defines the main window class and tab functions.
Now includes integration with modules/loganalyzer.py
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from pathlib import Path

import modules.passwords as passwords
import modules.integrity as integrity
import modules.loganalyzer as loganalyzer


def create_passwords_tab(parent):
    global result_label, pw_status_label
    """Create the content for the 'Passwords' tab."""
    frame = ttk.Frame(parent, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    label = ttk.Label(frame, text="Password Manager", font=('Segoe UI', 14, 'bold'))
    label.pack(pady=(0, 10))
    
    entry_frame = ttk.Frame(frame)
    entry_frame.pack(fill=tk.X, pady=5)
    
    entry_label = ttk.Label(entry_frame, text="Enter password to check:")
    entry_label.pack(side=tk.LEFT, padx=5)
    
    entry = ttk.Entry(entry_frame, show="*", width=40)
    entry.pack(side=tk.LEFT, padx=5)
    entry.bind('<KeyRelease>', lambda e: check_password_strength(entry.get()))
    
    gen_frame = ttk.Frame(frame)
    gen_frame.pack(fill=tk.X, pady=5)
    
    generate_btn = ttk.Button(gen_frame, text="Generate Secure Password", 
                              command=lambda: generate_and_show_password())
    generate_btn.pack(side=tk.LEFT, padx=5)
    
    result_frame = ttk.LabelFrame(frame, text="Result", padding=10)
    result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
    result_label = ttk.Label(result_frame, text="", font=('Segoe UI', 11))
    result_label.pack(pady=5)
    
    pw_status_label = ttk.Label(result_frame, text="Ready", foreground="green")
    pw_status_label.pack()
    
    return frame


def check_password_strength(password: str):
    """Check password strength and update the display."""
    if not password:
        result_label.config(text="")
        pw_status_label.config(text="Ready", foreground="green")
        return
    
    try:
        score_data = passwords.score_password_strength(password)
        
        result_text = f"Strength: {score_data['rating']} ({score_data['score']}/100)\n"
        result_text += f"Length: {score_data['length']}\n"
        
        if score_data['has_upper']:
            result_text += "✓ Contains uppercase\n"
        else:
            result_text += "✗ Missing uppercase\n"
        
        if score_data['has_lower']:
            result_text += "✓ Contains lowercase\n"
        else:
            result_text += "✗ Missing lowercase\n"
        
        if score_data['has_digit']:
            result_text += "✓ Contains numbers\n"
        else:
            result_text += "✗ Missing numbers\n"
        
        if score_data['has_special']:
            result_text += "✓ Contains special chars\n"
        else:
            result_text += "✗ Missing special characters\n"
        
        if score_data['has_common_pattern']:
            result_text += "⚠ Contains common pattern\n"
        
        result_label.config(text=result_text, foreground="black")
        
        if score_data['score'] >= 80:
            pw_status_label.config(text="Strong Password", foreground="green")
        elif score_data['score'] >= 60:
            pw_status_label.config(text="Moderate Password", foreground="orange")
        elif score_data['score'] >= 40:
            pw_status_label.config(text="Weak Password", foreground="yellow")
        else:
            pw_status_label.config(text="Very Weak Password", foreground="red")
            
    except Exception as e:
        result_label.config(text=f"Error: {str(e)}", foreground="red")
        pw_status_label.config(text="Error", foreground="red")


def generate_and_show_password():
    """Generate a secure password and display it with strength score."""
    try:
        password = passwords.generate_secure_password(16)
        score_data = passwords.score_password_strength(password)
        
        result_text = f"Generated Password: {password}\n"
        result_text += f"Strength: {score_data['rating']} ({score_data['score']}/100)"
        
        result_label.config(text=result_text, foreground="black")
        pw_status_label.config(text="Generated", foreground="green")
        
        messagebox.showinfo("Secure Password Generated", 
                           f"Your secure password:\n\n{password}\n\n"
                           f"Strength: {score_data['rating']}")
            
    except Exception as e:
        messagebox.showerror("Error", str(e))


def create_file_integrity_tab(parent):
    global folder_entry, tree, status_label, result_frame
    """Create the content for the 'File Integrity' tab."""
    frame = ttk.Frame(parent, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    label = ttk.Label(frame, text="File Integrity Checker", font=('Segoe UI', 14, 'bold'))
    label.pack(pady=(0, 10))
    
    folder_frame = ttk.Frame(frame)
    folder_frame.pack(fill=tk.X, pady=5)
    
    ttk.Label(folder_frame, text="Select folder:").pack(side=tk.LEFT, padx=5)
    
    folder_var = tk.StringVar()
    folder_entry = ttk.Entry(folder_frame, textvariable=folder_var, width=50)
    folder_entry.pack(side=tk.LEFT, padx=5)
    
    browse_btn = ttk.Button(folder_frame, text="Browse...", 
                           command=lambda: select_folder(folder_entry))
    browse_btn.pack(side=tk.LEFT, padx=5)
    
    btn_frame = ttk.Frame(frame)
    btn_frame.pack(fill=tk.X, pady=5)
    
    create_baseline_btn = ttk.Button(btn_frame, text="Create Baseline", 
                                     command=lambda: create_baseline(folder_entry.get()))
    create_baseline_btn.pack(side=tk.LEFT, padx=5)
    
    check_now_btn = ttk.Button(btn_frame, text="Check Now", 
                               command=lambda: check_integrity(folder_entry.get()))
    check_now_btn.pack(side=tk.LEFT, padx=5)
    
    result_frame = ttk.LabelFrame(frame, text="Scan Results", padding=10)
    result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
    columns = ('Type', 'File Path')
    tree = ttk.Treeview(result_frame, columns=columns, show='headings', height=10)
    tree.heading('Type', text='Type', anchor=tk.W)
    tree.heading('File Path', text='File Path', anchor=tk.W)
    tree.column('Type', width=80)
    tree.column('File Path', width=200)
    
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    status_label = ttk.Label(result_frame, text="Ready", foreground="gray")
    status_label.pack(side=tk.RIGHT, padx=10)
    
    scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    return frame


def select_folder(entry: ttk.Entry):
    """Open folder picker and set the selected folder in the entry."""
    folder = filedialog.askdirectory(title="Select Folder to Scan")
    if folder:
        entry.delete(0, tk.END)
        entry.insert(0, folder)


def create_baseline(folder_path: str):
    """Create baseline hash for the selected folder."""
    if not folder_path or not Path(folder_path).exists():
        messagebox.showerror("Error", "Please select a valid folder first.")
        return
    
    try:
        baseline_path = integrity.save_baseline(Path(folder_path))
        messagebox.showinfo("Success", f"Baseline created successfully!\nSaved to: {baseline_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def check_integrity(folder_path: str):
    """Check file integrity and display results in Treeview."""
    if not folder_path or not Path(folder_path).exists():
        messagebox.showerror("Error", "Please select a valid folder first.")
        return

    try:
        tree.delete(*tree.get_children())
        status_label.config(text="Scanning...", foreground="blue")

        def scan_task():
            try:
                comparison, message = integrity.run_integrity_check(folder_path)
                tree.after(0, lambda: update_results(comparison, message))
            except Exception as e:
                msg = f"Error: {e}"
                tree.after(0, lambda: status_label.config(text=msg, foreground="red"))

        thread = threading.Thread(target=scan_task, daemon=True)
        thread.start()

    except Exception as e:
        messagebox.showerror("Error", str(e))


def update_results(comparison: dict, message: str):
    """Update the Treeview with scan results."""
    status_label.config(text=message, foreground="green" if message == "Scan complete" else "red")
    
    for file_path in comparison['modified']:
        tree.insert('', tk.END, values=('Modified', file_path))
    
    for file_path in comparison['new']:
        tree.insert('', tk.END, values=('New', file_path))
    
    for file_path in comparison['deleted']:
        tree.insert('', tk.END, values=('Deleted', file_path))
    
    if comparison['modified'] or comparison['new'] or comparison['deleted']:
        status_label.config(text=f"Found {len(comparison['modified'])} modified, "
                               f"{len(comparison['new'])} new, {len(comparison['deleted'])} deleted files",
                           foreground="red")
    else:
        status_label.config(text="No changes detected", foreground="green")


def create_log_analyzer_tab(parent):
    global log_tree, log_status_label, log_result_frame
    """
    Create the content for the 'Log Analyzer' tab.
    Integrates with modules/loganalyzer.py for parsing failed login attempts.
    """
    frame = ttk.Frame(parent, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    label = ttk.Label(frame, text="Log Analyzer - Failed Login Detection", 
                     font=('Segoe UI', 14, 'bold'))
    label.pack(pady=(0, 10))
    
    # File picker
    file_frame = ttk.Frame(frame)
    file_frame.pack(fill=tk.X, pady=5)
    
    ttk.Label(file_frame, text="Select log file:").pack(side=tk.LEFT, padx=5)
    
    file_var = tk.StringVar()
    file_entry = ttk.Entry(file_frame, textvariable=file_var, width=50)
    file_entry.pack(side=tk.LEFT, padx=5)
    
    open_btn = ttk.Button(file_frame, text="Open Log File", 
                         command=lambda: select_log_file(file_entry))
    open_btn.pack(side=tk.LEFT, padx=5)
    
    analyze_btn = ttk.Button(file_frame, text="Analyze", 
                            command=lambda: analyze_logs(file_entry.get()))
    analyze_btn.pack(side=tk.LEFT, padx=5)
    
    # Results Treeview
    log_result_frame = ttk.LabelFrame(frame, text="Failed Login Attempts", padding=10)
    log_result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
    columns = ('IP Address', 'Attempts', 'SUSPICIOUS')
    log_tree = ttk.Treeview(log_result_frame, columns=columns, show='headings', height=15)
    log_tree.heading('IP Address', text='IP Address', anchor=tk.W)
    log_tree.heading('Attempts', text='Attempts', anchor=tk.CENTER)
    log_tree.heading('SUSPICIOUS', text='SUSPICIOUS', anchor=tk.CENTER)
    log_tree.column('IP Address', width=150)
    log_tree.column('Attempts', width=80)
    log_tree.column('SUSPICIOUS', width=80)
    
    log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    # Status label
    log_status_label = ttk.Label(log_result_frame, text="Ready", foreground="gray")
    log_status_label.pack(side=tk.RIGHT, padx=10)
    
    # Scrollbar for treeview
    scrollbar = ttk.Scrollbar(log_result_frame, orient=tk.VERTICAL, command=log_tree.yview)
    log_tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    return frame


def select_log_file(entry: ttk.Entry):
    """Open file picker and set the selected log file in the entry."""
    file_path = filedialog.askopenfilename(
        title="Select Log File",
        filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
    )
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)


def analyze_logs(folder_path: str):
    """Analyze log file and display results in Treeview."""
    if not folder_path or not Path(folder_path).exists():
        messagebox.showerror("Error", "Please select a valid log file first.")
        return
    
    try:
        # Update status
        log_status_label.config(text="Analyzing...", foreground="blue")
        log_tree.delete(*log_tree.get_children())
        
        # Run analysis in background thread
        def analyze_task():
            ip_attempts, status_msg, error_msg = loganalyzer.analyze_logs(Path(folder_path))
            
            # Update UI on main thread
            tk._default_root.after(0, lambda: update_log_results(ip_attempts, status_msg, error_msg))
        
        thread = threading.Thread(target=analyze_task, daemon=True)
        thread.start()
        
    except Exception as e:
        messagebox.showerror("Error", str(e))


def update_log_results(ip_attempts: dict, status_msg: str, error_msg: str):
    """Update the Treeview with log analysis results."""
    global summary_label
    if error_msg:
        log_status_label.config(text=f"Error: {error_msg}", foreground="red")
        log_tree.insert("", tk.END, values=("Error", error_msg, ""))
        return

    log_status_label.config(text=status_msg, foreground="green")

    # Get suspicious IPs (5+ attempts)
    suspicious = loganalyzer.get_suspicious_ips(ip_attempts, threshold=5)

    # Add all IPs to the table, most attempts first
    log_tree.tag_configure("red", foreground="red")
    for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True):
        is_suspicious = "Yes" if ip in suspicious else "No"
        color = "red" if is_suspicious == "Yes" else "black"
        log_tree.insert("", tk.END, values=(ip, count, is_suspicious), tags=(color,))

    # Update the summary label (created only once)
    total_attempts = sum(ip_attempts.values())
    total_suspicious = len(suspicious)
    summary_text = f"Total: {total_attempts} attempts | Suspicious IPs: {total_suspicious}"
    try:
        summary_label.config(text=summary_text)
    except (NameError, tk.TclError):
        summary_label = ttk.Label(log_result_frame, text=summary_text, font=("Segoe UI", 10, "bold"))
        summary_label.pack(side=tk.RIGHT, padx=10, pady=5)


def create_log_analyzer_tab_stub(parent):
    """Create the content for the 'Log Analyzer' tab."""
    frame = ttk.Frame(parent, padding=10)
    frame.pack(fill=tk.BOTH, expand=True)
    
    label = ttk.Label(frame, text="Log Analyzer", font=('Segoe UI', 14, 'bold'))
    label.pack(pady=(0, 10))
    
    status_label = ttk.Label(frame, text="No logs loaded", foreground="gray")
    status_label.pack()
    
    return frame


class SecurityToolkitApp(tk.Tk):
    """Main application class for the Security Toolkit."""
    
    def __init__(self):
        """Initialize the main window and notebook."""
        super().__init__()
        
        style = ttk.Style()
        style.configure("TNotebook.Tab", padding=5)
        
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.passwords_frame = create_passwords_tab(self.notebook)
        self.file_integrity_frame = create_file_integrity_tab(self.notebook)
        self.log_analyzer_frame = create_log_analyzer_tab(self.notebook)
        
        self.notebook.add(self.passwords_frame, text="Passwords")
        self.notebook.add(self.file_integrity_frame, text="File Integrity")
        self.notebook.add(self.log_analyzer_frame, text="Log Analyzer")
        
        self.status_bar = ttk.Label(self, text="Security Toolkit - Ready", 
                                    relief=tk.FLAT, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.resizable(True, True)
        self.minsize(600, 400)
        
        self.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def on_close(self):
        """Handle window close event."""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.destroy()


def main():
    """Entry point for the GUI module if run directly."""
    app = SecurityToolkitApp()
    app.mainloop()


if __name__ == "__main__":
    main()
