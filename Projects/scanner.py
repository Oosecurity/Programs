# codebase: python
# Version: 1.5
# Enhancements:
# - Vulnerability findings in the Treeview are now sorted by port number.
# - Retained features: Progress bar color, CVSS display, scan types, UI reset logic.

# --- Disclaimer & License ---
# (Disclaimer remains the same)

# --- Imports ---
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import ipaddress
import queue
from urllib.parse import urlparse
import re
import time
from typing import Dict, List, Any, Optional, Callable, Tuple

# --- External Libraries ---
try:
    from packaging import version as packaging_version
except ImportError:
    messagebox.showerror("Dependency Error", "Install 'packaging': pip install packaging"); exit()
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except ImportError:
     messagebox.showerror("Dependency Error", "Install 'matplotlib': pip install matplotlib"); exit()

# --- Configuration ---
# (Port lists, Timeouts, Severities remain the same)
COMMON_PORTS = sorted([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443])
EXTENDED_COMMON_PORTS = sorted(list(set(COMMON_PORTS + [20, 26, 69, 113, 119, 161, 162, 179, 389, 636, 465, 587, 514, 548, 873, 1080, 1433, 1434, 1521, 2049, 2375, 2376, 3000, 3128, 3283, 3307, 4000, 5000, 5432, 5555, 5672, 5901, 5902, 6379, 7077, 8000, 8001, 8008, 8081, 8888, 9000, 9090, 9100, 9200, 9300, 11211, 27017, 27018])))
CONNECTION_TIMEOUT: float = 1.0
BANNER_TIMEOUT: float = 2.0
SEVERITY_CRITICAL: str = "Critical"; SEVERITY_HIGH: str = "High"; SEVERITY_MEDIUM: str = "Medium"; SEVERITY_LOW: str = "Low"; SEVERITY_INFO: str = "Info"

# (VULN_INFO remains the same - includes CVSS)
HTTP_VULN_PATTERNS = [(re.compile(r'Apache/([\d.]+)', re.IGNORECASE), "2.4.53", {"severity": SEVERITY_MEDIUM, "description": "Outdated Apache version.", "cvss": 5.9}), (re.compile(r'nginx/([\d.]+)', re.IGNORECASE), "1.22.0", {"severity": SEVERITY_MEDIUM, "description": "Outdated Nginx version.", "cvss": 5.3})]
VULN_INFO: Dict[int, Dict[str, Any]] = {21: {"service_name": "FTP", "min_safe_version": "3.0.5", "vuln_below_min": {"severity": SEVERITY_HIGH, "description": "Potentially vulnerable FTP version.", "cvss": 7.5}, "known_vuln": { "2.3.4": {"severity": SEVERITY_CRITICAL, "description": "VSFTPD 2.3.4 Backdoor", "cvss": 10.0}}}, 22: {"service_name": "SSH", "min_safe_version": "8.8", "vuln_below_min": {"severity": SEVERITY_MEDIUM, "description": "Outdated SSH version.", "cvss": 5.3}, "known_vuln": {"7.7": {"severity": SEVERITY_HIGH, "description": "OpenSSH 7.7 User Enumeration", "cvss": 7.1}}}, 80: {"service_name": "HTTP", "vulnerable_patterns": HTTP_VULN_PATTERNS}, 443: {"service_name": "HTTPS", "vulnerable_patterns": HTTP_VULN_PATTERNS}}

# --- Core Logic ---

# (extract_version_from_banner remains the same)
def extract_version_from_banner(banner: str, port: int) -> Optional[str]:
    port_info = VULN_INFO.get(port);
    if port_info and "vulnerable_patterns" in port_info:
        for pattern, min_safe, vuln_details in port_info["vulnerable_patterns"]:
             match = pattern.search(banner);
             if match: return match.group(1)
    generic_patterns = [r"v?(\d+\.\d+\.\d+[a-zA-Z0-9.-]*)", r"v?(\d+\.\d+[a-zA-Z0-9.-]*)", r"version\s+(\d+\.\d+\.?\d*)", r"(\d+\.\d+\.\d+)", r"(\d+\.\d+)"]
    for pattern in generic_patterns:
        match = re.search(pattern, banner, re.IGNORECASE);
        if match: return match.group(1)
    return None

# (check_vulnerabilities remains the same)
def check_vulnerabilities(port: int, detected_version_str: Optional[str], banner: str) -> Optional[Dict[str, Any]]:
    if not detected_version_str: return None
    port_info = VULN_INFO.get(port);
    if not port_info: return None
    try:
        detected_version = packaging_version.parse(detected_version_str)
        if "known_vuln" in port_info:
            for vuln_ver_str, vuln_details in port_info["known_vuln"].items():
                 if detected_version_str == vuln_ver_str: return vuln_details
        if "min_safe_version" in port_info:
            min_safe_ver = packaging_version.parse(port_info["min_safe_version"])
            if detected_version < min_safe_ver: return port_info.get("vuln_below_min", {"severity": SEVERITY_LOW, "description": "Potentially outdated version.", "cvss": 3.0})
        if "vulnerable_patterns" in port_info:
             for pattern, min_safe_str, vuln_details in port_info["vulnerable_patterns"]:
                  match = pattern.search(banner)
                  if match and match.group(1) == detected_version_str:
                        min_safe_ver = packaging_version.parse(min_safe_str);
                        if detected_version < min_safe_ver: return vuln_details
    except packaging_version.InvalidVersion: return {"severity": SEVERITY_INFO, "description": f"Could not parse version '{detected_version_str}'.", "cvss": 0.0}
    except Exception as e: return {"severity": SEVERITY_INFO, "description": f"Vuln check error: {e}", "cvss": 0.0}
    return None

# (check_port remains the same)
def check_port(ip: str, port: int, result_queue: queue.Queue):
    result: Dict[str, Any] = {"port": port, "status": "Closed/Filtered", "banner": "", "version": None, "vulnerability": None}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(CONNECTION_TIMEOUT); sock.connect((ip, port)); result["status"] = "Open"
        try:
            sock.settimeout(BANNER_TIMEOUT); banner_bytes = sock.recv(1024)
            try: result["banner"] = banner_bytes.decode('utf-8', errors='ignore').strip()
            except Exception: result["banner"] = banner_bytes.decode('latin-1', errors='ignore').strip()
            if not result["banner"]: result["banner"] = "(No banner received)"
            else:
                result["version"] = extract_version_from_banner(result["banner"], port)
                if result["version"]: result["vulnerability"] = check_vulnerabilities(port, result["version"], result["banner"])
        except socket.timeout: result["banner"] = "(Banner read timeout)"
        except socket.error as e: result["banner"] = f"(Banner read error: {e})"
        except Exception as e: result["banner"] = f"(Banner processing error: {e})"
    except socket.timeout: result["status"] = "Filtered (Timeout)"
    except ConnectionRefusedError: result["status"] = "Closed"
    except socket.gaierror: result["status"] = "DNS Error"; result_queue.put({"port": port, "status": "STOP_DNS_ERROR"}); return
    except socket.error as e: result["status"] = f"Error ({e.errno})"
    except Exception as e: result["status"] = f"Unexpected Error: {e}"
    finally:
        if sock: sock.close()
    result_queue.put(result)

# --- Modified scan_host_with_progress ---
def scan_host_with_progress(ip: str, ports_to_scan: List[int], output_queue: queue.Queue,
                            progress_bar: ttk.Progressbar, vulnerability_tree: ttk.Treeview, # Note: vulnerability_tree is passed but not used directly here anymore
                            severity_counts: Dict[str, int]):
    """ Scans ports, updates log/progress, collects vulns, passes sorted list at end."""
    threads: List[threading.Thread] = []
    port_result_queue: queue.Queue = queue.Queue()
    vulnerability_details_list: List[Tuple] = [] # Collect vulnerability tuples here

    output_queue.put(f"Starting scan on {ip} for {len(ports_to_scan)} port(s)...\n")
    for key in severity_counts: severity_counts[key] = 0
    progress_bar.after(0, lambda: progress_bar.config(value=0, maximum=len(ports_to_scan)))

    for port in ports_to_scan:
        thread = threading.Thread(target=check_port, args=(ip, port, port_result_queue), daemon=True)
        threads.append(thread)
        thread.start()

    open_ports_count: int = 0
    processed_ports: int = 0
    scan_stopped_early: bool = False

    while processed_ports < len(ports_to_scan):
        try:
            result = port_result_queue.get(timeout=0.1)
            processed_ports += 1
            if not scan_stopped_early:
                progress_bar.after(0, lambda v=processed_ports: progress_bar.config(value=v))

            if result["status"] == "STOP_DNS_ERROR":
                output_queue.put(f"!!! DNS lookup failed for {ip}. Stopping scan. !!!\n")
                scan_stopped_early = True
                progress_bar.after(0, lambda: progress_bar.config(style="Red.Horizontal.TProgressbar"))
                break

            if result["status"] == "Open":
                open_ports_count += 1
                version_str = result["version"] if result["version"] else "(Not detected)"
                # Still log open ports progressively
                output_queue.put(f"[+] Port {result['port']:<5} is Open. Version: {version_str}\n")
                if result["vulnerability"]:
                    vuln = result["vulnerability"]
                    severity = vuln.get("severity", SEVERITY_INFO)
                    description = vuln.get("description", "N/A")
                    cvss_score = vuln.get("cvss", "N/A")
                    # *** Collect vuln details instead of scheduling Treeview insert ***
                    vulnerability_details_list.append((
                        result["port"], result["version"], severity, description, cvss_score
                    ))
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1 # Keep counting severity
            elif result["status"] != "Closed":
                 output_queue.put(f"[-] Port {result['port']:<5} Status: {result['status']}\n")

        except queue.Empty:
            if not any(t.is_alive() for t in threads): break

    # --- Sort collected vulnerabilities by port (first element of tuple) ---
    sorted_vulnerabilities = sorted(vulnerability_details_list, key=lambda item: item[0])

    if not scan_stopped_early:
        output_queue.put(f"\nScan finished for {ip}. Found {open_ports_count} open port(s).\n")

    # --- Signal completion with counts AND sorted vulnerability list ---
    output_queue.put(("DONE", severity_counts, sorted_vulnerabilities))


# --- GUI Functions ---

# (validate_ip_gui remains the same)
def validate_ip_gui(ip_string: str) -> Optional[str]:
    target = ip_string.strip();
    if not target: messagebox.showerror("Error", "Target cannot be empty."); return None
    try:
        parsed_url = urlparse(target);
        if parsed_url.scheme in ('http', 'https') and parsed_url.netloc:
            hostname = parsed_url.netloc.split(':')[0];
            if hostname: return hostname
            else: messagebox.showerror("Error", f"Could not extract hostname from URL: {target}"); return None
        elif parsed_url.scheme: messagebox.showerror("Error", f"Unsupported URL scheme: {parsed_url.scheme}"); return None
        try: ipaddress.ip_address(target); return target
        except ValueError:
            if len(target) > 253: messagebox.showerror("Error", "Hostname too long."); return None
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$", target):
                 if target == "localhost": return target
                 messagebox.showerror("Error", "Invalid characters in hostname."); return None
            return target
    except Exception as e: messagebox.showerror("Error", f"Failed to parse target: {target}\nError: {e}"); return None

# --- Modified update_output_gui ---
def update_output_gui(output_text: scrolledtext.ScrolledText, message_queue: queue.Queue,
                      root: tk.Tk, chart_updater: Callable, vulnerability_tree: ttk.Treeview): # Added vulnerability_tree
    """ Gets messages, updates log, populates tree and chart on DONE signal. """
    more_updates_expected = True
    try:
        while True:
            message_obj = message_queue.get_nowait()

            # Check for DONE signal (now includes sorted vulnerabilities)
            if isinstance(message_obj, tuple) and message_obj[0] == "DONE":
                final_counts = message_obj[1]
                sorted_vulns = message_obj[2] # Get the sorted list

                # --- Populate the Treeview directly (already in main thread) ---
                for vuln_data in sorted_vulns:
                     # Unpack tuple: port, version, severity, description, cvss
                     vulnerability_tree.insert("", "end", values=vuln_data)

                # Schedule final chart update
                root.after(50, lambda: chart_updater(final_counts))
                more_updates_expected = False
                return # Stop polling for this scan

            # Process regular log message
            message = str(message_obj)
            output_text.configure(state='normal')
            output_text.insert(tk.END, message)
            output_text.configure(state='disabled')
            output_text.see(tk.END)

    except queue.Empty: pass # No messages currently

    finally:
         if more_updates_expected: # Reschedule only if scan not finished
              root.after(100, update_output_gui, output_text, message_queue, root, chart_updater, vulnerability_tree) # Pass tree


# (update_pie_chart remains the same)
def update_pie_chart(severity_counts: Dict[str, int], chart_frame: ttk.Frame,
                     canvas_widget: FigureCanvasTkAgg, fig: plt.Figure):
    fig.clear(); items_with_counts = [(k, v) for k, v in severity_counts.items() if v > 0]; labels = [item[0] for item in items_with_counts]; sizes = [item[1] for item in items_with_counts]; colors = {SEVERITY_CRITICAL: 'red', SEVERITY_HIGH: 'orange', SEVERITY_MEDIUM: 'gold', SEVERITY_LOW: 'yellowgreen', SEVERITY_INFO: 'lightskyblue'}; pie_colors = [colors.get(label, 'grey') for label in labels]; ax = fig.add_subplot(111)
    if not sizes: ax.text(0.5, 0.5, 'No vulnerabilities found', ha='center', va='center'); ax.axis('off')
    else: ax.pie(sizes, labels=labels, colors=pie_colors, autopct='%1.1f%%', startangle=90, wedgeprops={'edgecolor': 'black'}); ax.axis('equal'); ax.set_title('Vulnerability Severity Distribution')
    canvas_widget.draw()


# --- GUI Construction Functions --- (Helper functions remain largely the same)
def _build_control_frame(root: tk.Tk) -> Tuple[ttk.Frame, ttk.Entry, ttk.Combobox, ttk.Entry, ttk.Button]:
    control_frame = ttk.Frame(root, padding="10"); control_frame.pack(fill=tk.X, padx=5, pady=5)
    ip_label = ttk.Label(control_frame, text="Target (IP/Hostname/URL):"); ip_label.pack(side=tk.LEFT, padx=(0, 5))
    ip_entry = ttk.Entry(control_frame, width=30); ip_entry.pack(side=tk.LEFT, padx=(0, 10))
    scan_type_label = ttk.Label(control_frame, text="Scan Type:"); scan_type_label.pack(side=tk.LEFT, padx=(0, 5))
    scan_options = ["Common Ports", "Extended Ports", "All Ports (1-65535)", "Custom Range"]
    scan_type_combo = ttk.Combobox(control_frame, values=scan_options, width=20, state="readonly"); scan_type_combo.pack(side=tk.LEFT, padx=(0, 10)); scan_type_combo.set(scan_options[0])
    custom_range_entry = ttk.Entry(control_frame, width=15, state="disabled"); custom_range_entry.pack(side=tk.LEFT, padx=(0, 10)); custom_range_entry.insert(0, "1-1024")
    scan_button = ttk.Button(control_frame, text="Start Scan"); scan_button.pack(side=tk.LEFT, padx=5, pady=5)
    return control_frame, ip_entry, scan_type_combo, custom_range_entry, scan_button

def _build_results_panes(root: tk.Tk) -> Tuple[tk.PanedWindow, scrolledtext.ScrolledText, ttk.Treeview]:
    main_paned_window = tk.PanedWindow(root, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=6); main_paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    top_pane = tk.PanedWindow(main_paned_window, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=6); main_paned_window.add(top_pane, stretch="always")
    log_frame = ttk.LabelFrame(top_pane, text="Scan Log", padding="5"); top_pane.add(log_frame, stretch="always", width=400)
    output_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, state='disabled'); output_text.pack(fill=tk.BOTH, expand=True)
    vulnerability_frame = ttk.LabelFrame(top_pane, text="Detected Vulnerabilities", padding="5"); top_pane.add(vulnerability_frame, stretch="always", width=600)
    tree_cols = ("Port", "Version", "Severity", "Description", "CVSS")
    vulnerability_tree = ttk.Treeview(vulnerability_frame, columns=tree_cols, show="headings");
    for col in tree_cols: vulnerability_tree.heading(col, text=col)
    vulnerability_tree.column("Port", width=60, anchor="center", stretch=False); vulnerability_tree.column("Version", width=100, anchor="w", stretch=False); vulnerability_tree.column("Severity", width=80, anchor="w", stretch=False); vulnerability_tree.column("Description", width=300, anchor="w", stretch=True); vulnerability_tree.column("CVSS", width=60, anchor="center", stretch=False)
    tree_scrollbar = ttk.Scrollbar(vulnerability_frame, orient="vertical", command=vulnerability_tree.yview); vulnerability_tree.configure(yscrollcommand=tree_scrollbar.set); tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y); vulnerability_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    return main_paned_window, output_text, vulnerability_tree

def _build_bottom_pane(parent: tk.PanedWindow) -> Tuple[ttk.Progressbar, ttk.Frame, FigureCanvasTkAgg, plt.Figure]:
    bottom_pane = ttk.Frame(parent, padding="5"); parent.add(bottom_pane, stretch="never")
    progress_bar = ttk.Progressbar(bottom_pane, orient="horizontal", mode="determinate", style="Green.Horizontal.TProgressbar"); progress_bar.pack(fill=tk.X, padx=5, pady=(5, 10))
    chart_outer_frame = ttk.LabelFrame(bottom_pane, text="Severity Summary", padding="5"); chart_outer_frame.pack(fill=tk.BOTH, expand=True)
    fig = plt.Figure(figsize=(5, 3), dpi=100); chart_canvas = FigureCanvasTkAgg(fig, master=chart_outer_frame); canvas_widget = chart_canvas.get_tk_widget(); canvas_widget.pack(fill=tk.BOTH, expand=True)
    return progress_bar, chart_outer_frame, chart_canvas, fig

# --- Modified create_gui ---
def create_gui():
    """Creates and runs the main Tkinter GUI."""
    root = tk.Tk()
    root.title("Enhanced Network Scanner v1.5") # Version bump
    root.geometry("1000x750")
    style = ttk.Style(); style.theme_use('clam')
    style.configure("Green.Horizontal.TProgressbar", troughcolor='#EAEAEA', background='#4CAF50')
    style.configure("Red.Horizontal.TProgressbar", troughcolor='#EAEAEA', background='#F44336')

    message_queue: queue.Queue = queue.Queue()
    severity_counts: Dict[str, int] = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0, SEVERITY_INFO: 0}

    control_frame, ip_entry, scan_type_combo, custom_range_entry, scan_button = _build_control_frame(root)
    main_paned_window, output_text, vulnerability_tree = _build_results_panes(root) # Get tree here
    progress_bar, chart_outer_frame, chart_canvas, fig = _build_bottom_pane(main_paned_window)

    def on_scan_type_change(event=None):
        custom_range_entry.config(state="normal" if scan_type_combo.get() == "Custom Range" else "disabled")
    scan_type_combo.bind("<<ComboboxSelected>>", on_scan_type_change)

    chart_updater_func = lambda counts: update_pie_chart(counts, chart_outer_frame, chart_canvas, fig)

    # Configure scan button command (now passing vulnerability_tree)
    scan_button.config(command=lambda: start_scan_gui(
        ip_entry, scan_type_combo, custom_range_entry,
        output_text, progress_bar, message_queue, vulnerability_tree, # Pass tree here
        severity_counts, chart_updater_func, scan_button, root
    ))

    # Start the background message queue poller (passing vulnerability_tree)
    root.after(100, update_output_gui, output_text, message_queue, root, chart_updater_func, vulnerability_tree) # Pass tree

    disclaimer = ttk.Label(root, text="Disclaimer: Educational tool. Use responsibly. Vulnerability data is illustrative ONLY.", foreground="darkorange", font=("Arial", 8)); disclaimer.pack(side=tk.BOTTOM, pady=(5, 10))
    chart_updater_func(severity_counts); on_scan_type_change()
    root.mainloop()


# --- Modified Start Scan Function ---
def start_scan_gui(ip_entry: ttk.Entry, scan_type_combo: ttk.Combobox, custom_range_entry: ttk.Entry,
                   output_text: scrolledtext.ScrolledText, progress_bar: ttk.Progressbar, message_queue: queue.Queue,
                   vulnerability_tree: ttk.Treeview, severity_counts: Dict[str, int], # Added tree here
                   chart_updater: Callable, scan_button: ttk.Button, root: tk.Tk):
    """Validates input, determines ports, clears state, starts scan thread, handles post-scan."""
    ip = validate_ip_gui(ip_entry.get())
    if not ip: return

    ports_to_scan: List[int] = []
    scan_type: str = scan_type_combo.get()
    try: # Determine ports
        if scan_type == "Common Ports": ports_to_scan = COMMON_PORTS
        elif scan_type == "Extended Ports": ports_to_scan = EXTENDED_COMMON_PORTS
        elif scan_type == "All Ports (1-65535)":
             if not messagebox.askyesno("Confirm Scan", "Scanning all 65,535 ports can take VERY long and may trigger alerts. Proceed?"): return
             ports_to_scan = list(range(1, 65536))
        elif scan_type == "Custom Range":
            port_range_str = custom_range_entry.get().strip()
            if '-' not in port_range_str: raise ValueError("Range requires start-end format (e.g., 1-1024).")
            start_port, end_port = map(int, port_range_str.split('-'))
            if not (1 <= start_port <= end_port <= 65535): raise ValueError("Port values out of bounds (1-65535).")
            ports_to_scan = list(range(start_port, end_port + 1))
        else: messagebox.showerror("Error", "Invalid scan type selected."); return
        if not ports_to_scan: messagebox.showerror("Error", "No ports selected for scanning."); return
    except ValueError as e: messagebox.showerror("Error", f"Invalid Custom Port Range: {e}"); return
    except Exception as e: messagebox.showerror("Error", f"Error processing port selection: {e}"); return

    # --- Prepare UI for New Scan ---
    output_text.configure(state='normal'); output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting new scan on {ip} ({scan_type})...\n"); output_text.configure(state='disabled')
    vulnerability_tree.delete(*vulnerability_tree.get_children()) # Clear tree
    chart_updater({k: 0 for k in severity_counts}) # Clear chart
    progress_bar.config(style="Green.Horizontal.TProgressbar") # Reset style to Green
    while not message_queue.empty(): # Clear queue
        try: message_queue.get_nowait()
        except queue.Empty: break

    # --- Start Scan ---
    scan_button.config(state='disabled', text='Scanning...')
    scan_thread = threading.Thread(
        target=scan_host_with_progress,
        # Pass vulnerability_tree to scan thread (though it doesn't use it directly anymore)
        args=(ip, ports_to_scan, message_queue, progress_bar, vulnerability_tree, severity_counts),
        daemon=True
    )
    scan_thread.start()

    # --- Monitor Scan Completion ---
    scan_active = True
    def check_scan_completion():
        nonlocal scan_active;
        if not scan_active: return
        if scan_thread.is_alive(): root.after(200, check_scan_completion)
        else: scan_button.config(state='normal', text='Start Scan'); scan_active = False

    # --- Ensure GUI Updater Polling is Active ---
    # Pass vulnerability_tree to the polling function
    root.after(100, update_output_gui, output_text, message_queue, root, chart_updater, vulnerability_tree)
    root.after(100, check_scan_completion) # Start checking thread status

# --- Main Execution ---
if __name__ == "__main__":
    create_gui()