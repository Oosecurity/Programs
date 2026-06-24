#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import queue
import os
import datetime
from pathlib import Path

class BBReconGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BB-Recon - Bug Bounty Automation Tool")
        self.root.geometry("1100x780")
        self.queue = queue.Queue()
        self.setup_ui()

    def setup_ui(self):
        # Control Frame
        control = ttk.Frame(self.root, padding=10)
        control.pack(fill=tk.X)
        
        ttk.Label(control, text="Target Domain:").pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(control, width=40)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        self.target_entry.insert(0, "example.com")
        
        self.mode_var = tk.StringVar(value="full")
        ttk.Radiobutton(control, text="Full Recon", variable=self.mode_var, value="full").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(control, text="Monitor Mode", variable=self.mode_var, value="monitor").pack(side=tk.LEFT)
        
        self.start_btn = ttk.Button(control, text="🚀 Start Recon", command=self.start_recon)
        self.start_btn.pack(side=tk.RIGHT, padx=5)

        # Main Panes
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=6)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Log
        log_frame = ttk.LabelFrame(paned, text="Live Log", padding=5)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=25, state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        paned.add(log_frame, stretch="always")

        # Findings
        findings_frame = ttk.LabelFrame(paned, text="Findings & Report", padding=5)
        self.findings_tree = ttk.Treeview(findings_frame, columns=("Type", "Count", "Status"), show="headings")
        for col in ("Type", "Count", "Status"):
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=150)
        self.findings_tree.pack(fill=tk.BOTH, expand=True)
        paned.add(findings_frame, stretch="always")

        # Bottom Status
        self.status_bar = ttk.Label(self.root, text="Ready. Use only on authorized bug bounty programs.", relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.root.after(100, self.process_queue)

    def log(self, msg: str):
        self.queue.put(("log", msg))

    def update_findings(self, new_subs=0, alive=0, nuclei_high=0):
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        self.findings_tree.insert("", "end", values=("New Subdomains", new_subs, "Detected" if new_subs > 0 else "None"))
        self.findings_tree.insert("", "end", values=("Alive Hosts", alive, "Scanned"))
        self.findings_tree.insert("", "end", values=("High/Critical Vulns", nuclei_high, "Nuclei"))

    def process_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "log":
                    self.log_text.configure(state='normal')
                    self.log_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {item[1]}\n")
                    self.log_text.see(tk.END)
                    self.log_text.configure(state='disabled')
                elif item[0] == "findings":
                    self.update_findings(*item[1])
                elif item[0] == "done":
                    self.start_btn.config(state='normal')
                    self.status_bar.config(text=f"✅ Completed - Results in ~/bb-recon/{item[1]}")
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def run_command(self, cmd: list, cwd=None):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=300)
            if result.stdout:
                self.log(result.stdout.strip())
            if result.stderr:
                self.log(f"STDERR: {result.stderr.strip()}")
            return result.returncode == 0
        except Exception as e:
            self.log(f"Error: {e}")
            return False

    def start_recon(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter a target domain")
            return

        self.start_btn.config(state='disabled')
        self.log_text.configure(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.configure(state='disabled')
        self.log(f"🚀 Starting recon for {target}")

        thread = threading.Thread(target=self.recon_worker, args=(target,), daemon=True)
        thread.start()

    def recon_worker(self, target):
        mode = self.mode_var.get()
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = Path.home() / "bb-recon" / target
        base_dir.mkdir(parents=True, exist_ok=True)
        (base_dir / "subs").mkdir(exist_ok=True)
        (base_dir / "scans").mkdir(exist_ok=True)
        (base_dir / "screenshots").mkdir(exist_ok=True)
        (base_dir / "reports").mkdir(exist_ok=True)
        (base_dir / "logs").mkdir(exist_ok=True)

        self.log("📡 Subdomain Enumeration...")
        self.run_command(["subfinder", "-d", target, "-o", str(base_dir/"subs/subfinder.txt"), "-silent", "-rl", "50"])
        self.run_command(["assetfinder", "--subs-only", target], cwd=str(base_dir/"subs"))
        self.run_command(["amass", "enum", "-d", target, "-o", str(base_dir/"subs/amass.txt"), "-silent", "-max-dns-queries", "150"])
        self.run_command(["curl", "-s", "--max-time", "15", f"https://crt.sh/?q=%25.{target}&output=json"], 
                        cwd=str(base_dir/"subs"))  # jq processing skipped for simplicity

        # Simple dedup (can be improved)
        all_subs_file = base_dir / "subs/all_subs.txt"
        subprocess.run(f"cat {base_dir}/subs/*.txt 2>/dev/null | sort -u | grep -E '\\.{target}$' > {all_subs_file}", shell=True)

        # New subs detection
        prev_file = base_dir / "subs/previous_subs.txt"
        new_subs = 0
        if prev_file.exists():
            new_file = base_dir / "subs/new_subs.txt"
            subprocess.run(f"comm -23 <(sort {all_subs_file}) <(sort {prev_file}) > {new_file}", shell=True)
            new_subs = len(open(new_file).readlines()) if new_file.stat().st_size > 0 else 0
            if new_subs > 0:
                self.log(f"🆕 NEW SUBDOMAINS: {new_subs}")
                self.queue.put(("findings", (new_subs, 0, 0)))

        subprocess.run(f"cp {all_subs_file} {prev_file}", shell=True)

        # Live hosts
        self.log("🔍 Live hosts + tech detection...")
        alive_file = base_dir / "subs/alive.txt"
        self.run_command(["httpx", "-l", str(all_subs_file), "-o", str(alive_file), "-silent", "-status-code", 
                         "-tech-detect", "-json", "-rl", "25", "-t", "25", "-timeout", "12"])
        alive_count = len(open(alive_file).readlines()) if alive_file.exists() else 0

        # Nuclei
        self.log("🔬 Nuclei scan...")
        nuclei_file = base_dir / "reports/nuclei.txt"
        self.run_command(["nuclei", "-l", str(alive_file), "-o", str(nuclei_file), "-severity", "critical,high", 
                         "-silent", "-rl", "40", "-c", "8"])
        nuclei_high = subprocess.run(f"grep -c 'critical\\|high' {nuclei_file} || echo 0", shell=True, capture_output=True, text=True).stdout.strip()
        nuclei_high = int(nuclei_high)

        if nuclei_high > 0:
            self.log("⚠️ HIGH/CRITICAL FINDINGS DETECTED!")
            self.queue.put(("findings", (new_subs, alive_count, nuclei_high)))

        # EyeWitness (full mode only)
        if mode == "full":
            self.log("📸 EyeWitness screenshots...")
            eyewitness_dir = Path.home() / "EyeWitness"
            if eyewitness_dir.exists():
                self.run_command([str(eyewitness_dir/"eyewitness.sh"), "-f", str(alive_file), "--web", 
                                "-d", str(base_dir/"screenshots/report"), "--threads", "8"])

        # HTML Report
        report_file = base_dir / f"reports/summary_{ts}.html"
        with open(report_file, "w") as f:
            f.write(f"""<!DOCTYPE html><html><head><title>BB-Recon: {target}</title>
<style>body{{background:#111;color:#0f0;font-family:Arial;}}</style></head><body>
<h1>BB-Recon Report - {target}</h1>
<p>New Subdomains: {new_subs}</p>
<p>Alive Hosts: {alive_count}</p>
<p>High/Critical: {nuclei_high}</p>
<p><a href="../screenshots/report/report.html">View Screenshots</a></p>
</body></html>""")

        self.queue.put(("done", target))
        self.queue.put(("findings", (new_subs, alive_count, nuclei_high)))
        self.log(f"✅ Done! Open: file://{report_file}")

if __name__ == "__main__":
    root = tk.Tk()
    app = BBReconGUI(root)
    root.mainloop()