import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading, json, smtplib, os, time, subprocess
from email.mime.text import MIMEText

SETTINGS_FILE = "settings.json"

class Settings:
    def __init__(self):
        self.smtp_server = ""
        self.smtp_port = 587
        self.email = ""
        self.password = ""
        self.alert_enabled = True
        self.load()

    def save(self):
        with open(SETTINGS_FILE, "w") as f:
            json.dump(self.__dict__, f)

    def load(self):
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                self.__dict__.update(json.load(f))

class FirewallAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self):
        missing = []
        redundant = []
        outdated = []
        if not any(r for r in self.rules if r[5] == "DROP"):
            missing.append("Default DROP rule")
        seen = set()
        for r in self.rules:
            t = tuple(r)
            if t in seen:
                redundant.append(r)
            seen.add(t)
            if r[1] == "192.168.0.1":
                outdated.append(r)
        return missing, redundant, outdated

class EmailAlertSystem:
    def __init__(self, settings):
        self.settings = settings

    def send_alert(self, subject, body):
        if not self.settings.alert_enabled:
            return
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.settings.email
            msg["To"] = self.settings.email
            with smtplib.SMTP(self.settings.smtp_server, self.settings.smtp_port) as server:
                server.starttls()
                server.login(self.settings.email, self.settings.password)
                server.sendmail(self.settings.email, [self.settings.email], msg.as_string())
        except Exception as e:
            print("Email error:", e)

class SystemFirewallMonitor(threading.Thread):
    def __init__(self, callback):
        super().__init__(daemon=True)
        self.callback = callback
        self.prev_rules = None
        self.running = True

    def get_rules(self):
        try:
            if os.name == 'posix':
                result = subprocess.check_output(["iptables", "-S"]).decode()
            else:
                result = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]).decode()
            return result.strip().split("\n")
        except:
            return []

    def run(self):
        while self.running:
            rules = self.get_rules()
            if self.prev_rules and rules != self.prev_rules:
                self.callback("Firewall rules changed!", "\n".join(rules))
            self.prev_rules = rules
            time.sleep(5)

class FirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Firewall Tool")
        self.settings = Settings()
        self.rules = []
        self.emailer = EmailAlertSystem(self.settings)

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.setup_rules_tab()
        self.setup_simulation_tab()
        self.setup_monitor_tab()
        self.setup_settings_tab()

        self.monitor = SystemFirewallMonitor(self.firewall_changed)
        self.monitor.start()

    # --- Rules Tab ---
    def setup_rules_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Rules")

        self.rules_tree = ttk.Treeview(frame, columns=("Proto","Src","Dst","SPort","DPort","Action"), show="headings")
        for col in self.rules_tree["columns"]:
            self.rules_tree.heading(col, text=col)
        self.rules_tree.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Add", command=self.add_rule).pack(side="left")
        ttk.Button(btn_frame, text="Edit", command=self.edit_rule).pack(side="left")
        ttk.Button(btn_frame, text="Delete", command=self.delete_rule).pack(side="left")
        ttk.Button(btn_frame, text="Load from File", command=self.load_rules).pack(side="left")
        ttk.Button(btn_frame, text="Save to File", command=self.save_rules).pack(side="left")
        ttk.Button(btn_frame, text="Analyze", command=self.analyze_rules).pack(side="left")

    def add_rule(self):
        data = [simpledialog.askstring("Add Rule", f"{field}:") for field in ["Proto","Src","Dst","SPort","DPort","Action"]]
        if all(data):
            self.rules.append(data)
            self.rules_tree.insert("", "end", values=data)

    def edit_rule(self):
        item = self.rules_tree.selection()
        if not item:
            return
        idx = self.rules_tree.index(item)
        current = self.rules[idx]
        new_data = [simpledialog.askstring("Edit Rule", f"{field}:", initialvalue=val) for field,val in zip(["Proto","Src","Dst","SPort","DPort","Action"], current)]
        if all(new_data):
            self.rules[idx] = new_data
            self.rules_tree.item(item, values=new_data)

    def delete_rule(self):
        item = self.rules_tree.selection()
        if not item:
            return
        idx = self.rules_tree.index(item)
        self.rules.pop(idx)
        self.rules_tree.delete(item)

    def load_rules(self):
        path = filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if path:
            with open(path) as f:
                self.rules = json.load(f)
            self.rules_tree.delete(*self.rules_tree.get_children())
            for r in self.rules:
                self.rules_tree.insert("", "end", values=r)

    def save_rules(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            with open(path,"w") as f:
                json.dump(self.rules, f)

    def analyze_rules(self):
        analyzer = FirewallAnalyzer(self.rules)
        missing, redundant, outdated = analyzer.analyze()
        messagebox.showinfo("Analysis",
            f"Missing: {missing}\nRedundant: {redundant}\nOutdated: {outdated}")

    # --- Simulation Tab ---
    def setup_simulation_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Simulation")

        form = ttk.Frame(frame)
        form.pack(fill="x")
        self.sim_fields = {}
        for field in ["Proto","Src","Dst","SPort","DPort"]:
            ttk.Label(form, text=field).pack(side="left")
            e = ttk.Entry(form, width=12)
            e.pack(side="left")
            self.sim_fields[field] = e
        ttk.Button(form, text="Test Packet", command=self.test_packet).pack(side="left")

        self.sim_log = tk.Text(frame, height=15, bg="black", fg="white")
        self.sim_log.pack(fill="both", expand=True)

    def test_packet(self):
        pkt = [self.sim_fields[f].get() for f in ["Proto","Src","Dst","SPort","DPort"]]
        allowed = any(r[:5] == pkt and r[5] == "ACCEPT" for r in self.rules)
        color = "green" if allowed else "red"
        self.sim_log.insert("end", f"{'ALLOWED' if allowed else 'BLOCKED'}: {pkt}\n", color)
        self.sim_log.tag_configure("green", foreground="lime")
        self.sim_log.tag_configure("red", foreground="red")
        if not allowed:
            self.emailer.send_alert("Suspicious Packet", f"Packet blocked: {pkt}")

    # --- Monitor Tab ---
    def setup_monitor_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Monitor")

        self.monitor_log = tk.Text(frame, height=20)
        self.monitor_log.pack(fill="both", expand=True)

    def firewall_changed(self, subject, body):
        self.monitor_log.insert("end", f"{subject}\n{body}\n{'-'*50}\n")
        self.emailer.send_alert(subject, body)

    # --- Settings Tab ---
    def setup_settings_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Settings")

        fields = [("SMTP Server", "smtp_server"), ("Port", "smtp_port"), ("Email", "email"), ("Password", "password")]
        self.setting_entries = {}
        for label, attr in fields:
            ttk.Label(frame, text=label).pack()
            entry = ttk.Entry(frame, show="*" if "pass" in attr else None)
            entry.insert(0, str(getattr(self.settings, attr)))
            entry.pack()
            self.setting_entries[attr] = entry

        self.alert_var = tk.BooleanVar(value=self.settings.alert_enabled)
        ttk.Checkbutton(frame, text="Enable Alerts", variable=self.alert_var).pack()

        ttk.Button(frame, text="Save Settings", command=self.save_settings).pack()

    def save_settings(self):
        for attr, entry in self.setting_entries.items():
            val = entry.get()
            setattr(self.settings, attr, int(val) if attr == "smtp_port" else val)
        self.settings.alert_enabled = self.alert_var.get()
        self.settings.save()
        messagebox.showinfo("Settings", "Saved successfully")

if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
