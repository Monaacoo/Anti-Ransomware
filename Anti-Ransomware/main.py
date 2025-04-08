import os
import tkinter as tk
from tkinter import ttk, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import time
import shutil
import hashlib
import psutil
from datetime import datetime

# Pasta monitorada e quarentena
MONITOR_FOLDER = "C:/Users/SeuCaminho/Downloads"
QUARANTINE_FOLDER = os.path.join(MONITOR_FOLDER, "quarentena")
LOG_FILE = os.path.join(MONITOR_FOLDER, "log.txt")
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
file_hashes = {}

# Interface
class RansomwareGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Ransomware")
        self.root.geometry("800x600")

        # Quarentena
        ttk.Label(root, text="Arquivos Quarentenados:").pack()
        self.quarantine_list = tk.Listbox(root, height=6)
        self.quarantine_list.pack(fill=tk.X, padx=10)

        # Processos
        ttk.Label(root, text="Processos Finalizados:").pack()
        self.process_list = tk.Listbox(root, height=6)
        self.process_list.pack(fill=tk.X, padx=10)

        # Log ao vivo
        ttk.Label(root, text="Log ao Vivo:").pack()
        self.log_text = scrolledtext.ScrolledText(root, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10)

    def add_log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_msg = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, full_msg)
        self.log_text.see(tk.END)
        with open(LOG_FILE, "a", encoding="utf-8") as log:
            log.write(full_msg)

    def add_quarantine(self, file):
        self.quarantine_list.insert(tk.END, file)

    def add_process(self, proc):
        self.process_list.insert(tk.END, proc)

# Funções auxiliares
def calculate_hash(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return None

def snapshot():
    for root, _, files in os.walk(MONITOR_FOLDER):
        for f in files:
            path = os.path.join(root, f)
            if not path.startswith(QUARANTINE_FOLDER):
                file_hashes[path] = calculate_hash(path)

def move_to_quarantine(path, gui):
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(path)
        new_name = f"{ts}_{name}"
        new_path = os.path.join(QUARANTINE_FOLDER, new_name)
        shutil.move(path, new_path)
        gui.add_log(f"Arquivo movido para quarentena: {new_path}")
        gui.add_quarantine(new_name)
    except Exception as e:
        gui.add_log(f"Erro ao mover para quarentena: {e}")

def kill_process_using(path, gui):
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            if proc.info['open_files']:
                for f in proc.info['open_files']:
                    if path == f.path:
                        proc.kill()
                        gui.add_log(f"Processo finalizado: {proc.info['name']} (PID: {proc.info['pid']})")
                        gui.add_process(f"{proc.info['name']} (PID: {proc.info['pid']})")
                        return
        except:
            continue

def looks_like_ransom(path):
    ext = os.path.splitext(path)[1].lower()
    name = os.path.basename(path).upper()
    suspicious_exts = ['.locked', '.enc', '.crypt', '.encrypted']
    ransom_names = ['README', 'DECRYPT', 'RECOVER']
    return ext in suspicious_exts or any(x in name for x in ransom_names)

# Watchdog handler
class Handler(FileSystemEventHandler):
    def __init__(self, gui):
        self.gui = gui

    def on_modified(self, event):
        if not event.is_directory:
            path = event.src_path
            if path.startswith(QUARANTINE_FOLDER):
                return
            new = calculate_hash(path)
            old = file_hashes.get(path)
            if old and new != old:
                self.gui.add_log(f"Arquivo modificado: {path}")
                if looks_like_ransom(path):
                    move_to_quarantine(path, self.gui)
                    kill_process_using(path, self.gui)
            file_hashes[path] = new

    def on_created(self, event):
        if not event.is_directory:
            path = event.src_path
            if path.startswith(QUARANTINE_FOLDER):
                return
            self.gui.add_log(f"Arquivo criado: {path}")
            if looks_like_ransom(path):
                move_to_quarantine(path, self.gui)
                kill_process_using(path, self.gui)
            file_hashes[path] = calculate_hash(path)

# Iniciar GUI + Observer

def start_monitor(gui):
    snapshot()
    observer = Observer()
    observer.schedule(Handler(gui), MONITOR_FOLDER, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == '__main__':
    root = tk.Tk()
    gui = RansomwareGUI(root)
    thread = threading.Thread(target=start_monitor, args=(gui,), daemon=True)
    thread.start()
    root.mainloop()
