# Importa bibliotecas padrão
import os
import time
import hashlib
import psutil
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# Caminho da pasta a ser monitorada (altere conforme necessário)
FOLDER_TO_MONITOR = "C:/Users/Lucas Monaco/Documents"

# Caminho da pasta de quarentena
QUARANTINE_FOLDER = os.path.join(FOLDER_TO_MONITOR, "quarentena")

# Caminho do arquivo de log
LOG_FILE = os.path.join(FOLDER_TO_MONITOR, "log.txt")

# Dicionário para armazenar os hashes dos arquivos (detecção de alterações)
file_hashes = {}

# Cria a pasta de quarentena se ela não existir
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# Função para registrar logs no terminal e no arquivo de log
def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Marca de tempo atual
    full_message = f"[{timestamp}] {message}"  # Formata a mensagem
    print(full_message)  # Exibe no terminal
    with open(LOG_FILE, "a", encoding="utf-8") as log:  # Abre o arquivo de log no modo append
        log.write(full_message + "\n")  # Escreve a mensagem

# Calcula o hash MD5 de um arquivo para detectar alterações
def calculate_hash(filepath):
    try:
        with open(filepath, "rb") as f:  # Abre o arquivo em modo binário
            return hashlib.md5(f.read()).hexdigest()  # Retorna o hash
    except:
        return None  # Retorna None caso ocorra erro ao abrir/ler

# Tira um "snapshot" inicial da pasta monitorada
def snapshot_folder(folder):
    for root, _, files in os.walk(folder):  # Percorre arquivos da pasta
        for name in files:
            path = os.path.join(root, name)
            if not path.startswith(QUARANTINE_FOLDER):  # Ignora a pasta de quarentena
                file_hashes[path] = calculate_hash(path)  # Salva o hash do arquivo

# Move um arquivo suspeito para a pasta de quarentena com timestamp
def move_to_quarantine(filepath):
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  # Timestamp para nome único
        filename = os.path.basename(filepath)  # Nome do arquivo original
        new_name = f"{timestamp}_{filename}"  # Novo nome com timestamp
        new_path = os.path.join(QUARANTINE_FOLDER, new_name)  # Caminho completo

        shutil.move(filepath, new_path)  # Move o arquivo
        log_event(f"🔒 Arquivo suspeito movido para quarentena: {new_path}")
    except Exception as e:
        log_event(f"ERRO ao mover para quarentena: {e}")  # Loga erro se falhar

# Classe que lida com eventos do sistema de arquivos
class RansomwareDetector(FileSystemEventHandler):

    # Quando um arquivo for modificado
    def on_modified(self, event):
        if not event.is_directory:  # Ignora diretórios
            path = event.src_path
            if path.startswith(QUARANTINE_FOLDER):  # Ignora a pasta de quarentena
                return

            new_hash = calculate_hash(path)  # Calcula novo hash
            old_hash = file_hashes.get(path)  # Pega hash antigo salvo

            if old_hash and new_hash != old_hash:  # Se mudou...
                log_event(f"⚠️ Arquivo modificado: {path}")

                # Se for suspeito, toma ação
                if self.looks_like_ransom(path):
                    log_event("🚨 Possível ransomware detectado!")
                    move_to_quarantine(path)
                    self.kill_suspect_process(path)

            file_hashes[path] = new_hash  # Atualiza o hash

    # Quando um novo arquivo for criado
    def on_created(self, event):
        if not event.is_directory:
            path = event.src_path
            if path.startswith(QUARANTINE_FOLDER):
                return

            log_event(f"📄 Novo arquivo criado: {path}")

            if self.looks_like_ransom(path):  # Se parecer com ransomware...
                log_event("🚨 Arquivo suspeito criado!")
                move_to_quarantine(path)
                self.kill_suspect_process(path)

    # Função que verifica se um arquivo tem características de ransomware
    def looks_like_ransom(self, path):
        suspicious_exts = ['.locked', '.crypt', '.enc', '.encrypted']  # Extensões comuns
        ransom_note_names = ['README', 'DECRYPT', 'RECOVER']  # Palavras-chave

        ext = os.path.splitext(path)[1].lower()  # Pega a extensão
        name = os.path.basename(path).upper()  # Nome do arquivo em caixa alta

        # Se tiver extensão suspeita ou nome típico de ransom note
        return ext in suspicious_exts or any(note in name for note in ransom_note_names)

    # Função para encerrar processo que estiver manipulando o arquivo
    def kill_suspect_process(self, filepath):
        for proc in psutil.process_iter(['pid', 'name', 'open_files']):  # Itera por processos
            try:
                if proc.info['open_files']:  # Verifica arquivos abertos
                    for f in proc.info['open_files']:
                        if filepath in f.path:  # Se o arquivo estiver aberto pelo processo
                            log_event(f"🔪 Matando processo suspeito: {proc.info['name']} (PID: {proc.info['pid']})")
                            proc.kill()  # Encerra o processo
                            return
            except Exception as e:
                log_event(f"ERRO ao tentar encerrar processo: {e}")  # Loga erro
                continue

# Função principal
if __name__ == "__main__":
    log_event("🛡️ Monitoramento de ransomware iniciado.")
    snapshot_folder(FOLDER_TO_MONITOR)  # Inicializa os hashes

    # Configura observador
    event_handler = RansomwareDetector()
    observer = Observer()
    observer.schedule(event_handler, FOLDER_TO_MONITOR, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(10)  # Loop principal: dorme e espera eventos
    except KeyboardInterrupt:  # Se o usuário parar com Ctrl+C
        observer.stop()
    observer.join()
    log_event("⛔ Monitoramento encerrado pelo usuário.")
