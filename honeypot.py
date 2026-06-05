#!/usr/bin/env python3
"""
Honeypot - Servidor señuelo multi-servicio para detectar y registrar
intentos de acceso no autorizados en tu red.
"""

import socket
import socketserver
import threading
import sys
import os
import time
import json
from datetime import datetime

BANNER = """
╔══════════════════════════════════════╗
║           Honeypot v1.0              ║
║    Servidor señuelo multi-servicio   ║
╚══════════════════════════════════════╝
"""

LOG_DIR = "logs"
LOG_FILE = None
log_lock = threading.Lock()

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
HTTP_BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><head><title>Admin Panel</title>"
    b"<style>body{font-family:monospace;background:#1a1a2e;color:#eee;margin:40px}"
    b"input{background:#16213e;border:1px solid #0f3460;color:#eee;padding:8px;width:200px}"
    b"</style></head><body>"
    b"<h2>!! Panel de Administracion</h2>"
    b"<form method='POST'>"
    b"<p>Usuario: <input name='user'></p>"
    b"<p>Password: <input name='pass' type='password'></p>"
    b"<p><input type='submit' value='Ingresar'></p>"
    b"</form><p style='color:#555'>Sistema de gestion v3.1</p></body></html>"
)
FTP_BANNER = b"220 ProFTPD 1.3.5 Server ready\r\n"
TELNET_BANNER = b"\r\nUbuntu 22.04 LTS\r\nlogin: "


def log(event_type, ip, port, data):
    """Registra un evento en el archivo de log."""
    global LOG_FILE
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "ip": ip,
        "port": port,
        "data": data,
    }
    line = json.dumps(entry, ensure_ascii=False)
    with log_lock:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()
        print(line)


def log_txt(event_type, ip, port, data):
    """Registra en formato legible."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{event_type:>8}] {ip}:{port} -> {data}"
    with log_lock:
        LOG_FILE.write(line + "\n")
        LOG_FILE.flush()
        print(line)


class SSHHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        port = self.client_address[1]
        log_txt("SSH_CONNECT", ip, port, "Conexion establecida")
        try:
            self.request.sendall(SSH_BANNER)
            data = self.request.recv(4096)
            if data:
                log_txt("SSH_BANNER", ip, port, data.strip()[:200])
                self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")

                for _ in range(3):
                    try:
                        self.request.settimeout(30)
                        data = self.request.recv(4096)
                        if not data:
                            break
                        decoded = data.hex()
                        log_txt("SSH_DATA", ip, port, decoded[:500])
                    except socket.timeout:
                        break
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            log_txt("SSH_ERROR", ip, port, str(e))
        log_txt("SSH_DISCONNECT", ip, port, "Conexion cerrada")


class HTTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        port = self.client_address[1]
        try:
            data = self.request.recv(8192)
            if data:
                decoded = data.decode("utf-8", errors="replace")
                first_line = decoded.split("\r\n")[0]
                log_txt("HTTP_REQ", ip, port, first_line)
                # Extraer credenciales del form si hay
                if "user=" in decoded or "pass=" in decoded:
                    log_txt("HTTP_FORM", ip, port, decoded[:500])
                self.request.sendall(HTTP_BANNER)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            log_txt("HTTP_ERROR", ip, port, str(e))


class FTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        port = self.client_address[1]
        log_txt("FTP_CONNECT", ip, port, "Conexion establecida")
        try:
            self.request.sendall(FTP_BANNER)
            while True:
                try:
                    self.request.settimeout(60)
                    data = self.request.recv(4096)
                    if not data:
                        break
                    cmd = data.decode("utf-8", errors="replace").strip()
                    log_txt("FTP_CMD", ip, port, cmd)

                    if cmd.upper().startswith("USER"):
                        self.request.sendall(b"331 Password required\r\n")
                    elif cmd.upper().startswith("PASS"):
                        log_txt("FTP_LOGIN", ip, port, cmd)
                        self.request.sendall(b"530 Login incorrect\r\n")
                    elif cmd.upper() == "QUIT":
                        self.request.sendall(b"221 Goodbye\r\n")
                        break
                    elif cmd.upper().startswith("AUTH"):
                        self.request.sendall(b"504 AUTH not supported\r\n")
                    else:
                        self.request.sendall(b"502 Command not implemented\r\n")
                except socket.timeout:
                    self.request.sendall(b"421 Timeout\r\n")
                    break
                except (ConnectionResetError, BrokenPipeError):
                    break
        except Exception as e:
            log_txt("FTP_ERROR", ip, port, str(e))
        log_txt("FTP_DISCONNECT", ip, port, "Conexion cerrada")


class TelnetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.client_address[0]
        port = self.client_address[1]
        log_txt("TELNET_CONNECT", ip, port, "Conexion establecida")
        try:
            self.request.sendall(TELNET_BANNER)
            user = self._read_line()
            if user:
                log_txt("TELNET_USER", ip, port, user.strip())
                self.request.sendall(b"Password: ")
                pwd = self._read_line()
                if pwd:
                    log_txt("TELNET_PASS", ip, port, pwd.strip())
                self.request.sendall(b"\r\nLogin incorrect\r\n")
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception as e:
            log_txt("TELNET_ERROR", ip, port, str(e))
        log_txt("TELNET_DISCONNECT", ip, port, "Conexion cerrada")

    def _read_line(self):
        buf = b""
        while True:
            try:
                self.request.settimeout(30)
                ch = self.request.recv(1)
                if not ch or ch == b"\n":
                    break
                buf += ch
            except socket.timeout:
                break
        return buf.decode("utf-8", errors="replace")


class ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


SERVICES = {
    "ssh": {"port": 2222, "handler": SSHHandler, "desc": "SSH falso"},
    "http": {"port": 8080, "handler": HTTPHandler, "desc": "HTTP falso"},
    "ftp": {"port": 2121, "handler": FTPHandler, "desc": "FTP falso"},
    "telnet": {"port": 2323, "handler": TelnetHandler, "desc": "Telnet falso"},
}


def start_service(name, cfg):
    """Inicia un servicio de honeypot en un thread."""
    try:
        server = ThreadedServer(("0.0.0.0", cfg["port"]), cfg["handler"])
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server, t
    except OSError as e:
        print(f"  [!] {name} ({cfg['port']}): {e}")
        return None, None


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Honeypot - Servidor señuelo multi-servicio",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s
  %(prog)s --ssh --http
  %(prog)s --ssh --ftp --telnet
  %(prog)s --http --port 80
  %(prog)s --ssh --ssh-port 22  # cuidado: necesita root
        """,
    )
    for name, cfg in SERVICES.items():
        parser.add_argument(f"--{name}", action="store_true", help=f"Activar {cfg['desc']} (puerto {cfg['port']})")
        parser.add_argument(f"--{name}-port", type=int, default=cfg["port"],
                            help=f"Puerto para {name} (default: {cfg['port']})")

    parser.add_argument("--all", action="store_true", help="Activar todos los servicios")
    parser.add_argument("-o", "--output", default="honeypot.log", help="Archivo de log")
    parser.add_argument("--json", action="store_true", help="Log en formato JSON")

    args = parser.parse_args()

    print(BANNER)
    print(f"  [!] ADVERTENCIA: Solo para uso en redes autorizadas")
    print(f"  [!] Los servicios simulan ser vulnerables para atraer atacantes")
    print()

    # Crear directorio de logs
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, args.output)
    global LOG_FILE
    LOG_FILE = open(log_path, "a")

    print(f"  [i] Log: {log_path}")
    print(f"  [i] Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Actualizar puertos
    for name in SERVICES:
        port_arg = f"{name}_port"
        port_val = getattr(args, port_arg.replace("-", "_"))
        SERVICES[name]["port"] = port_val

    if args.all:
        to_start = list(SERVICES.keys())
    else:
        to_start = [name for name in SERVICES if getattr(args, name)]

    if not to_start:
        to_start = list(SERVICES.keys())
        print(f"  [i] Ningun servicio especificado, iniciando todos")

    servers = []
    for name in to_start:
        cfg = SERVICES[name]
        print(f"  [+] Iniciando {cfg['desc']} en puerto {cfg['port']}...")
        srv, thr = start_service(name, cfg)
        if srv:
            servers.append((name, srv))
        else:
            print(f"  [!] No se pudo iniciar {name}")

    if not servers:
        print("  [!] No se pudo iniciar ningun servicio")
        sys.exit(1)

    print()
    print(f"  [>] Honeypot activo. Servicios corriendo:")
    for name, srv in servers:
        port = srv.server_address[1]
        print(f"       {name.upper():<8} -> 0.0.0.0:{port}")
    print()
    print(f"  [i] Presiona Ctrl+C para detener")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  [i] Deteniendo honeypot...")
        for name, srv in servers:
            srv.shutdown()
        LOG_FILE.close()
        print("  [i] Detenido.")


if __name__ == "__main__":
    main()
