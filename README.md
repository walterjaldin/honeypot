# Honeypot 🍯

Servidor señuelo multi-servicio que simula servicios vulnerables para detectar y registrar intentos de acceso no autorizados en tu red.

> **⚠️ ADVERTENCIA:** Solo para uso en redes autorizadas. Un honeypot interactúa con atacantes — úsalo con responsabilidad.

## Características

- **4 servicios simulados**: SSH, HTTP, FTP, Telnet
- **Logging completo**: timestamp, IP, puerto, payload de cada interacción
- **Multi-hilo**: Maneja conexiones simultáneas
- **Puertos configurables**: Evita conflictos con servicios reales
- **Sin dependencias**: Solo librería estándar de Python 3
- **Formato JSON o TXT**: Logs estructurados o legibles

## Instalación

```bash
git clone https://github.com/walterjaldin/honeypot.git
cd honeypot
chmod +x honeypot.py
```

## Uso

### Iniciar todos los servicios

```bash
python3 honeypot.py --all
```

### Servicios específicos

```bash
python3 honeypot.py --ssh --http
```

### Con puertos personalizados

```bash
python3 honeypot.py --http --http-port 80 --ssh --ssh-port 22
```

### Solo HTTP

```bash
python3 honeypot.py --http
```

### Log en JSON

```bash
python3 honeypot.py --all --json
```

## Opciones

| Argumento | Descripción | Default |
|-----------|-------------|---------|
| `--ssh` | Activar SSH falso | off |
| `--ssh-port` | Puerto SSH | `2222` |
| `--http` | Activar HTTP falso | off |
| `--http-port` | Puerto HTTP | `8080` |
| `--ftp` | Activar FTP falso | off |
| `--ftp-port` | Puerto FTP | `2121` |
| `--telnet` | Activar Telnet falso | off |
| `--telnet-port` | Puerto Telnet | `2323` |
| `--all` | Activar todos los servicios | off |
| `-o, --output` | Archivo de log | `honeypot.log` |
| `--json` | Log en formato JSON | off |

## Servicios simulados

### HTTP (puerto 8080)
Muestra un panel de administración falso con formulario de login. Captura credenciales enviadas.

### SSH (puerto 2222)
Presenta banner de OpenSSH. Captura el banner del cliente y datos intercambiados.

### FTP (puerto 2121)
Simula servidor ProFTPD. Responde a comandos USER/PASS y registra intentos de login.

### Telnet (puerto 2323)
Muestra prompt de login de Ubuntu. Captura usuario y contraseña ingresados.

## Ejemplo de log

```
[2026-06-05 15:52:14] [HTTP_REQ] 192.168.1.100:49473 -> GET / HTTP/1.1
[2026-06-05 15:52:14] [HTTP_FORM] 192.168.1.100:49475 -> user=admin&pass=secret
[2026-06-05 15:52:14] [FTP_CONNECT] 192.168.1.100:49476 -> Conexion establecida
[2026-06-05 15:52:14] [FTP_LOGIN] 192.168.1.100:49476 -> PASS test123
[2026-06-05 15:52:14] [SSH_CONNECT] 192.168.1.100:49477 -> Conexion establecida
[2026-06-05 15:52:14] [TELNET_USER] 192.168.1.100:49478 -> admin
[2026-06-05 15:52:14] [TELNET_PASS] 192.168.1.100:49478 -> pass123
```

## Para qué sirve

- **Detección de escaneos**: Si alguien escanea tu red, el honeypot responderá
- **Registro de intentos de acceso**: Captura credenciales y comandos de atacantes
- **Alerta temprana**: Detecta actividad sospechosa antes de que lleguen a servicios reales
- **Investigación**: Analiza técnicas y herramientas usadas por atacantes

## Licencia

[MIT](LICENSE)
