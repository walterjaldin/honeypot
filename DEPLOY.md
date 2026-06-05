# Despliegue del Honeypot en Ubuntu/Debian

Guía completa para implementar el honeypot como servicio persistente en un servidor Ubuntu o Debian.

---

## 1. Instalación básica

```bash
# Actualizar el sistema
sudo apt update && sudo apt upgrade -y

# Instalar Python 3 (viene por defecto en Ubuntu 20.04+)
sudo apt install -y python3

# Clonar o copiar los archivos
sudo mkdir -p /opt/honeypot
sudo cp honeypot.py /opt/honeypot/
sudo chmod +x /opt/honeypot/honeypot.py

# Crear estructura de directorios
sudo mkdir -p /opt/honeypot/logs
```

---

## 2. Servicio systemd

Crear el archivo de servicio:

```bash
sudo nano /etc/systemd/system/honeypot.service
```

Contenido:

```ini
[Unit]
Description=Honeypot - Servidor señuelo multi-servicio
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/honeypot/honeypot.py --all --json
WorkingDirectory=/opt/honeypot
Restart=always
RestartSec=5
User=nobody
Group=nogroup
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=/opt/honeypot/logs
StandardOutput=append:/opt/honeypot/logs/stdout.log
StandardError=append:/opt/honeypot/logs/stderr.log

[Install]
WantedBy=multi-user.target
```

Activar e iniciar:

```bash
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot
sudo systemctl status honeypot
```

Ver logs del servicio:

```bash
sudo journalctl -u honeypot -f
```

---

## 3. Servicios personalizados

Si solo quieres ciertos servicios o puertos específicos, modifica `ExecStart`:

### Solo HTTP + SSH en puertos no estándar

```ini
ExecStart=/usr/bin/python3 /opt/honeypot/honeypot.py \
  --http --http-port 8080 \
  --ssh --ssh-port 2222 \
  --json
```

### Todos los servicios con puertos no estándar (seguro, sin root)

```ini
ExecStart=/usr/bin/python3 /opt/honeypot/honeypot.py \
  --http --http-port 8080 \
  --ssh --ssh-port 2222 \
  --ftp --ftp-port 2121 \
  --telnet --telnet-port 2323 \
  --json
```

> **Importante:** No uses puertos < 1024 (22, 80, 21, 23) a menos que ejecutes como root. Usa los puertos no estándar por defecto.

### Servicios en puertos privilegiados (necesita root)

Si realmente quieres usar puertos como 22 o 80:

```ini
[Service]
ExecStart=/usr/bin/python3 /opt/honeypot/honeypot.py --ssh --ssh-port 22
User=root
```

> **Riesgo:** Si el honeypot es comprometido, el atacante tiene acceso root. Prefiere redirección con iptables.

---

## 4. Redirección con iptables (puertos reales sin root)

Puedes hacer que el puerto 22 apunte al 2222 sin ejecutar el honeypot como root:

```bash
# Redirigir puerto 22 → 2222 (SSH)
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Redirigir puerto 80 → 8080 (HTTP)
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirigir puerto 21 → 2121 (FTP)
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121

# Redirigir puerto 23 → 2323 (Telnet)
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

Hacer persistente:

```bash
sudo apt install -y iptables-persistent
sudo netfilter-persistent save
```

Ahora el honeypot corre como `nobody` en puertos no privilegiados, pero aparece como si estuviera en los puertos reales.

---

## 5. Despliegue con Docker

### Dockerfile

```dockerfile
FROM python:3-slim

WORKDIR /app
COPY honeypot.py .
RUN chmod +x honeypot.py

RUN mkdir -p /app/logs

EXPOSE 2222 8080 2121 2323

CMD ["python3", "honeypot.py", "--all", "--json"]
```

### Construir y ejecutar

```bash
docker build -t honeypot .
docker run -d \
  --name honeypot \
  --restart always \
  -p 2222:2222 \
  -p 8080:8080 \
  -p 2121:2121 \
  -p 2323:2323 \
  -v $(pwd)/logs:/app/logs \
  honeypot
```

### Con puertos reales via host network

```bash
docker run -d \
  --name honeypot \
  --restart always \
  --network host \
  -v $(pwd)/logs:/app/logs \
  honeypot \
  python3 honeypot.py --ssh --ssh-port 2222 --http --http-port 8080
```

---

## 6. Monitoreo y alertas

### Logrotate (rotar logs automáticamente)

```bash
sudo nano /etc/logrotate.d/honeypot
```

```conf
/opt/honeypot/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### Alerta en Telegram

```bash
sudo nano /opt/honeypot/alerter.sh
```

```bash
#!/bin/bash
TELEGRAM_TOKEN="tu_token"
CHAT_ID="tu_chat_id"
LOG="/opt/honeypot/logs/honeypot.log"

tail -Fn0 "$LOG" | while read line; do
  if echo "$line" | grep -qE "FTP_LOGIN|HTTP_FORM|TELNET_PASS|SSH_BANNER"; then
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
      -d "chat_id=$CHAT_ID&text=🔥 Honeypot: $line" > /dev/null
  fi
done
```

```bash
chmod +x /opt/honeypot/alerter.sh

# Como servicio
sudo nano /etc/systemd/system/honeypot-alert.service
```

```ini
[Unit]
Description=Honeypot Alerter
After=honeypot.service

[Service]
ExecStart=/opt/honeypot/alerter.sh
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
```

### Integración con SIEM (ELK)

```bash
# Enviar logs a Logstash
sudo apt install -y filebeat
sudo nano /etc/filebeat/filebeat.yml
```

```yaml
filebeat.inputs:
- type: log
  paths:
    - /opt/honeypot/logs/honeypot.log
  json.keys_under_root: true

output.logstash:
  hosts: ["192.168.1.200:5044"]
```

---

## 7. Seguridad del honeypot

### Aislar con AppArmor

```bash
sudo nano /etc/apparmor.d/usr.bin.python3.honeypot
```

```conf
#include <tunables/global>

/usr/bin/python3 /opt/honeypot/honeypot.py {
  #include <abstractions/base>
  #include <abstractions/python>

  /opt/honeypot/** r,
  /opt/honeypot/logs/** rw,
  network tcp,
  deny network raw,
  deny /etc/shadow r,
}
```

```bash
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.python3.honeypot
```

### Firewall: solo permitir acceso al honeypot

```bash
# Permitir trafico hacia el honeypot
sudo ufw allow 2222/tcp comment 'Honeypot SSH'
sudo ufw allow 8080/tcp comment 'Honeypot HTTP'
sudo ufw allow 2121/tcp comment 'Honeypot FTP'
sudo ufw allow 2323/tcp comment 'Honeypot Telnet'
```

---

## 8. Verificar que funciona

```bash
# Probar HTTP
curl -s http://localhost:8080/ | head -3

# Probar SSH
ssh -p 2222 fakeuser@localhost

# Probar FTP
ftp localhost 2121

# Ver logs
tail -f /opt/honeypot/logs/honeypot.log

# Verificar servicio
sudo systemctl status honeypot
```

---

## 9. Estructura final del directorio

```
/opt/honeypot/
├── honeypot.py
├── logs/
│   ├── honeypot.log
│   ├── stdout.log
│   └── stderr.log
└── alerter.sh         (opcional)
```

---

## 10. Resumen de puertos

| Servicio | Puerto por defecto | Puerto recomendado |
|----------|-------------------|--------------------|
| SSH      | 22                | 2222               |
| HTTP     | 80                | 8080               |
| FTP      | 21                | 2121               |
| Telnet   | 23                | 2323               |

Usa los puertos recomendados + iptables si quieres que aparezcan en los puertos reales.
