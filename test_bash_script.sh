#!/usr/bin/env bash
#set -euo pipefail

# --- Simple variable assignments ---
URL="https://example.com/archive.tar.gz"
DEST="/tmp/deploy"
LOGFILE="/var/log/deploy.log"
USER="deployuser"
GROUP="deploygroup"
ENC_PAYLOAD="IyEvYmluL2Jhc2gKZWNobyAiSGVsbG8sIHRoaXMgaXMgYSBwYXlsb2FkIGZyb20gYmFzZTY0IgpkYXRlKCkgeyBlY2hvICJQYXlsb2FkIGV4ZWN1dGlvbiIgfQ=="

# --- Function definition ---
function log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOGFILE"
}

# --- Decode an embedded base64 payload and execute it ---
echo "$ENC_PAYLOAD" | base64 -d | bash

# --- Create directories and set permissions ---
mkdir -p "$DEST"/{bin,lib,config,temp}
chmod 700 "$DEST"/temp
chown -R "$USER":"$GROUP" "$DEST"

log "Directories created"

# --- Download and extract an archive ---
if command -v curl &>/dev/null; then
    curl -fSL "$URL" -o /tmp/archive.tar.gz
else
    wget -qO /tmp/archive.tar.gz "$URL"
fi

log "Archive downloaded"

tar xzf /tmp/archive.tar.gz -C "$DEST"/lib
mv "$DEST"/lib/archive/* "$DEST"/lib/
rmdir "$DEST"/lib/archive

log "Archive extracted"

# --- Install dependencies via package manager ---
if command -v apt-get &>/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx unzip
elif command -v yum &>/dev/null; then
    yum install -y epel-release
    yum install -y nginx unzip
else
    echo "No supported package manager found" >&2
    exit 1
fi

log "Dependencies installed"

# --- Configure nginx ---
cat > "$DEST"/config/nginx.conf <<'EOF'
user  www-data;
worker_processes  auto;
error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       8080;
        server_name  localhost;
        location / {
            root   '"$DEST"'/bin;
            index  index.html index.htm;
        }
    }
}
EOF

ln -sf "$DEST"/config/nginx.conf /etc/nginx/nginx.conf
systemctl restart nginx

log "nginx configured and restarted"

# --- Loop over sample files, compress, and move ---
for file in "$DEST"/lib/*.so; do
    gzip -9 "$file"
    mv "${file}.gz" "$DEST"/bin/
done

log "Library files compressed and moved"

# --- Cleanup temporary files ---
rm -rf /tmp/archive.tar.gz
rm -rf "$DEST"/temp/*

log "Cleaned up temporary files"

# --- Use a here-document to execute a multi-line command via ssh ---
SSH_TARGET="remote.example.com"
ssh "$USER@$SSH_TARGET" <<SSH_CMD
    set -e
    mkdir -p ~/backup
    cp -r "$DEST"/bin ~/backup/
    chmod -R 755 ~/backup/bin
SSH_CMD

log "Remote backup completed"

# --- Final summary ---
echo "Deployment finished successfully."
exit 0
