#!/bin/bash
set -e

# Redirigir salida a log para debugging
exec > >(tee /var/log/startup-script.log | logger -t startup-script -s 2>/dev/console) 2>&1

# Colores para logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${GREEN}[$(date +'%F %T')] $1${NC}"; }
error()   { echo -e "${RED}[$(date +'%F %T')] ERROR: $1${NC}"; }
info()    { echo -e "${BLUE}[$(date +'%F %T')] INFO: $1${NC}"; }
warn()    { echo -e "${YELLOW}[$(date +'%F %T')] WARN: $1${NC}"; }

# ➕ Obtener metadatos desde GCP con mejor manejo de errores
log "🔍 Obteniendo metadatos de GCP..."
INSTANCE_NAME=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/instance-name" -H "Metadata-Flavor: Google" 2>/dev/null || echo "odoo-instance")
DEPLOYMENT_TIME=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/deployment-time" -H "Metadata-Flavor: Google" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
GITHUB_ACTOR=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-actor" -H "Metadata-Flavor: Google" 2>/dev/null || echo "unknown")

# Variables de configuración
ODOO_VERSION="18.0"
ODOO_USER="odoo"
ODOO_HOME="/opt/odoo"
ODOO_CONFIG="/etc/odoo/odoo.conf"
ODOO_PORT="8069"
POSTGRES_USER="odoo"
POSTGRES_PASSWORD="odoo123"
ADMIN_PASSWORD="admin123"  # Contraseña maestra para crear bases de datos

log "🚀 Iniciando instalación de Odoo 18 Community (Modo Selector DB)"
info "📋 Instancia: $INSTANCE_NAME"
info "📅 Despliegue: $DEPLOYMENT_TIME"
info "👤 GitHub actor: $GITHUB_ACTOR"

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Función para verificar conectividad a internet
check_internet() {
    if ! curl -s --max-time 10 http://www.google.com > /dev/null; then
        error "No hay conectividad a internet"
        exit 1
    fi
}

# Verificar conectividad
log "🌐 Verificando conectividad a internet..."
check_internet

# Actualización del sistema
log "📦 Actualizando sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

# Instalar dependencias completas del sistema
log "🔧 Instalando dependencias del sistema..."
apt-get install -y \
    wget git curl unzip python3 python3-venv python3-pip python3-dev \
    libxml2-dev libxslt1-dev libevent-dev libsasl2-dev libldap2-dev libpq-dev \
    libjpeg-dev libpng-dev libfreetype6-dev liblcms2-dev libwebp-dev libharfbuzz-dev \
    libfribidi-dev libxcb1-dev libfontconfig1 xfonts-base xfonts-75dpi gcc g++ make \
    build-essential libssl-dev libffi-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libncurses5-dev libncursesw5-dev xz-utils tk-dev libgdbm-dev libc6-dev \
    libnss3-dev libpython3-dev python3-wheel python3-setuptools ca-certificates \
    librust-openssl-dev pkg-config software-properties-common lsb-release

# Instalar PostgreSQL con mejor configuración
log "🐘 Instalando PostgreSQL..."
apt-get install -y postgresql postgresql-contrib postgresql-server-dev-all

# Configurar PostgreSQL para mejor rendimiento
log "⚙️ Configurando PostgreSQL..."
PG_VERSION=$(pg_config --version | awk '{print $2}' | sed 's/\..*//')
PG_CONF="/etc/postgresql/$PG_VERSION/main/postgresql.conf"

if [ -f "$PG_CONF" ]; then
    # Backup de configuración original
    cp "$PG_CONF" "$PG_CONF.backup"
    
    # Optimizaciones básicas para Odoo
    sed -i "s/#max_connections = 100/max_connections = 200/" "$PG_CONF"
    sed -i "s/#shared_buffers = 128MB/shared_buffers = 256MB/" "$PG_CONF"
    sed -i "s/#effective_cache_size = 4GB/effective_cache_size = 1GB/" "$PG_CONF"
    sed -i "s/#maintenance_work_mem = 64MB/maintenance_work_mem = 128MB/" "$PG_CONF"
    sed -i "s/#work_mem = 4MB/work_mem = 8MB/" "$PG_CONF"
fi

systemctl enable postgresql
systemctl start postgresql

# Validar PostgreSQL con reintentos
log "🔍 Verificando estado de PostgreSQL..."
for i in {1..5}; do
    if systemctl is-active --quiet postgresql; then
        log "✅ PostgreSQL está ejecutándose"
        break
    fi
    warn "PostgreSQL no está listo, esperando... (intento $i/5)"
    sleep 5
    if [ $i -eq 5 ]; then
        error "PostgreSQL no pudo iniciarse"
        systemctl status postgresql --no-pager
        exit 1
    fi
done

# Crear usuario PostgreSQL SOLAMENTE (sin base de datos)
log "🗄️ Configurando usuario PostgreSQL..."
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname = '$POSTGRES_USER'" | grep -q 1 || {
    sudo -u postgres psql -c "CREATE USER $POSTGRES_USER WITH CREATEDB PASSWORD '$POSTGRES_PASSWORD';"
    log "✅ Usuario PostgreSQL creado: $POSTGRES_USER"
}

# Crear usuario del sistema Odoo
log "👤 Creando usuario del sistema Odoo..."
if ! id "$ODOO_USER" &>/dev/null; then
    adduser --system --quiet --home=$ODOO_HOME --group $ODOO_USER
    log "✅ Usuario del sistema creado: $ODOO_USER"
else
    info "Usuario $ODOO_USER ya existe"
fi

# Instalar wkhtmltopdf con mejor detección de versión
log "📄 Instalando wkhtmltopdf..."
cd /tmp
UBUNTU_VERSION=$(lsb_release -rs)
WKHTMLTOPDF_URL=""

case "$UBUNTU_VERSION" in
    "22.04")
        WKHTMLTOPDF_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.jammy_amd64.deb"
        ;;
    "20.04")
        WKHTMLTOPDF_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.focal_amd64.deb"
        ;;
    "24.04")
        WKHTMLTOPDF_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-3/wkhtmltox_0.12.6.1-3.noble_amd64.deb"
        ;;
    *)
        warn "Versión de Ubuntu no reconocida: $UBUNTU_VERSION, usando focal como fallback"
        WKHTMLTOPDF_URL="https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.focal_amd64.deb"
        ;;
esac

WKHTMLTOPDF_FILE=$(basename "$WKHTMLTOPDF_URL")
if [ ! -f "$WKHTMLTOPDF_FILE" ]; then
    wget -q "$WKHTMLTOPDF_URL" || {
        error "No se pudo descargar wkhtmltopdf"
        exit 1
    }
fi

dpkg -i "$WKHTMLTOPDF_FILE" || apt-get install -f -y
rm -f "$WKHTMLTOPDF_FILE"

# Verificar instalación de wkhtmltopdf
if command_exists wkhtmltopdf; then
    log "✅ wkhtmltopdf instalado correctamente"
else
    error "wkhtmltopdf no se instaló correctamente"
    exit 1
fi

# Clonar Odoo con mejor manejo
log "📥 Clonando Odoo $ODOO_VERSION..."
if [ -d "$ODOO_HOME" ]; then
    warn "Directorio $ODOO_HOME existe, eliminando..."
    rm -rf "$ODOO_HOME"
fi

git clone https://github.com/odoo/odoo --depth 1 --branch "$ODOO_VERSION" "$ODOO_HOME" || {
    error "No se pudo clonar Odoo"
    exit 1
}

chown -R $ODOO_USER:$ODOO_USER "$ODOO_HOME"

# Validaciones importantes
if [ ! -f "$ODOO_HOME/odoo-bin" ]; then
    error "No se encontró odoo-bin en $ODOO_HOME"
    ls -la "$ODOO_HOME/"
    exit 1
fi

if [ ! -f "$ODOO_HOME/requirements.txt" ]; then
    error "No se encontró requirements.txt en $ODOO_HOME"
    ls -la "$ODOO_HOME/"
    exit 1
fi

chmod +x "$ODOO_HOME/odoo-bin"
log "✅ Odoo clonado y configurado"

# Crear entorno virtual con mejor configuración
log "🐍 Creando entorno virtual Python..."
sudo -u $ODOO_USER python3 -m venv "$ODOO_HOME/venv"
chown -R $ODOO_USER:$ODOO_USER "$ODOO_HOME/venv"

# Actualizar pip, setuptools y wheel
log "📦 Actualizando herramientas de Python..."
sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/pip" install --upgrade pip setuptools wheel

# Instalar psycopg2-binary primero
log "🐘 Instalando psycopg2-binary..."
sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/pip" install psycopg2-binary

# Instalar dependencias de Python con mejor manejo de errores
log "📦 Instalando dependencias Python..."
if ! sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/pip" install \
    --no-cache-dir \
    --timeout 300 \
    --retries 3 \
    -r "$ODOO_HOME/requirements.txt"; then
    
    error "Falló la instalación de dependencias Python estándar"
    info "Intentando instalación alternativa con versiones específicas..."
    
    # Lista de dependencias críticas con versiones compatibles
    CRITICAL_DEPS=(
        "Babel>=2.6.0"
        "chardet"
        "cryptography"
        "decorator"
        "docutils"
        "freezegun"
        "gevent"
        "greenlet"
        "idna"
        "Jinja2"
        "libsass"
        "lxml"
        "psutil"
        "lxml_html_clean"
        "MarkupSafe"
        "num2words"
        "ofxparse"
        "passlib"
        "Pillow"
        "polib"
        "psutil"
        "pydot"
        "pyparsing"
        "PyPDF2"
        "pyserial"
        "python-dateutil"
        "python-stdnum"
        "pytz"
        "pyusb"
        "qrcode"
        "reportlab"
        "requests"
        "urllib3"
        "vobject"
        "Werkzeug"
        "xlrd"
        "XlsxWriter"
        "xlwt"
        "zeep"
        "babel"
        "rjsmin"
        "rcssmin"
        "pyOpenSSL"
        "cffi"
        "pycparser"
        "cryptography"
    )
    
    for dep in "${CRITICAL_DEPS[@]}"; do
        log "Instalando $dep..."
        sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/pip" install "$dep" || warn "Falló la instalación de $dep"
    done

    # Instalar lxml_html_clean si no está en requirements.txt
    log "📦 Instalando lxml_html_clean..."
    sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/pip" install lxml_html_clean || warn "Falló la instalación de lxml_html_clean"
fi

# Verificar instalación de Python
log "🔍 Verificando instalación de Python..."
sudo -u $ODOO_USER "$ODOO_HOME/venv/bin/python" -c "import odoo" 2>/dev/null || {
    warn "No se puede importar odoo directamente, pero continuando..."
}

# Función para configurar PostgreSQL para Odoo
configure_postgresql_for_odoo() {
    print_step "Configurando PostgreSQL para Odoo..."
    
    # Crear usuario de base de datos
    sudo -u postgres createuser -s $ODOO_USER 2>/dev/null || true
    
    # Configurar autenticación en pg_hba.conf
    PG_VERSION=$(sudo -u postgres psql -t -c "SELECT version();" | grep -oP '\d+\.\d+' | head -1)
    PG_HBA_FILE="/etc/postgresql/$PG_VERSION/main/pg_hba.conf"
    
    print_message "Configurando autenticación en $PG_HBA_FILE..."
    
    # Hacer backup del archivo original
    cp $PG_HBA_FILE ${PG_HBA_FILE}.backup
    
    # Configurar autenticación trust para conexiones locales
    sed -i "s/local   all             all                                     peer/local   all             all                                     trust/" $PG_HBA_FILE
    sed -i "s/host    all             all             127.0.0.1\/32            scram-sha-256/host    all             all             127.0.0.1\/32            trust/" $PG_HBA_FILE
    sed -i "s/host    all             all             127.0.0.1\/32            md5/host    all             all             127.0.0.1\/32            trust/" $PG_HBA_FILE
    sed -i "s/host    all             all             ::1\/128                 scram-sha-256/host    all             all             ::1\/128                 trust/" $PG_HBA_FILE
    sed -i "s/host    all             all             ::1\/128                 md5/host    all             all             ::1\/128                 trust/" $PG_HBA_FILE
    
    # Reiniciar PostgreSQL para aplicar cambios
    systemctl restart postgresql
    
    # Verificar que la conexión funciona
    print_message "Verificando conexión a PostgreSQL..."
    if sudo -u $ODOO_USER psql -h localhost -p 5432 -U $ODOO_USER postgres -c "\q" 2>/dev/null; then
        print_message "Conexión a PostgreSQL verificada correctamente"
    else
        print_warning "Problema con la conexión a PostgreSQL, pero continuando..."
    fi
    
    print_message "PostgreSQL configurado para Odoo"
}


# Configurar paths de addons mejorado
log "📁 Configurando paths de addons..."
ADDONS_PATH="$ODOO_HOME/addons"
if [ -d "$ODOO_HOME/odoo/addons" ]; then
    ADDONS_PATH="$ODOO_HOME/addons,$ODOO_HOME/odoo/addons"
fi

# Crear directorios necesarios
log "📁 Creando directorios de configuración..."
mkdir -p /etc/odoo /var/log/odoo /var/lib/odoo
chown -R $ODOO_USER:$ODOO_USER /var/log/odoo /var/lib/odoo

# ==================== CONFIGURACIÓN PARA SELECTOR DE BASE DE DATOS ====================
log "⚙️ Configurando Odoo para mostrar selector de base de datos..."

# Crear configuración SIN base de datos por defecto
cat > "$ODOO_CONFIG" << EOF
[options]
# Configuración para mostrar selector de base de datos
admin_passwd = $ADMIN_PASSWORD
db_host = localhost
db_port = 5432
db_user = $POSTGRES_USER
db_password = $POSTGRES_PASSWORD
# NO especificar db_name para forzar selector de BD
addons_path = $ADDONS_PATH

# Configuración para permitir gestión de BD
list_db = True
db_maxconn = 64
db_template = template0

# Logging
logfile = /var/log/odoo/odoo.log
log_level = info
log_db = False
log_handler = :INFO
log_db_level = warning

# HTTP
xmlrpc_port = $ODOO_PORT
xmlrpc_interface = 0.0.0.0
longpolling_port = 8072

# Multiprocessing
workers = 0
max_cron_threads = 1

# Memory limits
limit_memory_hard = 2684354560
limit_memory_soft = 2147483648
limit_request = 8192
limit_time_cpu = 600
limit_time_real = 1200

# Data directory
data_dir = /var/lib/odoo

# Security y acceso
# Permitir acceso desde cualquier IP (para desarrollo)
# En producción, restringe estas configuraciones
without_demo = False
server_wide_modules = base,web

# Performance
unaccent = False
EOF

chown $ODOO_USER:$ODOO_USER "$ODOO_CONFIG"

# Crear servicio systemd
log "🔧 Creando servicio systemd para Odoo..."
cat > /etc/systemd/system/odoo.service << EOF
[Unit]
Description=Odoo 18 Community Edition
Documentation=https://www.odoo.com
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=$ODOO_USER
Group=$ODOO_USER
ExecStart=$ODOO_HOME/venv/bin/python3 $ODOO_HOME/odoo-bin -c $ODOO_CONFIG
WorkingDirectory=$ODOO_HOME
StandardOutput=journal+console
StandardError=journal+console
Restart=always
RestartSec=10
KillMode=mixed
KillSignal=SIGINT

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/odoo /var/lib/odoo /tmp
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# Habilitar el servicio
systemctl daemon-reload
systemctl enable odoo

# Función para esperar que Odoo inicie en modo selector
wait_for_odoo() {
    local max_attempts=60
    local attempt=1
    
    log "⏳ Esperando que Odoo inicie en modo selector de base de datos..."
    
    while [ $attempt -le $max_attempts ]; do
        # Verificar si el servicio está activo
        if systemctl is-active --quiet odoo; then
            # Verificar si el puerto está escuchando
            if ss -tuln 2>/dev/null | grep -q ":$ODOO_PORT " || netstat -tuln 2>/dev/null | grep -q ":$ODOO_PORT "; then
                # Verificar que responde con el selector de BD
                if curl -s --max-time 10 "http://localhost:$ODOO_PORT/web/database/selector" | grep -q "master_pwd\|Database" 2>/dev/null; then
                    log "✅ Odoo está ejecutándose y mostrando selector de base de datos"
                    return 0
                fi
            fi
        fi
        
        # Mostrar progreso cada 5 intentos
        if [ $((attempt % 5)) -eq 0 ]; then
            log "⏳ Esperando que Odoo inicie... (intento $attempt/$max_attempts)"
            if [ -f /var/log/odoo/odoo.log ]; then
                info "Últimas líneas del log:"
                tail -3 /var/log/odoo/odoo.log
            fi
        fi
        
        sleep 2
        ((attempt++))
    done
    
    # Verificación final
    if systemctl is-active --quiet odoo && (ss -tuln 2>/dev/null | grep -q ":$ODOO_PORT " || netstat -tuln 2>/dev/null | grep -q ":$ODOO_PORT "); then
        warn "Odoo parece estar funcionando pero la verificación del selector falló"
        log "✅ Continuando porque Odoo está activo y el puerto está escuchando"
        return 0
    fi
    
    error "Odoo no pudo iniciarse después de $max_attempts intentos"
    systemctl status odoo --no-pager -l
    if [ -f /var/log/odoo/odoo.log ]; then
        error "Últimas líneas del log de Odoo:"
        tail -20 /var/log/odoo/odoo.log
    fi
    return 1
}

# Iniciar el servicio Odoo
log "🚀 Iniciando servicio Odoo..."
systemctl start odoo

# Esperar que Odoo inicie
if ! wait_for_odoo; then
    error "No se pudo iniciar Odoo correctamente"
    exit 1
fi

# Obtener IP externa
log "🌐 Obteniendo información de red..."
EXTERNAL_IP=$(curl -s --max-time 10 "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" -H "Metadata-Flavor: Google" 2>/dev/null || echo "IP_NO_DISPONIBLE")

# Información final
log "🎉 ¡Instalación de Odoo completada exitosamente!"
echo "
╔══════════════════════════════════════════════════════════════════════════════╗
║                      🎉 ODOO 18 INSTALADO CON SELECTOR DE BD                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  📋 Información de la Instancia:                                           ║
║     • Instancia: $INSTANCE_NAME                                              ║
║     • Fecha de despliegue: $DEPLOYMENT_TIME                                  ║
║     • GitHub Actor: $GITHUB_ACTOR                                           ║
║                                                                              ║
║  🌐 Acceso Web:                                                             ║
║     • URL: http://$EXTERNAL_IP:$ODOO_PORT                                   ║
║     • Contraseña maestra: $ADMIN_PASSWORD                                   ║
║                                                                              ║
║  📝 Al acceder verás el selector de base de datos donde puedes:            ║
║     • Crear nuevas bases de datos                                           ║
║     • Restaurar bases de datos existentes                                   ║
║     • Gestionar múltiples bases de datos                                    ║
║                                                                              ║
║  🗄️ PostgreSQL:                                                           ║
║     • Usuario: $POSTGRES_USER                                               ║
║     • Contraseña: $POSTGRES_PASSWORD                                        ║
║     • Puerto: 5432                                                          ║
║                                                                              ║
║  📁 Rutas importantes:                                                      ║
║     • Instalación: $ODOO_HOME                                              ║
║     • Configuración: $ODOO_CONFIG                                          ║
║     • Logs: /var/log/odoo/odoo.log                                          ║
║     • Datos: /var/lib/odoo                                                  ║
║                                                                              ║
║  🔧 Comandos útiles:                                                        ║
║     • Ver estado: systemctl status odoo                                     ║
║     • Ver logs: tail -f /var/log/odoo/odoo.log                             ║
║     • Reiniciar: systemctl restart odoo                                     ║
╚══════════════════════════════════════════════════════════════════════════════╝

🔑 INFORMACIÓN IMPORTANTE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Al acceder a la URL, verás la pantalla de selector de base de datos
2. Usa la contraseña maestra '$ADMIN_PASSWORD' para crear nuevas bases de datos
3. Puedes crear tantas bases de datos como necesites
4. Cada base de datos será independiente con sus propios datos y configuraciones

📖 CREACIÓN DE BASE DE DATOS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Master Password: $ADMIN_PASSWORD
• Database Name: Elige el nombre que prefieras
• Email: Tu email como administrador
• Password: Contraseña para el usuario admin de esa BD
• Phone: Opcional
• Language: Selecciona tu idioma preferido
• Country: Selecciona tu país
• Demo Data: Marca si quieres datos de demostración
"

# Verificaciones finales
log "🔍 Verificaciones finales..."
echo "=== Estado del servicio Odoo ==="
systemctl status odoo --no-pager -l

echo -e "\n=== Verificando selector de base de datos ==="
if curl -s --max-time 10 "http://localhost:$ODOO_PORT/web/database/selector" | grep -q "master_pwd\|Database"; then
    log "✅ Selector de base de datos está funcionando correctamente"
else
    warn "⚠️ No se pudo verificar el selector de base de datos"
fi

echo -e "\n=== Puertos en escucha ==="
ss -tuln | grep -E ":($ODOO_PORT|5432) "

echo -e "\n=== Estado de PostgreSQL ==="
systemctl status postgresql --no-pager -l

echo -e "\n=== Bases de datos PostgreSQL existentes ==="
sudo -u postgres psql -l

echo -e "\n=== Espacio en disco ==="
df -h /

echo -e "\n=== Memoria del sistema ==="
free -h

echo -e "\n=== Últimas líneas del log de Odoo ==="
if [ -f /var/log/odoo/odoo.log ]; then
    tail -10 /var/log/odoo/odoo.log
else
    echo "No hay log de Odoo disponible"
fi

# Crear script de utilidades específico para modo selector
log "📝 Creando script de utilidades..."
cat > /usr/local/bin/odoo-db-utils << 'EOF'
#!/bin/bash

# Utilidades para Odoo 18 en modo selector de BD
ODOO_USER="odoo"
ODOO_HOME="/opt/odoo"
ODOO_CONFIG="/etc/odoo/odoo.conf"
POSTGRES_USER="odoo"
ODOO_PORT="8069"

show_help() {
    echo "Utilidades para Odoo 18 (Modo Selector de BD)"
    echo ""
    echo "Uso: odoo-db-utils [COMANDO]"
    echo ""
    echo "Comandos disponibles:"
    echo "  status       - Mostrar estado del servicio"
    echo "  logs         - Mostrar logs en tiempo real"
    echo "  restart      - Reiniciar Odoo"
    echo "  stop         - Detener Odoo"
    echo "  start        - Iniciar Odoo"
    echo "  list-db      - Listar bases de datos existentes"
    echo "  backup-db    - Hacer backup de una base de datos"
    echo "  restore-db   - Restaurar una base de datos"
    echo "  drop-db      - Eliminar una base de datos"
    echo "  test-selector - Probar el selector de base de datos"
    echo "  help         - Mostrar esta ayuda"
}
