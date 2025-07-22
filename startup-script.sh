#!/bin/bash
# Script de instalación automática de Odoo 18 Community en Ubuntu 22.04
# Archivo: install_odoo18.sh
# Uso: sudo bash install_odoo18.sh

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_message() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar que se ejecuta como root
if [ "$EUID" -ne 0 ]; then
    print_error "Este script debe ejecutarse como root (sudo)"
    exit 1
fi

# Configuración
ODOO_USER="odoo"
ODOO_HOME="/opt/odoo18"
ODOO_VERSION="18.0"
ODOO_CONFIG="/etc/odoo18.conf"
ODOO_LOG_DIR="/var/log/odoo18"
DB_PASSWORD="$(openssl rand -base64 32)"
ADMIN_PASSWORD="$(openssl rand -base64 32)"

print_message "Iniciando instalación de Odoo 18 Community..."
echo "=========================================="

# Paso 1: Actualizar sistema
print_message "Paso 1: Actualizando sistema Ubuntu..."
apt update && apt upgrade -y
print_success "Sistema actualizado correctamente"

# Paso 2: Instalar dependencias del sistema
print_message "Paso 2: Instalando dependencias del sistema..."
apt install -y \
    software-properties-common \
    python3-pip python3-dev python3-venv \
    postgresql postgresql-contrib \
    nginx git curl wget \
    build-essential libxml2-dev libxslt1-dev \
    libevent-dev libsasl2-dev libldap2-dev \
    libpq-dev libjpeg8-dev zlib1g-dev \
    wkhtmltopdf node-less \
    fontconfig xfonts-75dpi xfonts-base

print_success "Dependencias instaladas correctamente"

# Paso 3: Configurar PostgreSQL
print_message "Paso 3: Configurando PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Crear usuario PostgreSQL para Odoo
sudo -u postgres createuser -d -R -S $ODOO_USER || true
sudo -u postgres psql -c "ALTER USER $ODOO_USER WITH PASSWORD '$DB_PASSWORD';"

print_success "PostgreSQL configurado correctamente"

# Paso 4: Crear usuario del sistema para Odoo
print_message "Paso 4: Creando usuario del sistema para Odoo..."
if ! id "$ODOO_USER" &>/dev/null; then
    adduser --system --home=$ODOO_HOME --group $ODOO_USER
    print_success "Usuario $ODOO_USER creado"
else
    print_warning "Usuario $ODOO_USER ya existe"
fi

# Paso 5: Descargar Odoo 18
print_message "Paso 5: Descargando Odoo 18..."
if [ ! -d "$ODOO_HOME" ]; then
    git clone --depth=1 --branch=$ODOO_VERSION https://github.com/odoo/odoo.git $ODOO_HOME
    chown -R $ODOO_USER:$ODOO_USER $ODOO_HOME
    print_success "Odoo 18 descargado correctamente"
else
    print_warning "Directorio $ODOO_HOME ya existe"
fi

# Paso 6: Crear entorno virtual e instalar dependencias Python
print_message "Paso 6: Configurando entorno virtual Python..."
sudo -u $ODOO_USER python3 -m venv $ODOO_HOME/venv
sudo -u $ODOO_USER $ODOO_HOME/venv/bin/pip install --upgrade pip
sudo -u $ODOO_USER $ODOO_HOME/venv/bin/pip install wheel
sudo -u $ODOO_USER $ODOO_HOME/venv/bin/pip install -r $ODOO_HOME/requirements.txt

# Instalar dependencias adicionales para API
sudo -u $ODOO_USER $ODOO_HOME/venv/bin/pip install requests xmlrpc flask flask-restful flask-cors

print_success "Entorno Python configurado correctamente"

# Paso 7: Crear directorio para addons personalizados
print_message "Paso 7: Creando directorios necesarios..."
mkdir -p $ODOO_HOME/custom-addons
mkdir -p $ODOO_LOG_DIR
chown -R $ODOO_USER:$ODOO_USER $ODOO_HOME/custom-addons
chown -R $ODOO_USER:$ODOO_USER $ODOO_LOG_DIR

print_success "Directorios creados correctamente"

# Paso 8: Crear archivo de configuración de Odoo
print_message "Paso 8: Creando archivo de configuración de Odoo..."
cat > $ODOO_CONFIG <<EOF
[options]
admin_passwd = $ADMIN_PASSWORD
db_host = localhost
db_port = 5432
db_user = $ODOO_USER
db_password = $DB_PASSWORD
db_name = False
addons_path = $ODOO_HOME/addons,$ODOO_HOME/custom-addons
logfile = $ODOO_LOG_DIR/odoo.log
log_level = info
proxy_mode = True
workers = 4
max_cron_threads = 2
limit_memory_hard = 2684354560
limit_memory_soft = 2147483648
limit_request = 8192
limit_time_cpu = 600
limit_time_real = 1200
EOF

chown $ODOO_USER:$ODOO_USER $ODOO_CONFIG
print_success "Archivo de configuración creado"

# Paso 9: Crear servicio systemd
print_message "Paso 9: Configurando servicio systemd..."
cat > /etc/systemd/system/odoo18.service <<EOF
[Unit]
Description=Odoo18 Community Edition
Documentation=http://www.odoo.com
After=network.target postgresql.service

[Service]
Type=simple
SyslogIdentifier=odoo18
PermissionsStartOnly=true
User=$ODOO_USER
Group=$ODOO_USER
ExecStart=$ODOO_HOME/venv/bin/python $ODOO_HOME/odoo-bin -c $ODOO_CONFIG
StandardOutput=journal+console
Restart=always
RestartSec=10
KillMode=mixed

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable odoo18
print_success "Servicio systemd configurado"

# Paso 10: Configurar Nginx
print_message "Paso 10: Configurando Nginx..."
cat > /etc/nginx/sites-available/odoo18 <<EOF
upstream odoo18 {
    server 127.0.0.1:8069;
}

upstream odoo18-chat {
    server 127.0.0.1:8072;
}

map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name _;
    
    access_log /var/log/nginx/odoo_access.log;
    error_log /var/log/nginx/odoo_error.log;
    
    proxy_buffers 16 64k;
    proxy_buffer_size 128k;
    
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    
    location /web/static/ {
        proxy_pass http://odoo18;
        proxy_cache_valid 200 90m;
        proxy_buffering on;
        expires 864000;
    }
    
    location /longpolling {
        proxy_pass http://odoo18-chat;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    
    location / {
        proxy_pass http://odoo18;
        proxy_redirect off;
    }
    
    gzip_types text/css text/scss text/plain text/xml application/xml application/json application/javascript;
    gzip on;
}
EOF

# Habilitar sitio Nginx
ln -sf /etc/nginx/sites-available/odoo18 /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
print_success "Nginx configurado correctamente"

# Paso 11: Crear cliente API Python
print_message "Paso 11: Creando cliente API Python..."
cat > $ODOO_HOME/api_client.py <<'EOF'
#!/usr/bin/env python3
import xmlrpc.client
import json

class OdooAPI:
    def __init__(self, url, database, username, password):
        self.url = url
        self.database = database
        self.username = username
        self.password = password
        self.uid = None
        self.common = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/common')
        self.models = xmlrpc.client.ServerProxy(f'{url}/xmlrpc/2/object')
        
    def authenticate(self):
        """Autenticar usuario"""
        try:
            self.uid = self.common.authenticate(
                self.database, self.username, self.password, {}
            )
            return self.uid
        except Exception as e:
            print(f"Error de autenticación: {e}")
            return False
    
    def search_read(self, model, domain=[], fields=[]):
        """Buscar y leer registros"""
        if not self.uid:
            if not self.authenticate():
                return []
            
        try:
            return self.models.execute_kw(
                self.database, self.uid, self.password,
                model, 'search_read',
                [domain], {'fields': fields}
            )
        except Exception as e:
            print(f"Error en search_read: {e}")
            return []
    
    def create(self, model, values):
        """Crear un nuevo registro"""
        if not self.uid:
            if not self.authenticate():
                return False
            
        try:
            return self.models.execute_kw(
                self.database, self.uid, self.password,
                model, 'create', [values]
            )
        except Exception as e:
            print(f"Error en create: {e}")
            return False

# Ejemplo de uso
if __name__ == "__main__":
    # Configuración - Ajusta estos valores
    odoo = OdooAPI(
        url='http://localhost:8069',
        database='tu_base_de_datos',  # Cambia por el nombre de tu BD
        username='admin',
        password='admin'  # Cambia por tu contraseña de admin
    )
    
    # Autenticar
    if odoo.authenticate():
        print("✅ Autenticación exitosa")
        
        # Ejemplo: Buscar partners
        partners = odoo.search_read(
            'res.partner',
            domain=[('is_company', '=', True)],
            fields=['name', 'email', 'phone']
        )
        print(f"📋 Encontrados {len(partners)} partners")
        for partner in partners[:5]:  # Mostrar solo los primeros 5
            print(f"  - {partner['name']} ({partner['email']})")
            
    else:
        print("❌ Error en autenticación")
EOF

chown $ODOO_USER:$ODOO_USER $ODOO_HOME/api_client.py
chmod +x $ODOO_HOME/api_client.py
print_success "Cliente API creado"

# Paso 12: Configurar firewall UFW
print_message "Paso 12: Configurando firewall..."
ufw --force enable
ufw allow ssh
ufw allow 'Nginx Full'
ufw allow 8069/tcp
print_success "Firewall configurado"

# Paso 13: Iniciar servicios
print_message "Paso 13: Iniciando servicios..."
systemctl start odoo18
sleep 10

# Verificar servicios
if systemctl is-active --quiet odoo18; then
    print_success "✅ Servicio Odoo18 iniciado correctamente"
else
    print_error "❌ Error al iniciar servicio Odoo18"
    systemctl status odoo18 --no-pager
fi

if systemctl is-active --quiet nginx; then
    print_success "✅ Servicio Nginx activo"
else
    print_error "❌ Error en servicio Nginx"
fi

if systemctl is-active --quiet postgresql; then
    print_success "✅ Servicio PostgreSQL activo"
else
    print_error "❌ Error en servicio PostgreSQL"
fi

# Mostrar información final
echo ""
echo "=========================================="
print_success "🎉 INSTALACIÓN COMPLETADA EXITOSAMENTE 🎉"
echo "=========================================="
echo ""
echo "📋 INFORMACIÓN DE ACCESO:"
echo "   URL Principal: http://$(curl -s ifconfig.me)/"
echo "   URL Directa:   http://$(curl -s ifconfig.me):8069/"
echo "   URL Local:     http://localhost/"
echo ""
echo "🔑 CREDENCIALES IMPORTANTES (¡GUÁRDALAS!):"
echo "   Contraseña Master de Odoo: $ADMIN_PASSWORD"
echo "   Usuario PostgreSQL: $ODOO_USER"
echo "   Contraseña PostgreSQL: $DB_PASSWORD"
echo ""
echo "📁 ARCHIVOS IMPORTANTES:"
echo "   Configuración: $ODOO_CONFIG"
echo "   Logs: $ODOO_LOG_DIR/odoo.log"
echo "   Cliente API: $ODOO_HOME/api_client.py"
echo ""
echo "🔧 COMANDOS ÚTILES:"
echo "   Reiniciar Odoo: sudo systemctl restart odoo18"
echo "   Ver logs: sudo tail -f $ODOO_LOG_DIR/odoo.log"
echo "   Estado servicio: sudo systemctl status odoo18"
echo ""
echo "📚 PRÓXIMOS PASOS:"
echo "1. Accede a la URL principal"
echo "2. Crea una nueva base de datos"
echo "3. Configura tu primera empresa"
echo "4. Prueba el cliente API con: python3 $ODOO_HOME/api_client.py"
echo ""
print_warning "⚠️  IMPORTANTE: Guarda las contraseñas mostradas arriba en un lugar seguro"
echo ""
