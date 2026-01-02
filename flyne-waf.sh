#!/bin/bash
#===============================================================================
# FLYNE SHIELD WAF MODULE v1.0
# ModSecurity 3 + OWASP Core Rule Set for Nginx
# Optional add-on for Flyne Shield
#===============================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${GREEN}[WAF]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root"

MODSEC_DIR="/etc/nginx/modsecurity"
CRS_DIR="/etc/nginx/coreruleset"
WAF_LOG="/var/log/flyne/shield/waf.log"

source /opt/flyne/flyne.conf 2>/dev/null || true

#===============================================================================
# INSTALL MODSECURITY 3
#===============================================================================
log "Installing ModSecurity 3 for Nginx..."

apt update
apt install -y \
    libmodsecurity3 \
    libmodsecurity-dev \
    libnginx-mod-http-modsecurity \
    git build-essential libpcre3-dev zlib1g-dev \
    libssl-dev libxml2-dev libyajl-dev \
    libgeoip-dev liblmdb-dev libcurl4-openssl-dev

mkdir -p ${MODSEC_DIR}
mkdir -p ${CRS_DIR}

#===============================================================================
# MODSECURITY CONFIGURATION
#===============================================================================
log "Configuring ModSecurity..."

cat > ${MODSEC_DIR}/modsecurity.conf << 'MODSECCONF'
# Flyne Shield - ModSecurity Configuration
# Optimized for WordPress hosting

# Enable ModSecurity
SecRuleEngine On

# Request body handling
SecRequestBodyAccess On
SecRequestBodyLimit 134217728
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject

# Response body handling  
SecResponseBodyAccess Off

# Temp directory
SecTmpDir /tmp
SecDataDir /var/lib/modsecurity
SecUploadDir /tmp

# Debug log (disable in production)
SecDebugLogLevel 0

# Audit logging
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/flyne/shield/modsec_audit.log

# Process multipart/form-data
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
    "id:'200002',phase:2,t:none,log,deny,status:400,msg:'Multipart request body failed strict validation'"
SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
    "id:'200003',phase:2,t:none,log,deny,status:400,msg:'Multipart parser detected a possible unmatched boundary'"

# Enable XML body parsing
SecRule REQUEST_HEADERS:Content-Type "^(?:application(?:/soap\+|/)|text/)xml" \
    "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"

# Enable JSON body parsing
SecRule REQUEST_HEADERS:Content-Type "^application/json" \
    "id:'200001',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"

# File extension restrictions
SecRule REQUEST_FILENAME "\.(?:exe|bat|cmd|com|dll|msi|vbs|js|jar|scr|pif|reg)$" \
    "id:'200010',phase:2,t:none,t:lowercase,deny,status:403,msg:'Blocked file extension'"

# Server signature
SecServerSignature "Flyne-Shield"

# Default action
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

# GeoIP (if available)
# SecGeoLookupDB /usr/share/GeoIP/GeoLite2-Country.mmdb

# Unicode mapping
SecUnicodeMapFile unicode.mapping 20127

# Include OWASP CRS
Include /etc/nginx/coreruleset/crs-setup.conf
Include /etc/nginx/coreruleset/rules/*.conf
MODSECCONF

#===============================================================================
# DOWNLOAD OWASP CORE RULE SET
#===============================================================================
log "Downloading OWASP Core Rule Set..."

cd /tmp
CRS_VERSION="4.8.0"
wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" -O crs.tar.gz || {
    warn "Failed to download CRS, trying latest..."
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git crs-latest
    mv crs-latest/* ${CRS_DIR}/
}

if [[ -f crs.tar.gz ]]; then
    tar xzf crs.tar.gz
    mv coreruleset-${CRS_VERSION}/* ${CRS_DIR}/
    rm -rf crs.tar.gz coreruleset-${CRS_VERSION}
fi

#===============================================================================
# CRS CONFIGURATION - WORDPRESS OPTIMIZED
#===============================================================================
log "Configuring CRS for WordPress..."

cat > ${CRS_DIR}/crs-setup.conf << 'CRSSETUP'
# Flyne Shield - OWASP CRS Configuration
# Optimized for WordPress hosting

# Paranoia Level (1-4, higher = more strict, more false positives)
# Level 1: Basic protection, minimal false positives
# Level 2: Moderate protection, some tuning needed
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=1"

# Detection paranoia (for logging without blocking)
SecAction "id:900001,phase:1,pass,t:none,nolog,setvar:tx.detection_paranoia_level=2"

# Anomaly scoring threshold
# Inbound: 5 (critical only) to 100+ (very permissive)
SecAction "id:900110,phase:1,pass,t:none,nolog,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4"

# Enable anomaly mode (recommended)
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:tx.early_blocking=1"

# Sampling (1-100, 100 = check all requests)
SecAction "id:900400,phase:1,pass,t:none,nolog,setvar:tx.sampling_percentage=100"

# Allowed HTTP methods
SecAction "id:900200,phase:1,pass,t:none,nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"

# Allowed content types
SecAction "id:900220,phase:1,pass,t:none,nolog,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|'"

# File extension restrictions (block dangerous extensions)
SecAction "id:900240,phase:1,pass,t:none,nolog,\
    setvar:'tx.restricted_extensions=.asa/ .asax/ .ascx/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/'"

# HTTP argument limits
SecAction "id:900300,phase:1,pass,t:none,nolog,\
    setvar:tx.max_num_args=255,\
    setvar:tx.arg_name_length=100,\
    setvar:tx.arg_length=400,\
    setvar:tx.total_arg_length=64000,\
    setvar:tx.max_file_size=134217728,\
    setvar:tx.combined_file_sizes=134217728"

# Enable WordPress application exclusions
SecAction "id:900130,phase:1,pass,t:none,nolog,\
    setvar:tx.crs_exclusions_wordpress=1"
CRSSETUP

# Copy rules setup
[[ -f ${CRS_DIR}/crs-setup.conf.example ]] && rm ${CRS_DIR}/crs-setup.conf.example

#===============================================================================
# WORDPRESS-SPECIFIC EXCLUSIONS
#===============================================================================
log "Creating WordPress exclusion rules..."

cat > ${CRS_DIR}/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf << 'WPEXCLUSIONS'
# WordPress-specific exclusions for Flyne Shield
# These prevent false positives on common WordPress operations

# Allow WordPress admin AJAX
SecRule REQUEST_URI "@beginsWith /wp-admin/admin-ajax.php" \
    "id:1000,phase:1,pass,nolog,\
    ctl:ruleRemoveById=941100-941999,\
    ctl:ruleRemoveById=942100-942999"

# Allow Gutenberg editor
SecRule REQUEST_URI "@beginsWith /wp-json/" \
    "id:1001,phase:1,pass,nolog,\
    ctl:ruleRemoveById=941100,\
    ctl:ruleRemoveById=942100"

# Allow media uploads
SecRule REQUEST_URI "@beginsWith /wp-admin/async-upload.php" \
    "id:1002,phase:1,pass,nolog,\
    ctl:ruleRemoveById=200002,\
    ctl:ruleRemoveById=200003"

# Allow plugin/theme editors (if enabled)
SecRule REQUEST_URI "@rx /wp-admin/(?:plugin-editor|theme-editor)\.php" \
    "id:1003,phase:1,pass,nolog,\
    ctl:ruleRemoveById=941100-941999,\
    ctl:ruleRemoveById=942100-942999"

# Allow customizer
SecRule REQUEST_URI "@beginsWith /wp-admin/customize.php" \
    "id:1004,phase:1,pass,nolog,\
    ctl:ruleRemoveById=941100"

# Allow WooCommerce checkout
SecRule REQUEST_URI "@rx /(?:checkout|cart|my-account)" \
    "id:1005,phase:1,pass,nolog,\
    ctl:ruleRemoveById=942100"

# Exclude WordPress nonces from SQL injection detection
SecRule ARGS:_wpnonce "@rx ^[a-f0-9]+$" \
    "id:1010,phase:2,pass,nolog,\
    ctl:ruleRemoveTargetById=942100;ARGS:_wpnonce"

# Allow post content with HTML
SecRule REQUEST_URI "@beginsWith /wp-admin/post.php" \
    "id:1011,phase:2,pass,nolog,\
    ctl:ruleRemoveTargetById=941100;ARGS:content,\
    ctl:ruleRemoveTargetById=941110;ARGS:content,\
    ctl:ruleRemoveTargetById=941160;ARGS:content"
WPEXCLUSIONS

cat > ${CRS_DIR}/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf << 'AFTERCRS'
# Post-CRS exclusion rules (empty by default)
# Add site-specific exclusions here
AFTERCRS

#===============================================================================
# NGINX MODSECURITY INTEGRATION
#===============================================================================
log "Integrating ModSecurity with Nginx..."

# Create ModSecurity include file
cat > /etc/nginx/snippets/modsecurity.conf << 'MODSECNGINX'
modsecurity on;
modsecurity_rules_file /etc/nginx/modsecurity/modsecurity.conf;
MODSECNGINX

# Create per-site WAF snippet
cat > /etc/nginx/snippets/wordpress-waf.conf << 'WPWAF'
# Flyne Shield WAF for WordPress
include snippets/modsecurity.conf;

# Additional rate limiting for sensitive endpoints
location = /wp-login.php {
    limit_req zone=login burst=3 nodelay;
    include snippets/modsecurity.conf;
    
    try_files $uri =404;
    fastcgi_pass unix:$php_socket;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}

location = /xmlrpc.php {
    # Block XML-RPC by default (common attack vector)
    deny all;
    return 403;
}
WPWAF

#===============================================================================
# WAF LOGGING PARSER
#===============================================================================
log "Creating WAF log parser..."

cat > /opt/flyne/shield/scripts/parse-waf-logs.sh << 'WAFPARSER'
#!/bin/bash
# Parse ModSecurity audit logs and insert into database

AUDIT_LOG="/var/log/flyne/shield/modsec_audit.log"
PARSED_MARKER="/var/lib/flyne-shield/waf_parsed_offset"

source /opt/flyne/flyne.conf 2>/dev/null || true

[[ ! -f "$AUDIT_LOG" ]] && exit 0

# Get last parsed position
OFFSET=0
[[ -f "$PARSED_MARKER" ]] && OFFSET=$(cat "$PARSED_MARKER")

# Get current file size
CURRENT_SIZE=$(stat -c %s "$AUDIT_LOG" 2>/dev/null || echo 0)

# If file was rotated (smaller than offset), reset
[[ $CURRENT_SIZE -lt $OFFSET ]] && OFFSET=0

# Parse new entries
tail -c +$((OFFSET + 1)) "$AUDIT_LOG" 2>/dev/null | while IFS= read -r line; do
    # Extract relevant fields from ModSecurity audit format
    if [[ "$line" =~ "uri\":" ]]; then
        URI=$(echo "$line" | grep -oP '"uri"\s*:\s*"\K[^"]+')
    fi
    if [[ "$line" =~ "client_ip\":" ]]; then
        IP=$(echo "$line" | grep -oP '"client_ip"\s*:\s*"\K[^"]+')
    fi
    if [[ "$line" =~ "id\":" ]]; then
        RULE_ID=$(echo "$line" | grep -oP '"id"\s*:\s*"\K[^"]+')
    fi
    if [[ "$line" =~ "msg\":" ]]; then
        MSG=$(echo "$line" | grep -oP '"msg"\s*:\s*"\K[^"]+' | head -1)
    fi
    if [[ "$line" =~ "severity\":" ]]; then
        SEVERITY=$(echo "$line" | grep -oP '"severity"\s*:\s*"\K[^"]+')
    fi
    
    # When we have complete entry, insert to database
    if [[ -n "$RULE_ID" && -n "$IP" ]]; then
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO waf_events (rule_id, rule_msg, ip_address, request_uri, severity, action, created_at)
VALUES ('${RULE_ID}', '${MSG}', '${IP}', '${URI}', '${SEVERITY}', 'blocked', NOW())
ON DUPLICATE KEY UPDATE id=id;
SQLEOF
        # Reset for next entry
        unset URI IP RULE_ID MSG SEVERITY
    fi
done

# Update parsed offset
echo "$CURRENT_SIZE" > "$PARSED_MARKER"
WAFPARSER
chmod +x /opt/flyne/shield/scripts/parse-waf-logs.sh

# Add cron job for WAF log parsing
echo "*/5 * * * * root /opt/flyne/shield/scripts/parse-waf-logs.sh" >> /etc/cron.d/flyne-shield

#===============================================================================
# DATA DIRECTORY
#===============================================================================
mkdir -p /var/lib/modsecurity
chown www-data:www-data /var/lib/modsecurity

#===============================================================================
# UNICODE MAPPING FILE
#===============================================================================
if [[ ! -f ${MODSEC_DIR}/unicode.mapping ]]; then
    curl -sL "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping" \
        -o ${MODSEC_DIR}/unicode.mapping 2>/dev/null || \
    echo "# Basic unicode mapping" > ${MODSEC_DIR}/unicode.mapping
fi

#===============================================================================
# UPDATE EXISTING SITE CONFIGS
#===============================================================================
log "Would you like to enable WAF on all existing sites? (y/n)"
read -r ENABLE_ALL

if [[ "$ENABLE_ALL" == "y" ]]; then
    for conf in /etc/nginx/sites-flyne/*.conf; do
        [[ ! -f "$conf" ]] && continue
        [[ "$conf" == *"000-api"* ]] && continue
        [[ "$conf" == *"001-pma"* ]] && continue
        [[ "$conf" == *"002-security"* ]] && continue
        
        # Check if already has modsecurity
        if ! grep -q "modsecurity" "$conf"; then
            # Add modsecurity after the root directive
            sed -i '/^[[:space:]]*root/a\    include snippets/modsecurity.conf;' "$conf"
            log "Enabled WAF for: $(basename "$conf" .conf)"
        fi
    done
fi

#===============================================================================
# TEST CONFIGURATION
#===============================================================================
log "Testing Nginx configuration..."
nginx -t || error "Nginx configuration test failed"

log "Reloading Nginx..."
systemctl reload nginx

#===============================================================================
# FINAL OUTPUT
#===============================================================================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   FLYNE SHIELD WAF MODULE INSTALLED!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${CYAN}Features:${NC}"
echo "  ✓ ModSecurity 3 WAF engine"
echo "  ✓ OWASP Core Rule Set v${CRS_VERSION}"
echo "  ✓ WordPress-optimized exclusions"
echo "  ✓ Anomaly scoring mode"
echo "  ✓ WAF event logging"
echo ""
echo -e "${CYAN}Configuration Files:${NC}"
echo "  ${MODSEC_DIR}/modsecurity.conf"
echo "  ${CRS_DIR}/crs-setup.conf"
echo ""
echo -e "${CYAN}To enable WAF on a new site:${NC}"
echo "  Add to site's nginx config:"
echo "    include snippets/modsecurity.conf;"
echo ""
echo -e "${CYAN}To adjust paranoia level:${NC}"
echo "  Edit ${CRS_DIR}/crs-setup.conf"
echo "  Change tx.blocking_paranoia_level (1-4)"
echo ""
echo -e "${CYAN}WAF Logs:${NC}"
echo "  /var/log/flyne/shield/modsec_audit.log"
echo ""
log "WAF installation complete!"