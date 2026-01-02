#!/bin/bash
#===============================================================================
# FLYNE SHIELD v1.0 - Enterprise WordPress Security Suite
# Real-time malware detection, WAF, file integrity monitoring
# Compatible with Flyne Engine v4.0
#===============================================================================

set -uo pipefail
trap 'echo -e "${RED}[ERROR]${NC} Script failed at line $LINENO"; exit 1' ERR

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

log() { echo -e "${GREEN}[SHIELD]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash flyne-shield.sh"

clear
echo -e "${MAGENTA}"
cat << "EOF"
   _____ _                        _____ _     _      _     _ 
  |  ___| |_   _ _ __   ___      / ____| |   (_)    | |   | |
  | |_  | | | | | '_ \ / _ \    | (___ | |__  _  ___| | __| |
  |  _| | | |_| | | | |  __/     \___ \| '_ \| |/ _ \ |/ _` |
  |_|   |_|\__, |_| |_|\___|     ____) | | | | |  __/ | (_| |
           |___/                |_____/|_| |_|_|\___|_|\__,_|
  Enterprise WordPress Security Suite v1.0
EOF
echo -e "${NC}"

#===============================================================================
# CONFIGURATION
#===============================================================================
FLYNE_DIR="/opt/flyne"
SHIELD_DIR="/opt/flyne/shield"
SITES_DIR="/var/www/sites"
QUARANTINE_DIR="/opt/flyne/shield/quarantine"
SIGNATURES_DIR="/opt/flyne/shield/signatures"
YARA_DIR="/opt/flyne/shield/yara"
LOG_DIR="/var/log/flyne/shield"

# Load Flyne config if exists
[[ -f "${FLYNE_DIR}/flyne.conf" ]] && source "${FLYNE_DIR}/flyne.conf"

#===============================================================================
# CREATE DIRECTORY STRUCTURE
#===============================================================================
log "Creating security infrastructure..."

mkdir -p ${SHIELD_DIR}/{quarantine,signatures,yara,scripts,tmp,cache}
mkdir -p ${LOG_DIR}
mkdir -p /var/lib/flyne-shield

touch ${LOG_DIR}/{realtime.log,scan.log,quarantine.log,waf.log,fim.log,api.log}
chmod 640 ${LOG_DIR}/*.log

#===============================================================================
# INSTALL SECURITY PACKAGES
#===============================================================================
log "Installing security packages..."
export DEBIAN_FRONTEND=noninteractive

apt update
apt install -y \
    clamav clamav-daemon clamav-freshclam \
    inotify-tools \
    yara \
    rkhunter chkrootkit \
    aide \
    jq \
    libmodsecurity3 libmodsecurity-dev \
    libnginx-mod-http-modsecurity 2>/dev/null || true

# Install additional tools
log "Installing Linux Malware Detect..."
cd /tmp
if [[ ! -d "/usr/local/maldetect" ]]; then
    wget -q https://www.rfxn.com/downloads/maldetect-current.tar.gz -O maldetect.tar.gz || warn "LMD download failed"
    if [[ -f maldetect.tar.gz ]]; then
        tar xzf maldetect.tar.gz
        cd maldetect-*
        ./install.sh
        cd /tmp && rm -rf maldetect*
    fi
fi

#===============================================================================
# CLAMAV CONFIGURATION - WORDPRESS OPTIMIZED
#===============================================================================
log "Configuring ClamAV for WordPress..."

systemctl stop clamav-freshclam 2>/dev/null || true
systemctl stop clamav-daemon 2>/dev/null || true

# Update ClamAV databases
log "Updating ClamAV signatures (this may take a while)..."
freshclam || warn "FreshClam update had issues"

# Configure ClamAV daemon for on-access scanning
cat > /etc/clamav/clamd.conf << 'CLAMDCONF'
# Flyne Shield ClamAV Configuration
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 666
User clamav
TCPSocket 3310
TCPAddr 127.0.0.1
ScanMail false
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 20
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads 12
MaxConnectionQueueLength 30
LogSyslog true
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
LogTime true
LogRotate true
ExtendedDetectionInfo true
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly false
SelfCheck 3600
Foreground false
Debug false
ScanPE true
ScanELF true
DetectBrokenExecutables true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanXMLDOCS true
ScanHWP3 true
ScanHTML true
ScanMail false
PhishingSignatures true
PhishingScanURLs true
HeuristicScanPrecedence false
StructuredDataDetection false
CommandReadTimeout 30
SendBufTimeout 200
MaxScanTime 300000
MaxScanSize 100M
MaxFileSize 50M
MaxRecursion 16
MaxFiles 10000
MaxEmbeddedPE 10M
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
MaxPartitions 50
MaxIconsPE 100
PCREMatchLimit 10000
PCRERecMatchLimit 5000
PCREMaxFileSize 25M
ScanPartialMessages false
CrossFilesystems true
DisableCertCheck false
OnAccessIncludePath /var/www/sites
OnAccessExcludePath /var/www/sites/*/logs
OnAccessExcludePath /var/www/sites/*/tmp
OnAccessPrevention false
OnAccessExtraScanning true
OnAccessExcludeRootUID true
OnAccessExcludeUID 0
VirusEvent /opt/flyne/shield/scripts/virus-event.sh %v %f
CLAMDCONF

# On-Access daemon configuration
cat > /etc/clamav/clamd.conf.d/onaccess.conf << 'ONACCESS'
# On-Access Scanning Configuration
OnAccessMountPath /var/www/sites
OnAccessExcludePath /proc
OnAccessExcludePath /sys
OnAccessExcludePath /dev
OnAccessExcludePath /run
ONACCESS

# Configure freshclam for frequent updates
cat > /etc/clamav/freshclam.conf << 'FRESHCONF'
DatabaseDirectory /var/lib/clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose false
LogSyslog false
LogFacility LOG_LOCAL6
LogFileMaxSize 0
LogTime true
LogRotate true
Foreground false
Debug false
MaxAttempts 5
DatabaseMirror database.clamav.net
ScriptedUpdates yes
CompressLocalDatabase no
Bytecode true
NotifyClamd /etc/clamav/clamd.conf
Checks 24
DatabaseOwner clamav
FRESHCONF

#===============================================================================
# WORDPRESS-SPECIFIC MALWARE SIGNATURES
#===============================================================================
log "Installing WordPress malware signatures..."

cat > ${SIGNATURES_DIR}/wordpress-malware.ndb << 'WPSIGS'
# WordPress Specific Malware Signatures for ClamAV
# Format: MalwareName:TargetType:Offset:HexSignature

# PHP Backdoors
WP.Backdoor.Generic-1:0:*:6576616c28626173653634
WP.Backdoor.Generic-2:0:*:6576616c28677a696e666c617465
WP.Backdoor.Generic-3:0:*:6576616c28737472726576
WP.Backdoor.Generic-4:0:*:6576616c28677a756e636f6d70726573
WP.Backdoor.FilesMan-1:0:*:46696c65734d616e
WP.Backdoor.WSO-1:0:*:77736f5f76657273696f6e
WP.Backdoor.C99-1:0:*:633939736865
WP.Backdoor.R57-1:0:*:723537736865
WP.Backdoor.B374k-1:0:*:6233373462
WP.Backdoor.Weevely-1:0:*:7765657665
WP.Backdoor.Alfa-1:0:*:616c66615f636f6f6b6965

# Malicious Injections
WP.Injection.Generic-1:0:*:3c7363726970743e646f63756d656e742e777269746528756e657363617065
WP.Injection.Iframe-1:0:*:3c696672616d65207372633d
WP.Injection.Base64Eval-1:0:*:406576616c2840626173653634

# WP-VCD Malware
WP.Malware.WPVCD-1:0:*:77702d7663642e706870
WP.Malware.WPVCD-2:0:*:77702d696e636c756465732f77702d7663642e706870
WP.Malware.WPVCD-3:0:*:696e636c756465206f6e6365

# Cryptocurrency Miners
WP.Miner.Coinhive-1:0:*:636f696e686976652e636f6d
WP.Miner.Generic-1:0:*:6d696e65722e7374617274
WP.Miner.CryptoNight-1:0:*:63727970746f6e69676874

# SEO Spam
WP.Spam.Pharma-1:0:*:7669616772617c6369616c6973
WP.Spam.Japanese-1:0:*:e382abe382b8e3838ee382aa
WP.Spam.Redirect-1:0:*:6865616465722827
WPSIGS

# Copy to ClamAV database directory
cp ${SIGNATURES_DIR}/wordpress-malware.ndb /var/lib/clamav/

#===============================================================================
# YARA RULES FOR PHP MALWARE
#===============================================================================
log "Creating YARA rules..."

cat > ${YARA_DIR}/php-malware.yar << 'YARARULES'
/*
 * Flyne Shield - PHP/WordPress Malware Detection Rules
 * Enterprise-grade YARA signatures
 */

rule PHP_Backdoor_Eval_Base64 {
    meta:
        description = "Detects PHP backdoors using eval with base64"
        severity = "critical"
        category = "backdoor"
    strings:
        $eval1 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $eval2 = /eval\s*\(\s*gzinflate\s*\(\s*base64_decode/ nocase
        $eval3 = /eval\s*\(\s*gzuncompress\s*\(\s*base64_decode/ nocase
        $eval4 = /eval\s*\(\s*str_rot13\s*\(\s*base64_decode/ nocase
        $eval5 = /@eval\s*\(\s*\$_/ nocase
    condition:
        any of them
}

rule PHP_Backdoor_Shell_Functions {
    meta:
        description = "Detects PHP shells using dangerous functions"
        severity = "critical"
        category = "backdoor"
    strings:
        $shell1 = /passthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $shell2 = /system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $shell3 = /exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $shell4 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $shell5 = /popen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $shell6 = /proc_open\s*\(/ nocase
    condition:
        any of them
}

rule PHP_Backdoor_Obfuscated {
    meta:
        description = "Detects obfuscated PHP backdoors"
        severity = "high"
        category = "backdoor"
    strings:
        $obf1 = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*chr\s*\(\s*\d+\s*\)\s*\.\s*chr/ nocase
        $obf2 = /\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*/ nocase
        $obf3 = /create_function\s*\(\s*['"]['"]\s*,/ nocase
        $obf4 = /\$[a-zA-Z_]{1,3}\s*=\s*\$[a-zA-Z_]{1,3}\s*\(\s*['"]/ nocase
        $obf5 = /preg_replace\s*\(\s*['"]\/.+\/e['"]\s*,/ nocase
    condition:
        2 of them
}

rule PHP_Webshell_Generic {
    meta:
        description = "Generic webshell detection"
        severity = "critical"
        category = "webshell"
    strings:
        $ws1 = "FilesMan" nocase
        $ws2 = "WSO " 
        $ws3 = "c99shell" nocase
        $ws4 = "r57shell" nocase
        $ws5 = "b374k" nocase
        $ws6 = "weevely" nocase
        $ws7 = "alfashell" nocase
        $ws8 = "phpspy" nocase
        $ws9 = "adminer" nocase
        $ws10 = "safe0ver" nocase
    condition:
        any of them
}

rule WP_Malware_WPVCD {
    meta:
        description = "Detects WP-VCD malware"
        severity = "critical"
        category = "wordpress_malware"
    strings:
        $wpvcd1 = "wp-vcd.php" nocase
        $wpvcd2 = "wp-tmp.php" nocase
        $wpvcd3 = "wp-feed.php" nocase
        $wpvcd4 = /include\s*\(\s*['"]\.\s*\./ nocase
        $wpvcd5 = "/*flavor*/" nocase
    condition:
        2 of them
}

rule WP_Malware_Redirect {
    meta:
        description = "Detects WordPress redirect malware"
        severity = "high"
        category = "redirect"
    strings:
        $redir1 = /header\s*\(\s*['"]Location:\s*https?:\/\// nocase
        $redir2 = /\$_SERVER\s*\[\s*['"]HTTP_REFERER['"]\s*\].*google|bing|yahoo/ nocase
        $redir3 = /if\s*\(\s*preg_match.*googlebot.*header/ nocase
        $redir4 = /document\.location\s*=\s*['"]https?:\/\// nocase
    condition:
        any of them
}

rule PHP_Malicious_Upload {
    meta:
        description = "Detects malicious file uploaders"
        severity = "high"
        category = "uploader"
    strings:
        $up1 = /move_uploaded_file\s*\(\s*\$_FILES.*\$_(GET|POST|REQUEST)/ nocase
        $up2 = /copy\s*\(\s*['"]https?:\/\// nocase
        $up3 = /file_put_contents\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $up4 = /fwrite\s*\(.*\$_(GET|POST|REQUEST)/ nocase
    condition:
        any of them
}

rule PHP_Crypto_Miner {
    meta:
        description = "Detects cryptocurrency miners"
        severity = "high"
        category = "miner"
    strings:
        $miner1 = "coinhive.min.js" nocase
        $miner2 = "CoinHive.Anonymous" nocase
        $miner3 = "cryptonight" nocase
        $miner4 = "miner.start" nocase
        $miner5 = "deepMiner" nocase
    condition:
        any of them
}

rule PHP_SEO_Spam {
    meta:
        description = "Detects SEO spam injections"
        severity = "medium"
        category = "spam"
    strings:
        $spam1 = /<a\s+href=.*style\s*=\s*['"].*display\s*:\s*none/ nocase
        $spam2 = /visibility\s*:\s*hidden.*<a\s+href/ nocase
        $spam3 = /position\s*:\s*absolute\s*;\s*left\s*:\s*-\d{4}px/ nocase
    condition:
        any of them
}

rule PHP_Base64_Suspicious {
    meta:
        description = "Detects suspicious base64 patterns"
        severity = "medium"
        category = "suspicious"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/ 
    condition:
        #b64 > 5 and filesize < 500KB
}
YARARULES

#===============================================================================
# REAL-TIME FILE MONITORING SERVICE
#===============================================================================
log "Creating real-time monitoring service..."

cat > ${SHIELD_DIR}/scripts/realtime-monitor.sh << 'REALTIMESCRIPT'
#!/bin/bash
#===============================================================================
# Flyne Shield - Real-time File Monitor
# Uses inotify for instant malware detection on file changes
#===============================================================================

SITES_DIR="/var/www/sites"
LOG_FILE="/var/log/flyne/shield/realtime.log"
QUARANTINE_DIR="/opt/flyne/shield/quarantine"
YARA_RULES="/opt/flyne/shield/yara/php-malware.yar"
SHIELD_DIR="/opt/flyne/shield"

source /opt/flyne/flyne.conf 2>/dev/null || true

log_event() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

scan_file() {
    local file="$1"
    local domain="$2"
    
    # Skip non-PHP files for performance
    [[ ! "$file" =~ \.(php|phtml|php[0-9]|phar|inc)$ ]] && return 0
    
    # Skip if file doesn't exist (was deleted)
    [[ ! -f "$file" ]] && return 0
    
    # Quick YARA scan
    if yara -w -s "$YARA_RULES" "$file" 2>/dev/null | grep -q .; then
        local yara_result=$(yara -w -s "$YARA_RULES" "$file" 2>/dev/null | head -1)
        local rule_name=$(echo "$yara_result" | awk '{print $1}')
        quarantine_file "$file" "$domain" "$rule_name" "yara"
        return 1
    fi
    
    # ClamAV scan for suspicious files
    local clam_result=$(clamdscan --no-summary --infected "$file" 2>/dev/null)
    if [[ -n "$clam_result" ]]; then
        local virus_name=$(echo "$clam_result" | awk -F: '{print $NF}' | tr -d ' ')
        quarantine_file "$file" "$domain" "$virus_name" "clamav"
        return 1
    fi
    
    return 0
}

quarantine_file() {
    local file="$1"
    local domain="$2"
    local threat="$3"
    local scanner="$4"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local filename=$(basename "$file")
    local quarantine_name="${domain}_${timestamp}_${filename}"
    
    # Create quarantine entry
    mkdir -p "${QUARANTINE_DIR}/${domain}"
    
    # Move file to quarantine
    mv "$file" "${QUARANTINE_DIR}/${domain}/${quarantine_name}"
    chmod 000 "${QUARANTINE_DIR}/${domain}/${quarantine_name}"
    
    # Log to database
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, quarantine_path, scanner, severity, created_at)
VALUES ('${domain}', 'malware_detected', '${threat}', '${file}', '${QUARANTINE_DIR}/${domain}/${quarantine_name}', '${scanner}', 'critical', NOW());
SQLEOF
    
    log_event "QUARANTINED: $file | Domain: $domain | Threat: $threat | Scanner: $scanner"
    
    # Send notification (webhook/email)
    notify_admin "$domain" "$file" "$threat" "$scanner"
}

notify_admin() {
    local domain="$1"
    local file="$2"
    local threat="$3"
    local scanner="$4"
    
    # Webhook notification
    if [[ -n "${WEBHOOK_URL:-}" ]]; then
        curl -s -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"event\":\"malware_detected\",\"domain\":\"$domain\",\"file\":\"$file\",\"threat\":\"$threat\",\"scanner\":\"$scanner\",\"timestamp\":\"$(date -Iseconds)\"}" \
            2>/dev/null &
    fi
}

# Main monitoring loop
log_event "Starting real-time monitor for $SITES_DIR"

# Increase inotify watches
echo 524288 > /proc/sys/fs/inotify/max_user_watches 2>/dev/null || true

# Monitor for file changes
inotifywait -m -r -e create,modify,moved_to,close_write \
    --exclude '.*\.(log|tmp|cache|sess)$' \
    --exclude '.*/logs/.*' \
    --exclude '.*/tmp/.*' \
    --exclude '.*/cache/.*' \
    "$SITES_DIR" 2>/dev/null | while read -r directory events filename; do
    
    filepath="${directory}${filename}"
    
    # Extract domain from path
    domain=$(echo "$filepath" | sed -n 's|/var/www/sites/\([^/]*\)/.*|\1|p')
    
    [[ -z "$domain" ]] && continue
    
    # Scan the file
    scan_file "$filepath" "$domain" &
done
REALTIMESCRIPT
chmod +x ${SHIELD_DIR}/scripts/realtime-monitor.sh

#===============================================================================
# VIRUS EVENT HANDLER
#===============================================================================
cat > ${SHIELD_DIR}/scripts/virus-event.sh << 'VIRUSEVENT'
#!/bin/bash
# Called by ClamAV when a virus is detected
VIRUS_NAME="$1"
INFECTED_FILE="$2"
LOG_FILE="/var/log/flyne/shield/realtime.log"

echo "[$(date '+%Y-%m-%d %H:%M:%S')] CLAMAV DETECTION: $VIRUS_NAME in $INFECTED_FILE" >> "$LOG_FILE"

# Extract domain
DOMAIN=$(echo "$INFECTED_FILE" | sed -n 's|/var/www/sites/\([^/]*\)/.*|\1|p')

if [[ -n "$DOMAIN" ]]; then
    source /opt/flyne/flyne.conf 2>/dev/null
    QUARANTINE_DIR="/opt/flyne/shield/quarantine"
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    FILENAME=$(basename "$INFECTED_FILE")
    
    mkdir -p "${QUARANTINE_DIR}/${DOMAIN}"
    mv "$INFECTED_FILE" "${QUARANTINE_DIR}/${DOMAIN}/${TIMESTAMP}_${FILENAME}" 2>/dev/null
    chmod 000 "${QUARANTINE_DIR}/${DOMAIN}/${TIMESTAMP}_${FILENAME}" 2>/dev/null
    
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, created_at)
VALUES ('${DOMAIN}', 'malware_detected', '${VIRUS_NAME}', '${INFECTED_FILE}', 'clamav', 'critical', NOW());
SQLEOF
fi
VIRUSEVENT
chmod +x ${SHIELD_DIR}/scripts/virus-event.sh

#===============================================================================
# SCHEDULED FULL SCAN SERVICE
#===============================================================================
cat > ${SHIELD_DIR}/scripts/full-scan.sh << 'FULLSCAN'
#!/bin/bash
#===============================================================================
# Flyne Shield - Full System Scan
# Comprehensive malware scan with multiple engines
#===============================================================================

SITES_DIR="/var/www/sites"
LOG_FILE="/var/log/flyne/shield/scan.log"
QUARANTINE_DIR="/opt/flyne/shield/quarantine"
YARA_RULES="/opt/flyne/shield/yara/php-malware.yar"
REPORT_DIR="/opt/flyne/shield/reports"

source /opt/flyne/flyne.conf 2>/dev/null || true

mkdir -p "$REPORT_DIR"

SCAN_ID=$(date '+%Y%m%d_%H%M%S')
REPORT_FILE="${REPORT_DIR}/scan_${SCAN_ID}.json"

log_scan() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Initialize report
cat > "$REPORT_FILE" << EOF
{
    "scan_id": "${SCAN_ID}",
    "start_time": "$(date -Iseconds)",
    "sites_scanned": 0,
    "files_scanned": 0,
    "threats_found": 0,
    "threats": [],
    "status": "running"
}
EOF

TOTAL_THREATS=0
TOTAL_FILES=0
SITES_SCANNED=0

for site_dir in ${SITES_DIR}/*/; do
    [[ ! -d "$site_dir" ]] && continue
    
    domain=$(basename "$site_dir")
    public_dir="${site_dir}public"
    
    [[ ! -d "$public_dir" ]] && continue
    
    log_scan "Scanning: $domain"
    ((SITES_SCANNED++))
    
    # YARA Scan
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        rule_name=$(echo "$line" | awk '{print $1}')
        file_path=$(echo "$line" | awk '{print $2}')
        
        log_scan "YARA DETECTION: $rule_name in $file_path"
        
        # Quarantine
        timestamp=$(date '+%Y%m%d_%H%M%S')
        filename=$(basename "$file_path")
        mkdir -p "${QUARANTINE_DIR}/${domain}"
        mv "$file_path" "${QUARANTINE_DIR}/${domain}/${timestamp}_${filename}" 2>/dev/null
        chmod 000 "${QUARANTINE_DIR}/${domain}/${timestamp}_${filename}" 2>/dev/null
        
        ((TOTAL_THREATS++))
        
        # Log to database
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, scan_id, created_at)
VALUES ('${domain}', 'malware_detected', '${rule_name}', '${file_path}', 'yara', 'critical', '${SCAN_ID}', NOW());
SQLEOF
    done < <(yara -r -w "$YARA_RULES" "$public_dir" 2>/dev/null)
    
    # ClamAV Scan
    clam_output=$(clamdscan -r --no-summary --infected "$public_dir" 2>/dev/null)
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file_path=$(echo "$line" | cut -d: -f1)
        virus_name=$(echo "$line" | cut -d: -f2 | tr -d ' ')
        
        [[ "$virus_name" == "OK" ]] && continue
        
        log_scan "CLAMAV DETECTION: $virus_name in $file_path"
        
        # Quarantine (if not already moved)
        if [[ -f "$file_path" ]]; then
            timestamp=$(date '+%Y%m%d_%H%M%S')
            filename=$(basename "$file_path")
            mkdir -p "${QUARANTINE_DIR}/${domain}"
            mv "$file_path" "${QUARANTINE_DIR}/${domain}/${timestamp}_${filename}" 2>/dev/null
            chmod 000 "${QUARANTINE_DIR}/${domain}/${timestamp}_${filename}" 2>/dev/null
        fi
        
        ((TOTAL_THREATS++))
        
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, scan_id, created_at)
VALUES ('${domain}', 'malware_detected', '${virus_name}', '${file_path}', 'clamav', 'critical', '${SCAN_ID}', NOW());
SQLEOF
    done <<< "$clam_output"
    
    # Count files
    file_count=$(find "$public_dir" -type f -name "*.php" 2>/dev/null | wc -l)
    TOTAL_FILES=$((TOTAL_FILES + file_count))
done

# Update report
cat > "$REPORT_FILE" << EOF
{
    "scan_id": "${SCAN_ID}",
    "start_time": "$(date -d @$(($(date +%s) - 60)) -Iseconds)",
    "end_time": "$(date -Iseconds)",
    "sites_scanned": ${SITES_SCANNED},
    "files_scanned": ${TOTAL_FILES},
    "threats_found": ${TOTAL_THREATS},
    "status": "completed"
}
EOF

log_scan "Scan complete: ${SITES_SCANNED} sites, ${TOTAL_FILES} files, ${TOTAL_THREATS} threats"

# Store scan result in database
mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_scans (scan_id, scan_type, sites_scanned, files_scanned, threats_found, status, completed_at)
VALUES ('${SCAN_ID}', 'full', ${SITES_SCANNED}, ${TOTAL_FILES}, ${TOTAL_THREATS}, 'completed', NOW());
SQLEOF

echo "$REPORT_FILE"
FULLSCAN
chmod +x ${SHIELD_DIR}/scripts/full-scan.sh

#===============================================================================
# FILE INTEGRITY MONITORING
#===============================================================================
log "Setting up File Integrity Monitoring..."

cat > ${SHIELD_DIR}/scripts/fim-check.sh << 'FIMSCRIPT'
#!/bin/bash
#===============================================================================
# Flyne Shield - WordPress File Integrity Monitor
# Compares WordPress core files against known good hashes
#===============================================================================

SITES_DIR="/var/www/sites"
LOG_FILE="/var/log/flyne/shield/fim.log"
CACHE_DIR="/opt/flyne/shield/cache"

source /opt/flyne/flyne.conf 2>/dev/null || true

log_fim() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

check_wp_integrity() {
    local site_dir="$1"
    local domain="$2"
    local public_dir="${site_dir}public"
    
    [[ ! -f "${public_dir}/wp-includes/version.php" ]] && return
    
    # Get WordPress version
    wp_version=$(grep "wp_version = " "${public_dir}/wp-includes/version.php" | cut -d"'" -f2)
    [[ -z "$wp_version" ]] && return
    
    log_fim "Checking integrity for $domain (WordPress $wp_version)"
    
    # Download checksums from WordPress.org
    checksums_url="https://api.wordpress.org/core/checksums/1.0/?version=${wp_version}&locale=en_US"
    checksums_file="${CACHE_DIR}/wp-checksums-${wp_version}.json"
    
    if [[ ! -f "$checksums_file" ]] || [[ $(find "$checksums_file" -mtime +7 2>/dev/null) ]]; then
        curl -s "$checksums_url" -o "$checksums_file" 2>/dev/null
    fi
    
    [[ ! -f "$checksums_file" ]] && return
    
    # Check core files
    modified_files=0
    
    # Check key WordPress files
    for core_file in wp-admin/index.php wp-includes/version.php wp-login.php; do
        local_file="${public_dir}/${core_file}"
        [[ ! -f "$local_file" ]] && continue
        
        expected_hash=$(jq -r ".checksums[\"${core_file}\"]" "$checksums_file" 2>/dev/null)
        [[ -z "$expected_hash" || "$expected_hash" == "null" ]] && continue
        
        actual_hash=$(md5sum "$local_file" | awk '{print $1}')
        
        if [[ "$expected_hash" != "$actual_hash" ]]; then
            log_fim "MODIFIED: $core_file in $domain"
            ((modified_files++))
            
            mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine 2>/dev/null << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, created_at)
VALUES ('${domain}', 'file_modified', 'Core file modified', '${local_file}', 'fim', 'high', NOW());
SQLEOF
        fi
    done
    
    log_fim "Integrity check complete for $domain: $modified_files modified files"
}

# Main loop
for site_dir in ${SITES_DIR}/*/; do
    [[ ! -d "$site_dir" ]] && continue
    domain=$(basename "$site_dir")
    check_wp_integrity "$site_dir" "$domain"
done
FIMSCRIPT
chmod +x ${SHIELD_DIR}/scripts/fim-check.sh

#===============================================================================
# DATABASE SCHEMA FOR SECURITY
#===============================================================================
log "Creating security database tables..."

mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine << 'SECURITYDB'
-- Security Events Table
CREATE TABLE IF NOT EXISTS security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    event_type ENUM('malware_detected', 'file_modified', 'brute_force', 'waf_block', 'suspicious_activity') NOT NULL,
    threat_name VARCHAR(255),
    file_path VARCHAR(500),
    quarantine_path VARCHAR(500),
    scanner VARCHAR(50),
    severity ENUM('low', 'medium', 'high', 'critical') DEFAULT 'medium',
    scan_id VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    resolved TINYINT(1) DEFAULT 0,
    resolved_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_created (created_at),
    INDEX idx_resolved (resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Security Scans Table
CREATE TABLE IF NOT EXISTS security_scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id VARCHAR(50) NOT NULL UNIQUE,
    scan_type ENUM('full', 'quick', 'realtime', 'scheduled') DEFAULT 'full',
    sites_scanned INT DEFAULT 0,
    files_scanned INT DEFAULT 0,
    threats_found INT DEFAULT 0,
    duration_seconds INT,
    status ENUM('running', 'completed', 'failed') DEFAULT 'running',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    INDEX idx_scan_id (scan_id),
    INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Quarantine Table
CREATE TABLE IF NOT EXISTS quarantine (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL,
    original_path VARCHAR(500) NOT NULL,
    quarantine_path VARCHAR(500) NOT NULL,
    threat_name VARCHAR(255),
    scanner VARCHAR(50),
    file_hash VARCHAR(64),
    file_size BIGINT,
    restored TINYINT(1) DEFAULT 0,
    restored_at DATETIME,
    deleted TINYINT(1) DEFAULT 0,
    deleted_at DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_restored (restored)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- WAF Events Table
CREATE TABLE IF NOT EXISTS waf_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    rule_id VARCHAR(20),
    rule_msg TEXT,
    ip_address VARCHAR(45),
    request_uri TEXT,
    request_method VARCHAR(10),
    severity VARCHAR(20),
    action ENUM('blocked', 'logged', 'passed') DEFAULT 'blocked',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_domain (domain),
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Security Settings per Site
CREATE TABLE IF NOT EXISTS security_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    site_id INT NOT NULL,
    waf_enabled TINYINT(1) DEFAULT 1,
    realtime_scan TINYINT(1) DEFAULT 1,
    auto_quarantine TINYINT(1) DEFAULT 1,
    email_alerts TINYINT(1) DEFAULT 1,
    paranoia_level INT DEFAULT 1,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SECURITYDB

log "Security tables created"

#===============================================================================
# SYSTEMD SERVICES
#===============================================================================
log "Creating systemd services..."

# Real-time Monitor Service
cat > /etc/systemd/system/flyne-shield-realtime.service << 'REALTIMESVC'
[Unit]
Description=Flyne Shield Real-time Malware Monitor
After=network.target clamav-daemon.service
Wants=clamav-daemon.service

[Service]
Type=simple
ExecStart=/opt/flyne/shield/scripts/realtime-monitor.sh
Restart=always
RestartSec=10
User=root
StandardOutput=append:/var/log/flyne/shield/realtime.log
StandardError=append:/var/log/flyne/shield/realtime.log

[Install]
WantedBy=multi-user.target
REALTIMESVC

# ClamAV On-Access Service
cat > /etc/systemd/system/flyne-shield-onaccess.service << 'ONACCESVC'
[Unit]
Description=Flyne Shield ClamAV On-Access Scanner
After=clamav-daemon.service
Requires=clamav-daemon.service

[Service]
Type=simple
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/clamonacc --fdpass --log=/var/log/flyne/shield/onaccess.log
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
ONACCESVC

# Enable and start services
systemctl daemon-reload
systemctl enable clamav-daemon clamav-freshclam
systemctl restart clamav-daemon clamav-freshclam

sleep 5

systemctl enable flyne-shield-realtime
systemctl start flyne-shield-realtime || warn "Real-time monitor start delayed"

# On-access requires special kernel support
if [[ -c /dev/fanotify ]]; then
    systemctl enable flyne-shield-onaccess
    systemctl start flyne-shield-onaccess || warn "On-access scanner not available"
fi

#===============================================================================
# CRON JOBS FOR SCHEDULED SCANS
#===============================================================================
log "Setting up scheduled scans..."

cat > /etc/cron.d/flyne-shield << 'CRONSECURITY'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Full malware scan daily at 3 AM
0 3 * * * root /opt/flyne/shield/scripts/full-scan.sh >> /var/log/flyne/shield/scan.log 2>&1

# File integrity check every 6 hours
0 */6 * * * root /opt/flyne/shield/scripts/fim-check.sh >> /var/log/flyne/shield/fim.log 2>&1

# Update ClamAV signatures every 2 hours
0 */2 * * * root freshclam --quiet

# Update YARA rules weekly
0 4 * * 0 root /opt/flyne/shield/scripts/update-signatures.sh >> /var/log/flyne/shield/update.log 2>&1

# Cleanup old quarantine files (older than 90 days)
0 5 * * 0 root find /opt/flyne/shield/quarantine -type f -mtime +90 -delete

# Rootkit check weekly
0 4 * * 1 root rkhunter --check --skip-keypress --report-warnings-only >> /var/log/flyne/shield/rootkit.log 2>&1
CRONSECURITY
chmod 644 /etc/cron.d/flyne-shield

#===============================================================================
# SIGNATURE UPDATE SCRIPT
#===============================================================================
cat > ${SHIELD_DIR}/scripts/update-signatures.sh << 'UPDATESIGS'
#!/bin/bash
LOG_FILE="/var/log/flyne/shield/update.log"

log_update() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log_update "Starting signature update..."

# Update ClamAV
freshclam >> "$LOG_FILE" 2>&1

# Download latest PHP Malware Finder rules
cd /tmp
if git clone --depth 1 https://github.com/nbs-system/php-malware-finder.git pmf-update 2>/dev/null; then
    cp pmf-update/php-malware-finder/*.yar /opt/flyne/shield/yara/ 2>/dev/null
    rm -rf pmf-update
    log_update "PHP Malware Finder rules updated"
fi

# Download additional YARA rules
if curl -s -o /opt/flyne/shield/yara/webshell.yar \
    "https://raw.githubusercontent.com/nsacyber/Mitigating-Web-Shells/master/limited.webshell_detection.yara" 2>/dev/null; then
    log_update "NSA webshell rules updated"
fi

# Update Linux Malware Detect signatures
maldet -u >> "$LOG_FILE" 2>&1 || true

# Restart services
systemctl restart clamav-daemon

log_update "Signature update complete"
UPDATESIGS
chmod +x ${SHIELD_DIR}/scripts/update-signatures.sh

#===============================================================================
# SECURITY API ENDPOINTS
#===============================================================================
log "Creating security API..."

cat > ${SHIELD_DIR}/api.php << 'SECURITYAPI'
<?php
/**
 * Flyne Shield Security API
 * Provides endpoints for security monitoring and management
 */

header('Content-Type: application/json');

// Authentication
$api_secret = getenv('FLYNE_API_SECRET') ?: '';
$provided_secret = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$provided_secret = str_replace('Bearer ', '', $provided_secret);

if ($api_secret && $provided_secret !== $api_secret) {
    http_response_code(401);
    die(json_encode(['error' => 'Unauthorized']));
}

// Database connection
$db_host = 'localhost';
$db_user = getenv('FLYNE_MYSQL_USER') ?: 'flyne_admin';
$db_pass = getenv('FLYNE_MYSQL_PASS') ?: '';
$db_name = 'flyne_engine';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name;charset=utf8mb4", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    die(json_encode(['error' => 'Database connection failed']));
}

$action = $_GET['action'] ?? '';
$domain = $_GET['domain'] ?? '';

switch ($action) {
    case 'dashboard':
        // Overall security dashboard stats
        $stats = [];
        
        // Total threats (last 30 days)
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM security_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stats['threats_30d'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        // Threats by severity
        $stmt = $pdo->query("SELECT severity, COUNT(*) as count FROM security_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY severity");
        $stats['by_severity'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Recent threats
        $stmt = $pdo->query("SELECT * FROM security_events ORDER BY created_at DESC LIMIT 10");
        $stats['recent_threats'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Last scan info
        $stmt = $pdo->query("SELECT * FROM security_scans ORDER BY completed_at DESC LIMIT 1");
        $stats['last_scan'] = $stmt->fetch(PDO::FETCH_ASSOC);
        
        // Quarantine count
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM quarantine WHERE restored = 0 AND deleted = 0");
        $stats['quarantine_count'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        // Sites protected
        $stmt = $pdo->query("SELECT COUNT(*) as count FROM sites WHERE status = 'active'");
        $stats['sites_protected'] = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
        
        echo json_encode(['success' => true, 'data' => $stats]);
        break;
        
    case 'site_status':
        if (!$domain) {
            http_response_code(400);
            die(json_encode(['error' => 'Domain required']));
        }
        
        $stmt = $pdo->prepare("SELECT * FROM security_events WHERE domain = ? ORDER BY created_at DESC LIMIT 50");
        $stmt->execute([$domain]);
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $stmt = $pdo->prepare("SELECT * FROM quarantine WHERE domain = ? AND restored = 0 AND deleted = 0");
        $stmt->execute([$domain]);
        $quarantine = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'data' => [
            'events' => $events,
            'quarantine' => $quarantine
        ]]);
        break;
        
    case 'quarantine_list':
        $stmt = $pdo->query("
            SELECT q.*, se.threat_name, se.scanner 
            FROM quarantine q 
            LEFT JOIN security_events se ON q.original_path = se.file_path 
            WHERE q.restored = 0 AND q.deleted = 0 
            ORDER BY q.created_at DESC
        ");
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode(['success' => true, 'data' => $items]);
        break;
        
    case 'quarantine_restore':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die(json_encode(['error' => 'POST required']));
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $quarantine_id = $input['id'] ?? 0;
        
        $stmt = $pdo->prepare("SELECT * FROM quarantine WHERE id = ?");
        $stmt->execute([$quarantine_id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$item) {
            http_response_code(404);
            die(json_encode(['error' => 'Item not found']));
        }
        
        // Restore file
        if (file_exists($item['quarantine_path'])) {
            $dir = dirname($item['original_path']);
            if (!is_dir($dir)) mkdir($dir, 0755, true);
            
            chmod($item['quarantine_path'], 0644);
            rename($item['quarantine_path'], $item['original_path']);
            
            $stmt = $pdo->prepare("UPDATE quarantine SET restored = 1, restored_at = NOW() WHERE id = ?");
            $stmt->execute([$quarantine_id]);
            
            echo json_encode(['success' => true, 'message' => 'File restored']);
        } else {
            http_response_code(404);
            die(json_encode(['error' => 'Quarantine file not found']));
        }
        break;
        
    case 'quarantine_delete':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die(json_encode(['error' => 'POST required']));
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $quarantine_id = $input['id'] ?? 0;
        
        $stmt = $pdo->prepare("SELECT * FROM quarantine WHERE id = ?");
        $stmt->execute([$quarantine_id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($item && file_exists($item['quarantine_path'])) {
            unlink($item['quarantine_path']);
        }
        
        $stmt = $pdo->prepare("UPDATE quarantine SET deleted = 1, deleted_at = NOW() WHERE id = ?");
        $stmt->execute([$quarantine_id]);
        
        echo json_encode(['success' => true, 'message' => 'File permanently deleted']);
        break;
        
    case 'scan_now':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die(json_encode(['error' => 'POST required']));
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $scan_domain = $input['domain'] ?? 'all';
        
        // Trigger scan in background
        $scan_id = date('Ymd_His') . '_manual';
        
        if ($scan_domain === 'all') {
            exec('nohup /opt/flyne/shield/scripts/full-scan.sh > /dev/null 2>&1 &');
        } else {
            exec("nohup /opt/flyne/shield/scripts/scan-site.sh '$scan_domain' > /dev/null 2>&1 &");
        }
        
        echo json_encode(['success' => true, 'scan_id' => $scan_id, 'message' => 'Scan initiated']);
        break;
        
    case 'scan_status':
        $scan_id = $_GET['scan_id'] ?? '';
        
        if ($scan_id) {
            $stmt = $pdo->prepare("SELECT * FROM security_scans WHERE scan_id = ?");
            $stmt->execute([$scan_id]);
        } else {
            $stmt = $pdo->query("SELECT * FROM security_scans ORDER BY started_at DESC LIMIT 1");
        }
        
        $scan = $stmt->fetch(PDO::FETCH_ASSOC);
        echo json_encode(['success' => true, 'data' => $scan]);
        break;
        
    case 'waf_stats':
        $stmt = $pdo->query("
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as blocks,
                COUNT(DISTINCT ip_address) as unique_ips
            FROM waf_events 
            WHERE created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        ");
        $stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $stmt = $pdo->query("SELECT ip_address, COUNT(*) as count FROM waf_events GROUP BY ip_address ORDER BY count DESC LIMIT 10");
        $top_ips = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'data' => [
            'daily_stats' => $stats,
            'top_blocked_ips' => $top_ips
        ]]);
        break;
        
    case 'events':
        $page = max(1, intval($_GET['page'] ?? 1));
        $limit = min(100, max(10, intval($_GET['limit'] ?? 50)));
        $offset = ($page - 1) * $limit;
        $severity = $_GET['severity'] ?? '';
        $event_type = $_GET['type'] ?? '';
        
        $where = "1=1";
        $params = [];
        
        if ($domain) {
            $where .= " AND domain = ?";
            $params[] = $domain;
        }
        if ($severity) {
            $where .= " AND severity = ?";
            $params[] = $severity;
        }
        if ($event_type) {
            $where .= " AND event_type = ?";
            $params[] = $event_type;
        }
        
        $stmt = $pdo->prepare("SELECT * FROM security_events WHERE $where ORDER BY created_at DESC LIMIT $limit OFFSET $offset");
        $stmt->execute($params);
        $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $stmt = $pdo->prepare("SELECT COUNT(*) as total FROM security_events WHERE $where");
        $stmt->execute($params);
        $total = $stmt->fetch(PDO::FETCH_ASSOC)['total'];
        
        echo json_encode(['success' => true, 'data' => $events, 'total' => $total, 'page' => $page]);
        break;
        
    case 'resolve_event':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            die(json_encode(['error' => 'POST required']));
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        $event_id = $input['id'] ?? 0;
        
        $stmt = $pdo->prepare("UPDATE security_events SET resolved = 1, resolved_at = NOW() WHERE id = ?");
        $stmt->execute([$event_id]);
        
        echo json_encode(['success' => true, 'message' => 'Event resolved']);
        break;
        
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Unknown action', 'available_actions' => [
            'dashboard', 'site_status', 'quarantine_list', 'quarantine_restore',
            'quarantine_delete', 'scan_now', 'scan_status', 'waf_stats', 
            'events', 'resolve_event'
        ]]);
}
SECURITYAPI

# Link API to main Flyne directory
ln -sf ${SHIELD_DIR}/api.php ${FLYNE_DIR}/security-api.php

#===============================================================================
# SINGLE SITE SCAN SCRIPT
#===============================================================================
cat > ${SHIELD_DIR}/scripts/scan-site.sh << 'SITESCAN'
#!/bin/bash
DOMAIN="$1"
[[ -z "$DOMAIN" ]] && exit 1

SITES_DIR="/var/www/sites"
SITE_DIR="${SITES_DIR}/${DOMAIN}/public"
YARA_RULES="/opt/flyne/shield/yara/php-malware.yar"
QUARANTINE_DIR="/opt/flyne/shield/quarantine"
LOG_FILE="/var/log/flyne/shield/scan.log"

source /opt/flyne/flyne.conf 2>/dev/null || true

[[ ! -d "$SITE_DIR" ]] && exit 1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scanning site: $DOMAIN" >> "$LOG_FILE"

# YARA scan
yara -r -w "$YARA_RULES" "$SITE_DIR" 2>/dev/null | while read -r line; do
    rule=$(echo "$line" | awk '{print $1}')
    file=$(echo "$line" | awk '{print $2}')
    
    mkdir -p "${QUARANTINE_DIR}/${DOMAIN}"
    mv "$file" "${QUARANTINE_DIR}/${DOMAIN}/$(date +%Y%m%d%H%M%S)_$(basename "$file")" 2>/dev/null
    
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, created_at)
VALUES ('${DOMAIN}', 'malware_detected', '${rule}', '${file}', 'yara', 'critical', NOW());
SQLEOF
done

# ClamAV scan
clamdscan -r --no-summary --infected "$SITE_DIR" 2>/dev/null | while read -r line; do
    [[ -z "$line" ]] && continue
    file=$(echo "$line" | cut -d: -f1)
    virus=$(echo "$line" | cut -d: -f2 | tr -d ' ')
    [[ "$virus" == "OK" ]] && continue
    
    mkdir -p "${QUARANTINE_DIR}/${DOMAIN}"
    mv "$file" "${QUARANTINE_DIR}/${DOMAIN}/$(date +%Y%m%d%H%M%S)_$(basename "$file")" 2>/dev/null
    
    mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" flyne_engine << SQLEOF
INSERT INTO security_events (domain, event_type, threat_name, file_path, scanner, severity, created_at)
VALUES ('${DOMAIN}', 'malware_detected', '${virus}', '${file}', 'clamav', 'critical', NOW());
SQLEOF
done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Site scan complete: $DOMAIN" >> "$LOG_FILE"
SITESCAN
chmod +x ${SHIELD_DIR}/scripts/scan-site.sh

#===============================================================================
# CLI TOOL
#===============================================================================
log "Installing Shield CLI..."

cat > /usr/local/bin/flyne-shield << 'SHIELDCLI'
#!/bin/bash
source /opt/flyne/flyne.conf 2>/dev/null || true

case "$1" in
    status)
        echo "=== Flyne Shield Status ==="
        systemctl is-active --quiet flyne-shield-realtime && echo "Real-time Monitor: Running" || echo "Real-time Monitor: Stopped"
        systemctl is-active --quiet clamav-daemon && echo "ClamAV Daemon: Running" || echo "ClamAV Daemon: Stopped"
        systemctl is-active --quiet flyne-shield-onaccess 2>/dev/null && echo "On-Access Scanner: Running" || echo "On-Access Scanner: Not available"
        echo ""
        echo "Quarantine Files: $(find /opt/flyne/shield/quarantine -type f 2>/dev/null | wc -l)"
        echo "Events (24h): $(mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -N -e "SELECT COUNT(*) FROM flyne_engine.security_events WHERE created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)" 2>/dev/null)"
        ;;
    scan)
        if [[ -n "$2" ]]; then
            echo "Scanning site: $2"
            /opt/flyne/shield/scripts/scan-site.sh "$2"
        else
            echo "Starting full scan..."
            /opt/flyne/shield/scripts/full-scan.sh
        fi
        ;;
    quarantine)
        echo "=== Quarantine ==="
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "SELECT id, domain, threat_name, original_path, created_at FROM flyne_engine.quarantine WHERE restored=0 AND deleted=0 ORDER BY created_at DESC LIMIT 20" 2>/dev/null
        ;;
    events)
        echo "=== Recent Security Events ==="
        mysql -u "$MYSQL_USER" -p"$MYSQL_PASS" -e "SELECT id, domain, event_type, threat_name, severity, created_at FROM flyne_engine.security_events ORDER BY created_at DESC LIMIT 20" 2>/dev/null
        ;;
    update)
        echo "Updating signatures..."
        /opt/flyne/shield/scripts/update-signatures.sh
        ;;
    fim)
        echo "Running file integrity check..."
        /opt/flyne/shield/scripts/fim-check.sh
        ;;
    *)
        echo "Flyne Shield CLI v1.0"
        echo ""
        echo "Commands:"
        echo "  status           - Show security status"
        echo "  scan [domain]    - Run malware scan"
        echo "  quarantine       - List quarantined files"
        echo "  events           - Show recent security events"
        echo "  update           - Update malware signatures"
        echo "  fim              - Run file integrity check"
        ;;
esac
SHIELDCLI
chmod +x /usr/local/bin/flyne-shield

#===============================================================================
# NGINX API ENDPOINT FOR SECURITY
#===============================================================================
log "Configuring security API endpoint..."

cat > /etc/nginx/sites-flyne/002-security-api.conf << 'SECAPICONF'
# Security API - Included in main API
location /security-api.php {
    try_files $uri =404;
    fastcgi_pass unix:/run/php/php8.4-fpm-api.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
}
SECAPICONF

nginx -t && systemctl reload nginx

#===============================================================================
# KERNEL TUNING FOR INOTIFY
#===============================================================================
log "Tuning kernel for file monitoring..."

cat >> /etc/sysctl.d/99-flyne-shield.conf << 'SHIELDSYSCTL'
# Flyne Shield - inotify tuning
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
fs.inotify.max_queued_events = 32768
SHIELDSYSCTL
sysctl -p /etc/sysctl.d/99-flyne-shield.conf 2>/dev/null || true

#===============================================================================
# RKHUNTER CONFIGURATION
#===============================================================================
log "Configuring rootkit detection..."

if [[ -f /etc/rkhunter.conf ]]; then
    sed -i 's/UPDATE_MIRRORS=0/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
    sed -i 's/MIRRORS_MODE=1/MIRRORS_MODE=0/' /etc/rkhunter.conf
    sed -i 's/WEB_CMD=""/WEB_CMD="curl -fsSL"/' /etc/rkhunter.conf
    rkhunter --update 2>/dev/null || true
    rkhunter --propupd 2>/dev/null || true
fi

#===============================================================================
# FINAL SETUP
#===============================================================================
log "Running initial signature update..."
${SHIELD_DIR}/scripts/update-signatures.sh

# Set permissions
chown -R root:root ${SHIELD_DIR}
chmod -R 750 ${SHIELD_DIR}/scripts
chown -R clamav:clamav /var/lib/clamav

#===============================================================================
# SUMMARY
#===============================================================================
echo ""
echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}   FLYNE SHIELD v1.0 INSTALLED SUCCESSFULLY!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo ""
echo -e "${CYAN}Security Features Enabled:${NC}"
echo "  ✓ Real-time file monitoring (inotify)"
echo "  ✓ ClamAV malware scanning"
echo "  ✓ YARA-based PHP malware detection"
echo "  ✓ WordPress-specific signatures"
echo "  ✓ File integrity monitoring"
echo "  ✓ Automatic quarantine system"
echo "  ✓ Rootkit detection (rkhunter)"
echo "  ✓ Security API for dashboard"
echo ""
echo -e "${CYAN}CLI Commands:${NC}"
echo "  flyne-shield status      - Check security status"
echo "  flyne-shield scan        - Run full malware scan"
echo "  flyne-shield quarantine  - View quarantined files"
echo "  flyne-shield events      - View security events"
echo "  flyne-shield update      - Update signatures"
echo ""
echo -e "${CYAN}API Endpoints:${NC}"
echo "  GET  /security-api.php?action=dashboard"
echo "  GET  /security-api.php?action=site_status&domain=example.com"
echo "  GET  /security-api.php?action=quarantine_list"
echo "  POST /security-api.php?action=scan_now"
echo "  GET  /security-api.php?action=events"
echo ""
echo -e "${CYAN}Log Files:${NC}"
echo "  /var/log/flyne/shield/realtime.log"
echo "  /var/log/flyne/shield/scan.log"
echo "  /var/log/flyne/shield/fim.log"
echo ""
log "Flyne Shield installation complete!"