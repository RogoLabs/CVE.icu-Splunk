#!/bin/bash
#===============================================================================
# TA-cveicu Factory Reset Script
#===============================================================================
#
# Purpose: Completely wipe local state of TA-cveicu for fresh installation testing
#
# Usage:
#   cd $SPLUNK_HOME
#   sudo -u splunk ./etc/apps/TA-cveicu/scripts/factory_reset.sh
#
# Or with options:
#   ./factory_reset.sh --skip-stop      # Don't stop Splunk
#   ./factory_reset.sh --skip-index     # Don't clean index data
#   ./factory_reset.sh --dry-run        # Show what would be done without doing it
#
# Requirements:
#   - Must be run from $SPLUNK_HOME directory
#   - Splunk admin credentials (will prompt if not provided)
#   - sudo/root access recommended for stopping Splunk
#
#===============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#===============================================================================
# Configuration
#===============================================================================

APP_NAME="TA-cveicu"
KVSTORE_COLLECTION="ta_cveicu_checkpoints"
CREDENTIAL_REALM="TA-cveicu"
CREDENTIAL_NAME="github_token"
LOG_FILE="var/log/splunk/${APP_NAME}.log"
INDEX_NAME="cve_data"
SPLUNK_URI="https://localhost:8089"

# Parse command line arguments
SKIP_STOP=false
SKIP_INDEX=false
DRY_RUN=false
SPLUNK_USER=""
SPLUNK_PASS=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-stop)
            SKIP_STOP=true
            shift
            ;;
        --skip-index)
            SKIP_INDEX=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --user)
            SPLUNK_USER="$2"
            shift 2
            ;;
        --password)
            SPLUNK_PASS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-stop     Don't stop Splunk before reset"
            echo "  --skip-index    Don't clean index data"
            echo "  --dry-run       Show what would be done without executing"
            echo "  --user USER     Splunk admin username"
            echo "  --password PASS Splunk admin password"
            echo "  -h, --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

#===============================================================================
# Helper Functions
#===============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

run_cmd() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would execute: $1"
    else
        eval "$1"
    fi
}

confirm() {
    if [ "$DRY_RUN" = true ]; then
        return 0
    fi
    read -p "$(echo -e ${YELLOW}$1${NC}) [y/N] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Yy]$ ]]
}

#===============================================================================
# Pre-flight Checks
#===============================================================================

echo ""
echo "==============================================================================="
echo "  TA-cveicu Factory Reset"
echo "==============================================================================="
echo ""

# Check if we're in SPLUNK_HOME
if [ ! -f "bin/splunk" ]; then
    log_error "This script must be run from \$SPLUNK_HOME directory"
    log_error "Current directory: $(pwd)"
    log_error "Usage: cd \$SPLUNK_HOME && ./etc/apps/${APP_NAME}/scripts/factory_reset.sh"
    exit 1
fi

SPLUNK_HOME=$(pwd)
APP_DIR="etc/apps/${APP_NAME}"

if [ ! -d "$APP_DIR" ]; then
    log_error "App directory not found: $APP_DIR"
    exit 1
fi

log_info "SPLUNK_HOME: $SPLUNK_HOME"
log_info "App directory: $APP_DIR"

if [ "$DRY_RUN" = true ]; then
    log_warning "DRY-RUN MODE - No changes will be made"
fi

echo ""

# Get credentials if not provided
if [ -z "$SPLUNK_USER" ]; then
    read -p "Splunk admin username: " SPLUNK_USER
fi

if [ -z "$SPLUNK_PASS" ]; then
    read -s -p "Splunk admin password: " SPLUNK_PASS
    echo ""
fi

# Final confirmation
echo ""
log_warning "This will PERMANENTLY DELETE:"
echo "  - Local configs (${APP_DIR}/local/)"
echo "  - KV Store checkpoints (${KVSTORE_COLLECTION})"
echo "  - Stored credentials (${CREDENTIAL_NAME})"
echo "  - Log files (${LOG_FILE})"
echo "  - Metadata (${APP_DIR}/metadata/local.meta)"
if [ "$SKIP_INDEX" = false ]; then
    echo "  - All indexed data in '${INDEX_NAME}'"
fi
echo ""

if ! confirm "Are you sure you want to continue?"; then
    log_info "Aborted by user"
    exit 0
fi

echo ""
echo "==============================================================================="
echo "  Starting Factory Reset"
echo "==============================================================================="
echo ""

#===============================================================================
# Step 1: Stop Splunk (Optional)
#===============================================================================

if [ "$SKIP_STOP" = false ]; then
    log_info "Step 1: Stopping Splunk..."
    if run_cmd "./bin/splunk stop"; then
        log_success "Splunk stopped"
    else
        log_warning "Could not stop Splunk (may not be running)"
    fi
else
    log_info "Step 1: Skipping Splunk stop (--skip-stop)"
fi

echo ""

#===============================================================================
# Step 2: Wipe Local Configs
#===============================================================================

log_info "Step 2: Wiping local configs..."

LOCAL_DIR="${APP_DIR}/local"
if [ -d "$LOCAL_DIR" ]; then
    log_info "  Removing: $LOCAL_DIR"
    run_cmd "rm -rf '$LOCAL_DIR'"
    log_success "Local configs removed"
else
    log_info "  No local directory found (already clean)"
fi

echo ""

#===============================================================================
# Step 3: Remove Metadata
#===============================================================================

log_info "Step 3: Removing local metadata..."

METADATA_LOCAL="${APP_DIR}/metadata/local.meta"
if [ -f "$METADATA_LOCAL" ]; then
    log_info "  Removing: $METADATA_LOCAL"
    run_cmd "rm -f '$METADATA_LOCAL'"
    log_success "Local metadata removed"
else
    log_info "  No local.meta found (already clean)"
fi

echo ""

#===============================================================================
# Step 4: Clean Log Files
#===============================================================================

log_info "Step 4: Cleaning log files..."

if [ -f "$LOG_FILE" ]; then
    log_info "  Removing: $LOG_FILE"
    run_cmd "rm -f '$LOG_FILE'"
    log_success "Log file removed"
else
    log_info "  No log file found (already clean)"
fi

# Also clean any rotated logs
ROTATED_LOGS=$(find var/log/splunk -name "${APP_NAME}*.log*" 2>/dev/null || true)
if [ -n "$ROTATED_LOGS" ]; then
    log_info "  Removing rotated logs..."
    run_cmd "rm -f var/log/splunk/${APP_NAME}*.log*"
fi

echo ""

#===============================================================================
# Step 5: Start Splunk for REST operations (if stopped)
#===============================================================================

if [ "$SKIP_STOP" = false ] && [ "$DRY_RUN" = false ]; then
    log_info "Step 5: Starting Splunk for REST operations..."
    if ./bin/splunk start --accept-license --answer-yes --no-prompt; then
        log_success "Splunk started"
        sleep 5  # Wait for REST API to be ready
    else
        log_error "Failed to start Splunk"
        exit 1
    fi
else
    log_info "Step 5: Skipping Splunk start"
fi

echo ""

#===============================================================================
# Step 6: Clear KV Store Checkpoints
#===============================================================================

log_info "Step 6: Clearing KV Store checkpoints..."

KVSTORE_URL="${SPLUNK_URI}/servicesNS/nobody/${APP_NAME}/storage/collections/data/${KVSTORE_COLLECTION}"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} Would execute:"
    echo "  curl -k -u \$USER:\$PASS -X DELETE '$KVSTORE_URL'"
else
    RESPONSE=$(curl -s -k -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
        -X DELETE \
        "$KVSTORE_URL" \
        -w "\n%{http_code}" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        log_success "KV Store checkpoints cleared"
    elif [ "$HTTP_CODE" = "404" ]; then
        log_info "  KV Store collection not found (already clean or not created)"
    else
        log_warning "KV Store clear returned HTTP $HTTP_CODE"
        log_warning "  Response: $BODY"
    fi
fi

echo ""

#===============================================================================
# Step 7: Remove Secure Credentials
#===============================================================================

log_info "Step 7: Removing secure credentials..."

CRED_URL="${SPLUNK_URI}/servicesNS/nobody/${APP_NAME}/storage/passwords/${CREDENTIAL_REALM}%3A${CREDENTIAL_NAME}%3A"

if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} Would execute:"
    echo "  curl -k -u \$USER:\$PASS -X DELETE '$CRED_URL'"
else
    RESPONSE=$(curl -s -k -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
        -X DELETE \
        "$CRED_URL" \
        -w "\n%{http_code}" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        log_success "Secure credentials removed"
    elif [ "$HTTP_CODE" = "404" ]; then
        log_info "  Credential not found (already clean or never stored)"
    else
        log_warning "Credential removal returned HTTP $HTTP_CODE"
        log_warning "  Response: $BODY"
    fi
fi

echo ""

#===============================================================================
# Step 8: Delete Indexed Data (Optional)
#===============================================================================

if [ "$SKIP_INDEX" = false ]; then
    log_info "Step 8: Cleaning indexed data..."
    
    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would execute:"
        echo "  ./bin/splunk clean eventdata -index ${INDEX_NAME} -f"
    else
        log_warning "Stopping Splunk for index cleaning..."
        ./bin/splunk stop
        
        if ./bin/splunk clean eventdata -index "$INDEX_NAME" -f; then
            log_success "Index data cleaned: $INDEX_NAME"
        else
            log_warning "Could not clean index (may not exist)"
        fi
        
        log_info "Restarting Splunk..."
        ./bin/splunk start --accept-license --answer-yes --no-prompt
    fi
else
    log_info "Step 8: Skipping index cleanup (--skip-index)"
fi

echo ""

#===============================================================================
# Complete
#===============================================================================

echo "==============================================================================="
echo "  Factory Reset Complete"
echo "==============================================================================="
echo ""
log_success "TA-cveicu has been reset to factory state"
echo ""
echo "Next steps:"
echo "  1. Navigate to the app in Splunk Web"
echo "  2. You should see the setup page again"
echo "  3. Configure the input as needed"
echo ""
echo "To verify reset, run:"
echo "  index=_internal source=*${APP_NAME}* earliest=-5m"
echo ""
