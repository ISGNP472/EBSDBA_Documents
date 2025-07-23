#!/bin/bash

# Set variables
BACKUP_DIR="/path/to/backup"
EBS_APPS_DIR="/path/to/EBSapps"
TAR_PREFIX="EBSapps_backup"
DAYS_TO_KEEP=3
PRECLONE_SCRIPT="/path/to/apps/preclone.sh"

# 1. Remove backup tars older than 3 days
find "$BACKUP_DIR" -name "${TAR_PREFIX}_*.tar.gz" -type f -mtime +$DAYS_TO_KEEP -exec rm -f {} \;

# 2. Run the preclone on the Application Tier
if [ -x "$PRECLONE_SCRIPT" ]; then
    echo "Running preclone script..."
    "$PRECLONE_SCRIPT"
    PRECLONE_STATUS=$?
    if [ $PRECLONE_STATUS -ne 0 ]; then
        echo "Preclone failed with status $PRECLONE_STATUS. Aborting backup."
        exit 1
    fi
else
    echo "Preclone script not found or not executable: $PRECLONE_SCRIPT"
    exit 1
fi

# 3. Take the tar of EBSapps
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
TAR_FILE="${BACKUP_DIR}/${TAR_PREFIX}_${TIMESTAMP}.tar.gz"
tar -czf "$TAR_FILE" -C "$EBS_APPS_DIR" .

echo "Backup complete: $TAR_FILE"
