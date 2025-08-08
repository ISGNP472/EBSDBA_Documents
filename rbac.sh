#!/bin/bash

#----- CONFIGURE THESE VARIABLES -----
ORACLE_SID="[ORACLE_SID]"
OUTPUT_DIR="./"
CSV_REPORT="$OUTPUT_DIR/oracle_user_audit_report.csv"
HTML_REPORT="$OUTPUT_DIR/oracle_user_audit_report.html"
SQL_OUTPUT="$OUTPUT_DIR/oracle_audit_raw_output.txt"
PDB_NAME="PDB1"
#-------------------------------------

# SQL*Plus connect string (sysdba)
CONNECT_STRING="/ as sysdba"

# SQL script to extract instance and user privilege data within the PDB context
cat > $OUTPUT_DIR/oracle_audit_extract.sql <<EOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=$PDB_NAME;
-- Instance details
SELECT 'INSTANCE_NAME:' || instance_name || ',HOST:' || host_name || ',VERSION:' || version FROM v\\$instance;
-- CSV Header
PROMPT USERNAME,ACCESS_NAME,ACCESS_TYPE,ADMIN_OPTION,OBJECT_OWNER,OBJECT_NAME,COLUMN_NAME

-- Roles
SELECT username || ',' || granted_role || ',' || 'ROLE' || ',' || admin_option || ',,,' 
FROM dba_users u JOIN dba_role_privs r ON u.username = r.grantee
WHERE (u.username LIKE '%CODE%' OR u.username LIKE '%HA');

-- System Privileges
SELECT username || ',' || privilege || ',' || 'SYSTEM PRIVILEGE' || ',' || admin_option || ',,,' 
FROM dba_users u JOIN dba_sys_privs s ON u.username = s.grantee
WHERE (u.username LIKE '%CODE%' OR u.username LIKE '%HA');

-- Object Privileges
SELECT username || ',' || privilege || ',' || 'OBJECT PRIVILEGE' || ',' || grantable || ',' || owner || ',' || table_name || ',' || NVL(column_name,'') 
FROM dba_users u JOIN dba_tab_privs t ON u.username = t.grantee
WHERE (u.username LIKE '%CODE%' OR u.username LIKE '%HA');
EXIT;
EOF

# Set Oracle environment variables if provided (optional, for remote or custom setups)
if [ -n "$ORACLE_SID" ]; then export ORACLE_SID=$ORACLE_SID; fi
if [ -n "$ORACLE_HOME" ]; then export ORACLE_HOME=$ORACLE_HOME; fi
if [ -n "$PATH" ] && [ -n "$ORACLE_HOME" ]; then export PATH=$ORACLE_HOME/bin:$PATH; fi

# Run SQL*Plus and collect output
sqlplus -s "$CONNECT_STRING" @$OUTPUT_DIR/oracle_audit_extract.sql > $SQL_OUTPUT

# Extract instance details and CSV data
INSTANCE_LINE=$(grep "INSTANCE_NAME:" "$SQL_OUTPUT" | head -1)
CSV_HEADER=$(grep "^USERNAME," "$SQL_OUTPUT" | head -1)
grep -v "INSTANCE_NAME:" "$SQL_OUTPUT" | grep -v "^$" | grep -v "^USERNAME," > "$OUTPUT_DIR/raw_data.csv"

# Create CSV report
{
  echo "$INSTANCE_LINE"
  echo "$CSV_HEADER"
  cat "$OUTPUT_DIR/raw_data.csv"
} > "$CSV_REPORT"

# Create HTML report
{
  echo "<html><head><title>Oracle User Audit Report</title>"
  echo "<style>table {border-collapse: collapse;} th, td {border: 1px solid #888; padding: 4px;} th {background: #eee;} </style>"
  echo "</head><body>"
  echo "<h2>Oracle User Audit Report</h2>"
  echo "<p><b>Instance Details:</b> $INSTANCE_LINE</p>"
  echo "<table>"
  # HTML table header
  IFS=',' read -ra HEADERS <<< "$CSV_HEADER"
  echo "<tr>"
  for col in "${HEADERS[@]}"; do
    echo "<th>${col}</th>"
  done
  echo "</tr>"
  # HTML table rows
  while IFS=',' read -ra ROW; do
    echo "<tr>"
    for col in "${ROW[@]}"; do
      echo "<td>${col}</td>"
    done
    echo "</tr>"
  done < "$OUTPUT_DIR/raw_data.csv"
  echo "</table>"
  echo "<p>Report generated on $(date "+%Y-%m-%d %H:%M:%S")</p>"
  echo "</body></html>"
} > "$HTML_REPORT"

# Clean up
rm -f "$SQL_OUTPUT" "$OUTPUT_DIR/raw_data.csv" "$OUTPUT_DIR/oracle_audit_extract.sql"

echo "Audit completed."
echo "CSV Report: $CSV_REPORT"
echo "HTML Report: $HTML_REPORT"
