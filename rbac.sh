#!/usr/bin/env bash
# rbac_extract_sid.sh — Extract privileged access for accounts with %UT% or %HA in username
# Outputs: rbac_privileges_<SID>_YYYYMMDD_HH24MISS.csv

set -euo pipefail

# Ensure ORACLE_SID is set
if [ -z "${ORACLE_SID:-}" ]; then
    echo "ERROR: ORACLE_SID is not set in the environment."
    exit 1
fi

# Load Oracle environment
. oraenv <<<"$ORACLE_SID" > /dev/null 2>&1

OUTFILE="rbac_privileges_${ORACLE_SID}_$(date +%Y%m%d_%H%M%S).csv"

# --- Run SQL as sysdba ---
sqlplus -s "/ as sysdba" <<SQL > "$OUTFILE"
WHENEVER SQLERROR EXIT FAILURE
SET HEADING OFF FEEDBACK OFF TERMOUT OFF PAGES 0 LINES 400 TRIMSPOOL ON

-- CSV Header
PROMPT "Privilege Name","Username","Owner/Schema","Object Type","Object Name","Access","Granularity Level"

WITH
-- Fixed filter: %UT% or %HA anywhere in username
users_of_interest AS (
  SELECT username
  FROM   dba_users
  WHERE  username LIKE '%UT%' OR username LIKE '%HA'
),

-- Recursive role expansion
role_tree AS (
  SELECT drp.grantee AS username, drp.granted_role AS role
  FROM   dba_role_privs drp
  WHERE  drp.grantee IN (SELECT username FROM users_of_interest)
  UNION ALL
  SELECT rt.username, drp.granted_role
  FROM   dba_role_privs drp
  JOIN   role_tree rt ON drp.grantee = rt.role
),

roles_expanded AS (
  SELECT DISTINCT username, role FROM role_tree
),

-- Direct SYSTEM privileges
direct_sys AS (
  SELECT dsp.privilege, dsp.grantee,
         NULL, NULL, NULL,
         dsp.privilege, 'SYSTEM'
  FROM   dba_sys_privs dsp
  WHERE  dsp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct OBJECT privileges
direct_obj AS (
  SELECT dtp.privilege, dtp.grantee, dtp.owner, dtp.type, dtp.table_name,
         dtp.privilege, 'OBJECT'
  FROM   dba_tab_privs dtp
  WHERE  dtp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct COLUMN privileges
direct_col AS (
  SELECT dcp.privilege, dcp.grantee, dcp.table_schema, 'COLUMN',
         dcp.table_name || '.' || dcp.column_name,
         dcp.privilege, 'COLUMN'
  FROM   dba_col_privs dcp
  WHERE  dcp.grantee IN (SELECT username FROM users_of_interest)
),

-- SYSTEM privileges via roles
role_sys AS (
  SELECT rsp.privilege, re.username,
         NULL, NULL, NULL,
         rsp.privilege || ' (via role ' || rsp.role || ')', 'ROLE->SYSTEM'
  FROM   role_sys_privs rsp
  JOIN   roles_expanded re ON rsp.role = re.role
),

-- OBJECT privileges via roles
role_obj AS (
  SELECT rtp.privilege, re.username, rtp.owner, rtp.type, rtp.table_name,
         rtp.privilege || ' (via role ' || rtp.role || ')', 'ROLE->OBJECT'
  FROM   role_tab_privs rtp
  JOIN   roles_expanded re ON rtp.role = re.role
)

-- Final Output
SELECT '"' || privilege_name   || '","'
       || username             || '","'
       || NVL(owner_schema,'') || '","'
       || NVL(object_type,'')  || '","'
       || NVL(object_name,'')  || '","'
       || access               || '","'
       || granularity_level    || '"'
FROM (
  SELECT privilege AS privilege_name, grantee AS username, owner_schema, object_type, object_name, access, granularity_level FROM direct_sys
  UNION ALL
  SELECT privilege AS privilege_name, grantee AS username, owner_schema, object_type, object_name, access, granularity_level FROM direct_obj
  UNION ALL
  SELECT privilege AS privilege_name, grantee AS username, owner_schema, object_type, object_name, access, granularity_level FROM direct_col
  UNION ALL
  SELECT privilege AS privilege_name, username, owner_schema, object_type, object_name, access, granularity_level FROM role_sys
  UNION ALL
  SELECT privilege AS privilege_name, username, owner_schema, object_type, object_name, access, granularity_level FROM role_obj
)
ORDER BY username, granularity_level, owner_schema NULLS FIRST, object_type NULLS FIRST, object_name NULLS FIRST, privilege_name;

EXIT
SQL

echo "Done. Output file: $OUTFILE"
