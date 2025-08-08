-- rbac_extract.sql — Extract privileged access for accounts with %UT% or %HA% in username
SET ECHO OFF VERIFY OFF HEADING OFF FEEDBACK OFF TERMOUT OFF PAGES 0 LINES 400 TRIMSPOOL ON

-- Build filename parts
COLUMN cur_date NEW_VALUE DATE
COLUMN sid      NEW_VALUE ORACLE_SID
SELECT TO_CHAR(SYSDATE,'YYYYMMDD_HH24MISS') cur_date FROM dual;
SELECT SYS_CONTEXT('USERENV','INSTANCE_NAME') sid FROM dual;

-- Spool file (example: rbac_privileges_PROD1_20250808_142500.csv)
SPOOL rbac_privileges_&&ORACLE_SID._&&DATE..csv

-- CSV Header
PROMPT "Privilege Name","Username","Owner/Schema","Object Type","Object Name","Access","Granularity Level"

WITH
-- Target users: contains UT or HA anywhere (case-insensitive)
users_of_interest AS (
  SELECT username
    FROM dba_users
   WHERE UPPER(username) LIKE '%UT%'
      OR UPPER(username) LIKE '%HA%'
),

-- Recursive role expansion for those users
role_tree AS (
  SELECT drp.grantee AS username, drp.granted_role AS role
    FROM dba_role_privs drp
   WHERE drp.grantee IN (SELECT username FROM users_of_interest)
  UNION ALL
  SELECT rt.username, drp.granted_role
    FROM dba_role_privs drp
    JOIN role_tree rt ON drp.grantee = rt.role
),
roles_expanded AS (
  SELECT DISTINCT username, role FROM role_tree
),

-- SYSTEM privileges granted to roles (to be mapped to users via roles_expanded)
role_sys_privs AS (
  SELECT drp.granted_role AS role, dsp.privilege
    FROM dba_sys_privs dsp
    JOIN dba_role_privs drp ON dsp.grantee = drp.granted_role
),

-- OBJECT privileges granted to roles (to be mapped to users via roles_expanded)
role_tab_privs AS (
  SELECT drp.granted_role AS role, dtp.privilege, dtp.owner, dtp.type, dtp.table_name
    FROM dba_tab_privs dtp
    JOIN dba_role_privs drp ON dtp.grantee = drp.granted_role
),

-- Direct SYSTEM privileges to users
direct_sys AS (
  SELECT dsp.privilege, dsp.grantee,
         NULL AS owner_schema, NULL AS object_type, NULL AS object_name,
         dsp.privilege AS access, 'SYSTEM' AS granularity_level
    FROM dba_sys_privs dsp
   WHERE dsp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct OBJECT privileges to users
direct_obj AS (
  SELECT dtp.privilege, dtp.grantee, dtp.owner AS owner_schema, dtp.type AS object_type, dtp.table_name AS object_name,
         dtp.privilege AS access, 'OBJECT' AS granularity_level
    FROM dba_tab_privs dtp
   WHERE dtp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct COLUMN privileges to users
direct_col AS (
  SELECT dcp.privilege, dcp.grantee, dcp.table_schema AS owner_schema, 'COLUMN' AS object_type,
         dcp.table_name || '.' || dcp.column_name AS object_name,
         dcp.privilege AS access, 'COLUMN' AS granularity_level
    FROM dba_col_privs dcp
   WHERE dcp.grantee IN (SELECT username FROM users_of_interest)
),

-- SYSTEM privileges via roles
role_sys AS (
  SELECT rsp.privilege, re.username,
         NULL AS owner_schema, NULL AS object_type, NULL AS object_name,
         rsp.privilege || ' (via role ' || rsp.role || ')' AS access,
         'ROLE->SYSTEM' AS granularity_level
    FROM role_sys_privs rsp
    JOIN roles_expanded re ON rsp.role = re.role
),

-- OBJECT privileges via roles
role_obj AS (
  SELECT rtp.privilege, re.username, rtp.owner AS owner_schema, rtp.type AS object_type, rtp.table_name AS object_name,
         rtp.privilege || ' (via role ' || rtp.role || ')' AS access,
         'ROLE->OBJECT' AS granularity_level
    FROM role_tab_privs rtp
    JOIN roles_expanded re ON rtp.role = re.role
)

-- Final CSV output
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

SPOOL OFF
EXIT
