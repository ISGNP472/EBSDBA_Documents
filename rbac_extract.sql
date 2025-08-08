-- rbac_extract.sql — Extract privileged access for accounts with %UT% or %HA% in username
SET ECHO OFF VERIFY OFF HEADING OFF FEEDBACK OFF TERMOUT OFF PAGES 0 LINES 400 TRIMSPOOL ON

-- Build filename parts (avoid using reserved names like DATE)
COLUMN ts  NEW_VALUE TS
COLUMN sid NEW_VALUE ORACLE_SID
SELECT TO_CHAR(SYSDATE,'YYYYMMDD_HH24MISS') ts FROM dual;
SELECT SYS_CONTEXT('USERENV','INSTANCE_NAME') sid FROM dual;

-- Spool file (example: rbac_privileges_PROD1_20250808_142500.csv)
SPOOL rbac_privileges_&&ORACLE_SID._&&TS..csv

-- CSV Header
PROMPT "Privilege Name","Username","Owner/Schema","Object Type","Object Name","Access","Granularity Level"

WITH
-- Target users: contains UT or HA anywhere (case-insensitive)
users_of_interest AS (
  SELECT username
  FROM   dba_users
  WHERE  UPPER(username) LIKE '%UT%'
     OR  UPPER(username) LIKE '%HA%'
),

-- All roles (direct/indirect) held by target users (recursive)
role_tree AS (
  SELECT drp.grantee AS username, drp.granted_role AS role
  FROM   dba_role_privs drp
  WHERE  drp.grantee IN (SELECT username FROM users_of_interest)
  UNION ALL
  SELECT rt.username, drp.granted_role
  FROM   dba_role_privs drp
  JOIN   role_tree rt
    ON   drp.grantee = rt.role
),
roles_expanded AS (
  SELECT DISTINCT username, role FROM role_tree
),

/* ===== Direct grants to users ===== */

-- Direct SYSTEM privileges to users
direct_sys AS (
  SELECT dsp.privilege                   AS privilege_name,
         dsp.grantee                     AS username,
         CAST(NULL AS VARCHAR2(128))     AS owner_schema,
         CAST(NULL AS VARCHAR2(128))     AS object_type,
         CAST(NULL AS VARCHAR2(261))     AS object_name,
         dsp.privilege                   AS access,
         'SYSTEM'                        AS granularity_level
  FROM   dba_sys_privs dsp
  WHERE  dsp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct OBJECT privileges to users (resolve object_type via DBA_OBJECTS for safety)
direct_obj AS (
  SELECT dtp.privilege                   AS privilege_name,
         dtp.grantee                     AS username,
         dtp.owner                       AS owner_schema,
         NVL(do.object_type, 'OBJECT')   AS object_type,
         dtp.table_name                  AS object_name,
         dtp.privilege                   AS access,
         'OBJECT'                        AS granularity_level
  FROM   dba_tab_privs dtp
  LEFT   JOIN dba_objects do
         ON do.owner = dtp.owner
        AND do.object_name = dtp.table_name
  WHERE  dtp.grantee IN (SELECT username FROM users_of_interest)
),

-- Direct COLUMN privileges to users (DBA_COL_PRIVS uses OWNER, not TABLE_SCHEMA)
direct_col AS (
  SELECT dcp.privilege                   AS privilege_name,
         dcp.grantee                     AS username,
         dcp.owner                       AS owner_schema,
         'COLUMN'                        AS object_type,
         dcp.table_name || '.' || dcp.column_name AS object_name,
         dcp.privilege                   AS access,
         'COLUMN'                        AS granularity_level
  FROM   dba_col_privs dcp
  WHERE  dcp.grantee IN (SELECT username FROM users_of_interest)
),

/* ===== Grants via roles ===== */

-- SYSTEM privileges granted to roles
role_sys_privs AS (
  SELECT dsp.privilege                   AS privilege_name,
         drp.granted_role                AS role
  FROM   dba_sys_privs dsp
  JOIN   dba_role_privs drp
    ON   dsp.grantee = drp.granted_role
),

-- OBJECT privileges granted to roles (resolve type via DBA_OBJECTS)
role_tab_privs AS (
  SELECT dtp.privilege                   AS privilege_name,
         drp.granted_role                AS role,
         dtp.owner                       AS owner_schema,
         NVL(do.object_type, 'OBJECT')   AS object_type,
         dtp.table_name                  AS object_name
  FROM   dba_tab_privs dtp
  JOIN   dba_role_privs drp
    ON   dtp.grantee = drp.granted_role
  LEFT   JOIN dba_objects do
    ON   do.owner = dtp.owner
   AND   do.object_name = dtp.table_name
),

-- SYSTEM privileges via roles mapped to users
role_sys AS (
  SELECT rsp.privilege_name              AS privilege_name,
         re.username                     AS username,
         CAST(NULL AS VARCHAR2(128))     AS owner_schema,
         CAST(NULL AS VARCHAR2(128))     AS object_type,
         CAST(NULL AS VARCHAR2(261))     AS object_name,
         rsp.privilege_name || ' (via role ' || re.role || ')' AS access,
         'ROLE->SYSTEM'                  AS granularity_level
  FROM   role_sys_privs rsp
  JOIN   roles_expanded re
    ON   rsp.role = re.role
),

-- OBJECT privileges via roles mapped to users
role_obj AS (
  SELECT rtp.privilege_name              AS privilege_name,
         re.username                     AS username,
         rtp.owner_schema                AS owner_schema,
         rtp.object_type                 AS object_type,
         rtp.object_name                 AS object_name,
         rtp.privilege_name || ' (via role ' || re.role || ')' AS access,
         'ROLE->OBJECT'                  AS granularity_level
  FROM   role_tab_privs rtp
  JOIN   roles_expanded re
    ON   rtp.role = re.role
)

/* ===== Final CSV ===== */
SELECT '"' || privilege_name   || '","'
       || username             || '","'
       || NVL(owner_schema,'') || '","'
       || NVL(object_type,'')  || '","'
       || NVL(object_name,'')  || '","'
       || access               || '","'
       || granularity_level    || '"'
FROM (
  SELECT * FROM direct_sys
  UNION ALL
  SELECT * FROM direct_obj
  UNION ALL
  SELECT * FROM direct_col
  UNION ALL
  SELECT * FROM role_sys
  UNION ALL
  SELECT * FROM role_obj
)
ORDER BY username, granularity_level, owner_schema NULLS FIRST, object_type NULLS FIRST, object_name NULLS FIRST, privilege_name;

SPOOL OFF
EXIT
