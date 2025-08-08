-- non_read_privs_utcode.sql
SET PAGES 0 LINES 400 TRIMSPOOL ON HEADING ON FEEDBACK OFF

COL USERNAME        FORMAT A30
COL PRIVILEGE_TYPE  FORMAT A10
COL PRIVILEGE_NAME  FORMAT A35
COL OWNER           FORMAT A30
COL OBJECT_TYPE     FORMAT A18
COL OBJECT_NAME     FORMAT A64
COL HOW_GRANTED     FORMAT A40

WITH
users_of_interest AS (
  SELECT username
  FROM   dba_users
  WHERE  UPPER(username) LIKE '%UTCODE%'
),

-- Expand all roles (direct & nested) held by those users
role_tree (username, role) AS (
  SELECT drp.grantee, drp.granted_role
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

/* ---------------- Direct grants ---------------- */

direct_sys AS (
  SELECT dsp.grantee        AS username,
         'SYSTEM'           AS privilege_type,
         dsp.privilege      AS privilege_name,
         CAST(NULL AS VARCHAR2(128)) AS owner,
         CAST(NULL AS VARCHAR2(30))  AS object_type,
         CAST(NULL AS VARCHAR2(128)) AS object_name,
         'DIRECT'           AS how_granted
  FROM   dba_sys_privs dsp
  WHERE  dsp.grantee IN (SELECT username FROM users_of_interest)
  -- exclude read-only style system privileges
  AND    dsp.privilege NOT LIKE 'SELECT ANY%'
  AND    dsp.privilege NOT LIKE 'READ ANY%'
  AND    dsp.privilege NOT IN ('CREATE SESSION')
),

direct_obj AS (
  SELECT dtp.grantee        AS username,
         'OBJECT'           AS privilege_type,
         dtp.privilege      AS privilege_name,
         dtp.owner          AS owner,
         NVL(do.object_type,'OBJECT') AS object_type,
         dtp.table_name     AS object_name,
         'DIRECT'           AS how_granted
  FROM   dba_tab_privs dtp
  LEFT   JOIN dba_objects do
    ON   do.owner = dtp.owner
   AND   do.object_name = dtp.table_name
  WHERE  dtp.grantee IN (SELECT username FROM users_of_interest)
  -- exclude read-only object privs
  AND    dtp.privilege NOT IN ('SELECT','READ')
),

direct_col AS (
  SELECT dcp.grantee        AS username,
         'COLUMN'           AS privilege_type,
         dcp.privilege      AS privilege_name,
         dcp.owner          AS owner,
         'COLUMN'           AS object_type,
         dcp.table_name||'.'||dcp.column_name AS object_name,
         'DIRECT'           AS how_granted
  FROM   dba_col_privs dcp
  WHERE  dcp.grantee IN (SELECT username FROM users_of_interest)
  -- exclude read-only column privs
  AND    dcp.privilege NOT IN ('SELECT','READ')
),

/* ---------------- Grants via roles ---------------- */

role_sys AS (
  SELECT re.username        AS username,
         'SYSTEM'           AS privilege_type,
         dsp.privilege      AS privilege_name,
         CAST(NULL AS VARCHAR2(128)) AS owner,
         CAST(NULL AS VARCHAR2(30))  AS object_type,
         CAST(NULL AS VARCHAR2(128)) AS object_name,
         'VIA ROLE '||re.role AS how_granted
  FROM   dba_sys_privs dsp
  JOIN   roles_expanded re
    ON   dsp.grantee = re.role
  -- exclude read-only style system privileges
  WHERE  dsp.privilege NOT LIKE 'SELECT ANY%'
    AND  dsp.privilege NOT LIKE 'READ ANY%'
    AND  dsp.privilege NOT IN ('CREATE SESSION')
),

role_obj AS (
  SELECT re.username        AS username,
         'OBJECT'           AS privilege_type,
         dtp.privilege      AS privilege_name,
         dtp.owner          AS owner,
         NVL(do.object_type,'OBJECT') AS object_type,
         dtp.table_name     AS object_name,
         'VIA ROLE '||re.role AS how_granted
  FROM   dba_tab_privs dtp
  JOIN   roles_expanded re
    ON   dtp.grantee = re.role
  LEFT   JOIN dba_objects do
    ON   do.owner = dtp.owner
   AND   do.object_name = dtp.table_name
  -- exclude read-only object privs
  WHERE  dtp.privilege NOT IN ('SELECT','READ')
)

SELECT username, privilege_type, privilege_name, owner, object_type, object_name, how_granted
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
ORDER BY username, privilege_type, owner NULLS FIRST, object_type NULLS FIRST, object_name NULLS FIRST, privilege_name;
