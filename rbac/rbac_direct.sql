SELECT DISTINCT
       u.username,
       'SYSTEM' AS privilege_type,
       sp.privilege AS privilege_name,
       NULL AS owner,
       NULL AS object_type,
       NULL AS object_name,
       CASE WHEN sp.grantee = u.username THEN 'DIRECT'
            ELSE 'VIA ROLE '||sp.grantee END AS how_granted
FROM   dba_users u
JOIN   (
         SELECT grantee, privilege FROM dba_sys_privs
         UNION ALL
         SELECT drp.grantee, sp.privilege
         FROM   dba_sys_privs sp
         JOIN   dba_role_privs drp ON sp.grantee = drp.granted_role
       ) sp
       ON sp.grantee = u.username
       OR u.username IN (SELECT drp.grantee
                         FROM   dba_role_privs drp
                         WHERE  drp.granted_role = sp.grantee)
WHERE  UPPER(u.username) LIKE '%UTCODE%'
AND    sp.privilege NOT LIKE 'SELECT ANY%'
AND    sp.privilege NOT LIKE 'READ ANY%'
AND    sp.privilege NOT IN ('CREATE SESSION')

UNION ALL

SELECT DISTINCT
       u.username,
       'OBJECT' AS privilege_type,
       tp.privilege AS privilege_name,
       tp.owner,
       NVL(o.object_type, 'OBJECT') AS object_type,
       tp.table_name AS object_name,
       CASE WHEN tp.grantee = u.username THEN 'DIRECT'
            ELSE 'VIA ROLE '||tp.grantee END AS how_granted
FROM   dba_users u
JOIN   (
         SELECT grantee, owner, table_name, privilege FROM dba_tab_privs
         UNION ALL
         SELECT drp.grantee, tp.owner, tp.table_name, tp.privilege
         FROM   dba_tab_privs tp
         JOIN   dba_role_privs drp ON tp.grantee = drp.granted_role
       ) tp
       ON tp.grantee = u.username
       OR u.username IN (SELECT drp.grantee
                         FROM   dba_role_privs drp
                         WHERE  drp.granted_role = tp.grantee)
LEFT JOIN dba_objects o
       ON o.owner = tp.owner
      AND o.object_name = tp.table_name
WHERE  UPPER(u.username) LIKE '%UTCODE%'
AND    tp.privilege NOT IN ('SELECT','READ')

UNION ALL

SELECT DISTINCT
       u.username,
       'COLUMN' AS privilege_type,
       cp.privilege AS privilege_name,
       cp.owner,
       'COLUMN' AS object_type,
       cp.table_name||'.'||cp.column_name AS object_name,
       CASE WHEN cp.grantee = u.username THEN 'DIRECT'
            ELSE 'VIA ROLE '||cp.grantee END AS how_granted
FROM   dba_users u
JOIN   (
         SELECT grantee, owner, table_name, column_name, privilege FROM dba_col_privs
         UNION ALL
         SELECT drp.grantee, cp.owner, cp.table_name, cp.column_name, cp.privilege
         FROM   dba_col_privs cp
         JOIN   dba_role_privs drp ON cp.grantee = drp.granted_role
       ) cp
       ON cp.grantee = u.username
       OR u.username IN (SELECT drp.grantee
                         FROM   dba_role_privs drp
                         WHERE  drp.granted_role = cp.grantee)
WHERE  UPPER(u.username) LIKE '%UTCODE%'
AND    cp.privilege NOT IN ('SELECT','READ')

ORDER BY username, privilege_type, owner, object_type, object_name, privilege_name;
