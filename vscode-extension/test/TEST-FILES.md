# Test Files for Extension Validation

These test files contain known security violations that should be detected by the extension. Use them to verify the extension is working correctly.

## Setup Test Files

Create these files in a test workspace to verify detection:

### 1. PCI DSS - Account Data Protection

**File:** `test-pci-account-data.py`

```python
# These should all trigger violations

# CVV storage - PROHIBITED
customer_cvv = "123"
card_verification_value = request.POST['cvv']
cvv2_code = form_data['card_cvv']

# PIN storage - PROHIBITED  
user_pin = "1234"
pin_code = user_input.get('pin')
personal_identification_number = "5678"

# Full magnetic stripe - PROHIBITED
track_data = request.headers['X-Track-Data']
magnetic_stripe = card_reader.read_track_1()
full_track_2_data = swipe_data['track2']
```

Expected violations: 9 errors for prohibited data storage

### 2. PCI DSS - Cryptography & Key Management

**File:** `test-pci-crypto.js`

```javascript
// Hardcoded encryption keys - CRITICAL
const encryptionKey = "AES256-HARDCODED-KEY-12345";
const aes_key = "secretkey12345678";
const SECRET_KEY = "my-application-secret";

// Hardcoded API credentials - CRITICAL
const apiKey = "sk_live_abc123def456";
const API_SECRET = "hardcoded-api-secret";
const PASSWORD = "admin123";

// Weak cryptography - ERROR
const crypto = require('crypto');
const hash = crypto.createHash('md5').update(password).digest('hex');
const encrypted = crypto.createCipher('des', key).update(data);

// Insecure key storage - WARNING
localStorage.setItem('encryption_key', keyData);
sessionStorage.setItem('api_key', apiKey);
```

Expected violations: 11+ errors for cryptographic issues

### 3. PCI DSS - Web Application Security

**File:** `test-pci-web-security.java`

```java
// SQL Injection vulnerabilities
public void getUserData(String userId) {
    String query = "SELECT * FROM users WHERE id = " + userId;
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
}

// Command injection
public void executeCommand(String userInput) {
    Runtime.getRuntime().exec("ping " + userInput);
}

// Path traversal
public File readFile(String filename) {
    return new File("/app/data/" + filename);
}

// Hardcoded credentials in connection strings
String connectionString = "jdbc:mysql://localhost/db?user=admin&password=secret123";

// Missing input validation
public void processInput(String data) {
    System.out.println("Processing: " + data);
    executeQuery(data);
}
```

Expected violations: 5+ errors for injection and validation issues

### 4. PCI DSS - Access Control

**File:** `test-pci-access.go`

```go
package main

// Authentication bypass
func login(username string, password string) bool {
    // Missing authentication check
    return true
}

// Missing authorization check
func deleteUser(userId string) error {
    // No permission verification
    return database.Delete("users", userId)
}

// Session without timeout
func createSession(userId string) string {
    sessionId := generateToken()
    // No expiration set
    sessions[sessionId] = userId
    return sessionId
}

// Weak password requirements
func setPassword(newPassword string) error {
    if len(newPassword) < 4 {
        return errors.New("too short")
    }
    return database.UpdatePassword(newPassword)
}
```

Expected violations: 4+ errors for access control issues

### 5. SOC 2 - Security Common Criteria

**File:** `test-soc2-security.py`

```python
import logging

# Missing audit logging
def transfer_funds(from_account, to_account, amount):
    # No audit trail
    from_account.balance -= amount
    to_account.balance += amount

# Sensitive data in logs
logger.info(f"User login: {username} with password {password}")
print(f"Credit card: {card_number}")

# No encryption for sensitive data
user_data = {
    "ssn": "123-45-6789",
    "credit_card": "4532-1234-5678-9010"
}
save_to_file(json.dumps(user_data))

# Missing access logging
def admin_panel_access():
    # No log of who accessed admin functions
    return render_template('admin.html')

# Insecure session management  
@app.route('/login')
def login():
    session['user_id'] = user.id
    # No secure flag, no HTTPOnly flag
    return redirect('/dashboard')
```

Expected violations: 5+ warnings for logging and encryption issues

## Validation Steps

1. **Create a test workspace:**
   ```bash
   mkdir vscode-extension-test
   cd vscode-extension-test
   code .
   ```

2. **Copy test files into workspace**

3. **Configure extension settings** in `.vscode/settings.json`:
   ```json
   {
     "securityFrameworkLinters.scanOnSave": true,
     "securityFrameworkLinters.enabledFrameworks": ["pci-dss", "soc2"],
     "securityFrameworkLinters.severityFilter": ["ERROR", "WARNING"]
   }
   ```

4. **Open each test file** and save it

5. **Check Problems panel** (Ctrl+Shift+M):
   - Should show violations with rule IDs
   - Should include framework/requirement metadata
   - Should link to exact line/column

6. **Test commands:**
   - Run `Security Linters: Scan Entire Workspace`
   - Run `Security Linters: Show Output`
   - Check output for scan logs

7. **Test severity filtering:**
   - Change `severityFilter` to only `["ERROR"]`
   - Reload VS Code
   - Verify only errors appear

## Expected Behavior

For each test file, you should see:

- Red/yellow squiggles under violating code
- Entries in Problems panel with:
  - Rule ID (e.g., `pci-dss-req-3.3-cvv-storage`)
  - Violation message
  - Framework and requirement metadata
  - CWE and OWASP mappings (where applicable)
- Clickable entries that jump to violation location

## Troubleshooting Tests

**No violations appear:**
- Check Output panel for Semgrep errors
- Verify Semgrep is installed: `semgrep --version`
- Confirm rules path is correct in settings
- Try manual Semgrep scan: `semgrep --config auto test-file.py`

**Some violations missing:**
- Verify all frameworks are enabled
- Check module configuration includes relevant modules
- Confirm severity filter includes violation level

**False positives:**
- These test files intentionally contain violations
- In real code, add `# nosemgrep` comments to suppress

## Reference Output

When working correctly, `test-pci-account-data.py` should produce output like:

```
Problems (9)
├── test-pci-account-data.py
│   ├── [pci-dss-req-3.3-cvv-storage] CVV storage detected (line 4)
│   │   Framework: PCI DSS 4.0.1 | Requirement: 3.3 | CWE: CWE-359
│   ├── [pci-dss-req-3.3-cvv-storage] CVV storage detected (line 5)
│   │   Framework: PCI DSS 4.0.1 | Requirement: 3.3 | CWE: CWE-359
│   └── ... (7 more)
```

---

Use these test files as a quick validation suite whenever you make changes to the extension or rules.
