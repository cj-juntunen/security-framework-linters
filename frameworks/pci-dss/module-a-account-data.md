# PCI Secure Software Standard - Module A: Account Data Protection

**Standard Version:** v1.2.1  
**Document Version:** 1.0  
**Last Updated:** 2024-11-19  
**Module Type:** Module A - Account Data Protection Requirements

---

## Overview

This document contains code-level compliance rules for **Module A: Account Data Protection** of the PCI Secure Software Standard (PCI SSS). These requirements apply specifically to payment software that stores, processes, or transmits account data.

### About This Module

Module A establishes security requirements for software that handles sensitive authentication data (SAD) and cardholder data (CHD). These requirements are in addition to the Core Requirements and focus on:
- Protection of Primary Account Numbers (PAN)
- Prohibition of sensitive authentication data storage
- Encryption of cardholder data in transit and at rest
- Secure key management for account data encryption
- Data retention and disposal
- Masking and truncation of account data

### Applicability

This module applies to payment software if it:
- Stores cardholder data (even temporarily)
- Processes payment card transactions
- Transmits account data between systems
- Displays or logs account data

### How to Use This Document

Each rule in this document includes:
- **Rule ID**: Unique identifier linking to PCI SSS requirement
- **Severity**: Critical, High, Medium, or Low
- **Detection Pattern**: How to identify violations in code
- **Code Examples**: Both compliant and non-compliant examples
- **Remediation Steps**: How to fix violations
- **Tool Configurations**: Ready-to-use rules for Semgrep, ESLint, etc.

---

## Table of Contents

- [A1. Sensitive Authentication Data Protection](#a1-sensitive-authentication-data-protection)
- [A2. Primary Account Number Protection](#a2-primary-account-number-protection)
- [A3. Cardholder Data Encryption](#a3-cardholder-data-encryption)
- [A4. Cryptographic Key Management](#a4-cryptographic-key-management)
- [A5. Data Retention and Disposal](#a5-data-retention-and-disposal)
- [A6. Account Data Display and Logging](#a6-account-data-display-and-logging)

---

## A1. Sensitive Authentication Data Protection

### Rule: PCI-SSS-A1.1 - Prohibition of SAD Storage After Authorization

**Severity:** Critical  
**PCI SSS Reference:** Module A, Requirement A1.1

#### Description
Sensitive Authentication Data (SAD) must NEVER be stored after authorization, even if encrypted. This includes:
- Full magnetic stripe data (track data)
- CAV2/CVC2/CVV2/CID (card verification codes)
- PIN/PIN blocks

#### Rationale
Storage of SAD violates PCI DSS and creates catastrophic risk if compromised. Even encrypted SAD storage is prohibited because these values are used to create fraudulent cards.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Variable naming + Database operations
- **Looks for:**
  - Variables named cvv, cvc, cav, cid, pin, track, magnetic
  - Database INSERT/UPDATE with these field names
  - File writes containing these data elements

#### Examples

##### Non-Compliant Code

```python
# Python - CRITICAL VIOLATION: Storing CVV
def process_payment(card_number, cvv, expiry):
    transaction = {
        'card': card_number,
        'cvv': cvv,  # VIOLATION - CVV must never be stored
        'expiry': expiry,
        'timestamp': datetime.now()
    }
    db.transactions.insert(transaction)  # VIOLATION
    
    return gateway.authorize(card_number, cvv, expiry)

# Python - CRITICAL VIOLATION: Storing track data
def swipe_payment(track_data):
    # VIOLATION - magnetic stripe data must not be stored
    db.save("INSERT INTO payments (track_data) VALUES (?)", track_data)
```

```javascript
// JavaScript - CRITICAL VIOLATION: Storing PIN
async function processPINDebit(cardNumber, pin, amount) {
    // VIOLATION - PIN must never be stored
    await db.query(
        'INSERT INTO transactions (card, pin, amount) VALUES (?, ?, ?)',
        [cardNumber, pin, amount]
    );
    
    return await pinPad.authorize(cardNumber, pin, amount);
}

// JavaScript - CRITICAL VIOLATION: Logging CVV
function validateCard(cardData) {
    console.log('Validating card:', cardData.number, cardData.cvv);  // VIOLATION
    return cardData.cvv.length === 3;
}
```

```java
// Java - CRITICAL VIOLATION: Storing CVC in database
public class PaymentService {
    public Transaction processPayment(PaymentRequest request) {
        Transaction txn = new Transaction();
        txn.setCardNumber(request.getCardNumber());
        txn.setCvc(request.getCvc());  // VIOLATION
        txn.setAmount(request.getAmount());
        
        // VIOLATION - CVC persisted to database
        transactionRepository.save(txn);
        
        return gateway.authorize(request);
    }
}
```

##### Compliant Code

```python
# Python - Compliant: CVV used but not stored
def process_payment(card_number, cvv, expiry):
    # Use CVV only for authorization
    auth_result = gateway.authorize(card_number, cvv, expiry)
    
    # Store only non-sensitive data
    transaction = {
        'card_token': auth_result.token,  # Tokenized reference
        'last_four': card_number[-4:],
        'expiry': expiry,
        'auth_code': auth_result.auth_code,
        'timestamp': datetime.now()
    }
    db.transactions.insert(transaction)  # COMPLIANT - no SAD
    
    # CVV is never stored, only used in memory
    return auth_result

# Python - Compliant: Track data not stored
def swipe_payment(track_data):
    # Parse and extract only necessary data
    parsed = parse_track_data(track_data)
    pan = parsed['pan']
    
    # Send to gateway immediately
    auth_result = gateway.authorize_swipe(track_data)
    
    # Store only PAN (which will be encrypted separately)
    db.save("INSERT INTO payments (encrypted_pan, auth_code) VALUES (?, ?)",
            encrypt_pan(pan), auth_result.auth_code)  # COMPLIANT
```

```javascript
// JavaScript - Compliant: PIN never stored
async function processPINDebit(cardNumber, pin, amount) {
    // Use PIN for authorization only
    const authResult = await pinPad.authorize(cardNumber, pin, amount);
    
    // Store transaction without PIN
    await db.query(
        'INSERT INTO transactions (card_token, amount, auth_code) VALUES (?, ?, ?)',
        [authResult.token, amount, authResult.authCode]
    );  // COMPLIANT - no PIN stored
    
    return authResult;
}

// JavaScript - Compliant: No CVV in logs
function validateCard(cardData) {
    // Validate without logging CVV
    const isValid = cardData.cvv && cardData.cvv.length === 3;
    console.log('Card validation result:', isValid);  // COMPLIANT
    return isValid;
}
```

```java
// Java - Compliant: CVC used but not persisted
public class PaymentService {
    public Transaction processPayment(PaymentRequest request) {
        // Use CVC for authorization only (in memory)
        AuthorizationResult authResult = gateway.authorize(
            request.getCardNumber(),
            request.getCvc(),  // Used here but not stored
            request.getExpiry(),
            request.getAmount()
        );
        
        // Store transaction without CVC
        Transaction txn = new Transaction();
        txn.setCardToken(authResult.getToken());
        txn.setAuthCode(authResult.getAuthCode());
        txn.setAmount(request.getAmount());
        txn.setLastFour(request.getCardNumber().substring(
            request.getCardNumber().length() - 4
        ));
        
        transactionRepository.save(txn);  // COMPLIANT - no SAD
        
        return txn;
    }
}
```

#### Remediation Steps
1. **Immediate**: Remove all SAD from storage (database, files, logs)
2. **Audit code**: Search for cvv, cvc, pin, track, magnetic stripe references
3. **Tokenization**: Replace stored PANs with tokens from payment gateway
4. **Gateway integration**: Send SAD directly to payment gateway without local storage
5. **Secure disposal**: Overwrite SAD in memory after authorization
6. **Code review**: Implement mandatory review for any payment processing code

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-a1.1-cvv-storage
    patterns:
      - pattern-either:
          - pattern: $DB.save(..., $CVV, ...)
          - pattern: $DB.insert(..., cvv=$CVV, ...)
          - pattern: $DB.update(..., cvv=$CVV, ...)
      - metavariable-regex:
          metavariable: $CVV
          regex: (cvv|cvc|cav|cid)
    message: |
      CRITICAL: CVV/CVC storage detected. PCI SSS A1.1 strictly prohibits
      storage of card verification codes after authorization.
    severity: ERROR
    languages: [python, javascript, java, go]
    metadata:
      category: security
      cwe: "CWE-311: Missing Encryption of Sensitive Data"
      pci-dss: "3.2"
      framework: PCI-SSS
      requirement: "A1.1"
```

---

## A2. Primary Account Number Protection

### Rule: PCI-SSS-A2.1 - PAN Encryption at Rest

**Severity:** Critical  
**PCI SSS Reference:** Module A, Requirement A2.1

#### Description
Primary Account Numbers (PAN) must be rendered unreadable wherever stored. Acceptable methods include:
- Strong cryptography (AES-256)
- Truncation (only first 6 and last 4 digits visible)
- Hashing (one-way, with strong salt)
- Tokenization (preferred)

#### Rationale
Stored PANs are the primary target of data breaches. Rendering them unreadable protects cardholder data even if storage is compromised.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Database operations + Regex
- **Looks for:**
  - PAN-like patterns (13-19 digit numbers) in database writes
  - Unencrypted storage of card number fields
  - File writes containing PAN patterns

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: Plaintext PAN storage
def store_payment_method(customer_id, card_number):
    db.execute(
        "INSERT INTO payment_methods (customer_id, card_number) VALUES (?, ?)",
        (customer_id, card_number)  # VIOLATION - plaintext PAN
    )

# Python - VIOLATION: PAN in log file
def log_transaction(transaction):
    with open('transactions.log', 'a') as f:
        # VIOLATION - PAN written to log file
        f.write(f"{transaction.timestamp},{transaction.card_number},{transaction.amount}\n")
```

```javascript
// JavaScript - VIOLATION: Unencrypted PAN in MongoDB
async function savePaymentMethod(customerId, cardNumber) {
    // VIOLATION - plaintext storage
    await db.collection('payment_methods').insertOne({
        customerId: customerId,
        cardNumber: cardNumber,  // VIOLATION
        createdAt: new Date()
    });
}

// JavaScript - VIOLATION: PAN in local storage
function rememberCard(cardNumber) {
    // VIOLATION - plaintext in browser storage
    localStorage.setItem('savedCard', cardNumber);
}
```

```java
// Java - VIOLATION: Plaintext PAN in entity
@Entity
public class PaymentMethod {
    @Id
    private Long id;
    
    private String customerId;
    
    // VIOLATION - no encryption specified
    private String cardNumber;
    
    // Getters and setters
}
```

##### Compliant Code

```python
# Python - Compliant: Encrypted PAN storage
from cryptography.fernet import Fernet
import os

def get_encryption_key():
    # Retrieve from secure key management service
    return os.environ['ENCRYPTION_KEY'].encode()

def store_payment_method(customer_id, card_number):
    # Encrypt PAN before storage
    fernet = Fernet(get_encryption_key())
    encrypted_pan = fernet.encrypt(card_number.encode())
    
    db.execute(
        "INSERT INTO payment_methods (customer_id, encrypted_pan) VALUES (?, ?)",
        (customer_id, encrypted_pan)  # COMPLIANT - encrypted
    )

# Python - Compliant: Only last 4 digits in logs
def log_transaction(transaction):
    last_four = transaction.card_number[-4:]
    with open('transactions.log', 'a') as f:
        # COMPLIANT - only last 4 digits
        f.write(f"{transaction.timestamp},****{last_four},{transaction.amount}\n")
```

```javascript
// JavaScript - Compliant: Tokenized PAN storage
async function savePaymentMethod(customerId, cardNumber) {
    // Tokenize through payment gateway
    const tokenResult = await paymentGateway.tokenize(cardNumber);
    
    // Store token, not PAN
    await db.collection('payment_methods').insertOne({
        customerId: customerId,
        cardToken: tokenResult.token,  // COMPLIANT - tokenized
        lastFour: cardNumber.slice(-4),
        cardBrand: tokenResult.brand,
        createdAt: new Date()
    });
}

// JavaScript - Compliant: Never store in browser
function rememberCard(cardNumber) {
    // Get token from server instead of storing PAN
    fetch('/api/tokenize', {
        method: 'POST',
        body: JSON.stringify({ cardNumber })
    })
    .then(response => response.json())
    .then(data => {
        // Store token, not PAN
        localStorage.setItem('savedCardToken', data.token);  // COMPLIANT
    });
}
```

```java
// Java - Compliant: Encrypted PAN with JPA converter
@Entity
public class PaymentMethod {
    @Id
    private Long id;
    
    private String customerId;
    
    // COMPLIANT - encrypted via converter
    @Convert(converter = CardNumberEncryptionConverter.class)
    private String cardNumber;
    
    // Last 4 digits stored separately for display
    private String lastFour;
}

// Custom JPA converter for automatic encryption
@Converter
public class CardNumberEncryptionConverter 
        implements AttributeConverter<String, String> {
    
    @Override
    public String convertToDatabaseColumn(String plaintext) {
        if (plaintext == null) return null;
        try {
            return encryptionService.encrypt(plaintext);  // COMPLIANT
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
    
    @Override
    public String convertToEntityAttribute(String encrypted) {
        if (encrypted == null) return null;
        try {
            return encryptionService.decrypt(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
```

#### Remediation Steps
1. **Inventory**: Identify all locations where PAN is stored
2. **Encryption implementation**:
   - Use AES-256 minimum
   - Implement key management (AWS KMS, Azure Key Vault, etc.)
   - Use database-level encryption or application-level encryption
3. **Alternative**: Implement tokenization with payment gateway
4. **Migrate data**: Encrypt existing plaintext PANs
5. **Verify**: Scan database for plaintext PAN patterns
6. **Monitor**: Alert on any plaintext PAN detection

---

### Rule: PCI-SSS-A2.2 - PAN Masking in Display

**Severity:** High  
**PCI SSS Reference:** Module A, Requirement A2.2

#### Description
When displaying PAN, only show the first 6 and last 4 digits. The middle digits must be masked. This applies to:
- User interfaces
- Printed receipts
- Email confirmations
- Support screens

#### Rationale
Even authorized users should have minimal exposure to full PANs. Masking reduces risk of shoulder surfing, social engineering, and insider threats.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** String operations + UI rendering
- **Looks for:**
  - PAN variables used in display contexts without masking
  - String concatenation that might expose full PAN
  - Template rendering with card_number fields

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: Displaying full PAN
def show_payment_method(payment_method):
    # VIOLATION - full PAN displayed
    print(f"Card on file: {payment_method.card_number}")
    return render_template('payment.html', 
                         card=payment_method.card_number)  # VIOLATION

# Python - VIOLATION: Email with full PAN
def send_receipt(email, card_number, amount):
    message = f"""
    Thank you for your purchase!
    Card used: {card_number}
    Amount: ${amount}
    """  # VIOLATION
    send_email(email, message)
```

```javascript
// JavaScript - VIOLATION: Displaying full PAN in UI
function displaySavedCard(cardNumber) {
    // VIOLATION - shows full number
    document.getElementById('card').textContent = cardNumber;
}

// React - VIOLATION: Full PAN in component
function PaymentMethod({ cardNumber }) {
    return (
        <div>
            <span>Card: {cardNumber}</span>  {/* VIOLATION */}
        </div>
    );
}
```

```java
// Java - VIOLATION: Full PAN in receipt
public String generateReceipt(Transaction txn) {
    return String.format(
        "Card: %s\nAmount: $%.2f",
        txn.getCardNumber(),  // VIOLATION
        txn.getAmount()
    );
}
```

##### Compliant Code

```python
# Python - Compliant: Masked PAN display
def mask_pan(pan):
    """Mask PAN showing only first 6 and last 4 digits"""
    if len(pan) < 13:
        return "****"
    return f"{pan[:6]}{'*' * (len(pan) - 10)}{pan[-4:]}"

def show_payment_method(payment_method):
    masked = mask_pan(payment_method.card_number)
    print(f"Card on file: {masked}")  # COMPLIANT
    return render_template('payment.html', card=masked)

# Python - Compliant: Masked PAN in email
def send_receipt(email, card_number, amount):
    masked_pan = mask_pan(card_number)
    message = f"""
    Thank you for your purchase!
    Card used: {masked_pan}
    Amount: ${amount}
    """  # COMPLIANT
    send_email(email, message)
```

```javascript
// JavaScript - Compliant: Masked display function
function maskPAN(cardNumber) {
    if (cardNumber.length < 13) return '****';
    const first6 = cardNumber.slice(0, 6);
    const last4 = cardNumber.slice(-4);
    const masked = '*'.repeat(cardNumber.length - 10);
    return `${first6}${masked}${last4}`;
}

function displaySavedCard(cardNumber) {
    const masked = maskPAN(cardNumber);
    document.getElementById('card').textContent = masked;  // COMPLIANT
}

// React - Compliant: Masked PAN component
function PaymentMethod({ cardNumber }) {
    const masked = maskPAN(cardNumber);
    return (
        <div>
            <span>Card: {masked}</span>  {/* COMPLIANT */}
        </div>
    );
}
```

```java
// Java - Compliant: Masked receipt
public class PANMasker {
    public static String mask(String pan) {
        if (pan == null || pan.length() < 13) {
            return "****";
        }
        String first6 = pan.substring(0, 6);
        String last4 = pan.substring(pan.length() - 4);
        String masked = "*".repeat(pan.length() - 10);
        return first6 + masked + last4;
    }
}

public String generateReceipt(Transaction txn) {
    String maskedPAN = PANMasker.mask(txn.getCardNumber());
    return String.format(
        "Card: %s\nAmount: $%.2f",
        maskedPAN,  // COMPLIANT
        txn.getAmount()
    );
}
```

#### Remediation Steps
1. **Create masking utility**: Centralized function for PAN masking
2. **Update all display code**: Search for card_number in templates/UI
3. **Database views**: Create views that return masked PANs by default
4. **Testing**: Verify no full PANs appear in any user-facing output
5. **Exception handling**: Document any legitimate need for full PAN display
6. **Audit logging**: Log when full PAN is accessed (for authorized use only)

---

## A3. Cardholder Data Encryption

### Rule: PCI-SSS-A3.1 - Encryption in Transit (TLS 1.2+)

**Severity:** Critical  
**PCI SSS Reference:** Module A, Requirement A3.1

#### Description
All transmission of cardholder data must use strong cryptography. TLS 1.2 or higher is required. This applies to:
- Payment gateway communications
- Internal system communications
- API calls containing CHD
- File transfers with CHD

#### Rationale
Unencrypted transmission exposes cardholder data to interception attacks. TLS 1.2+ provides strong encryption and authentication.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** HTTP client configuration
- **Looks for:**
  - HTTP (not HTTPS) for payment operations
  - TLS version configuration less than 1.2
  - Disabled certificate validation
  - Weak cipher suites

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: HTTP for payment data
import requests

def submit_payment(card_data):
    # VIOLATION - HTTP not HTTPS
    response = requests.post(
        'http://payment-gateway.example.com/charge',
        json=card_data
    )
    return response.json()

# Python - VIOLATION: Disabled SSL verification
def send_to_gateway(payment):
    # VIOLATION - SSL verification disabled
    response = requests.post(
        'https://gateway.example.com/api',
        json=payment,
        verify=False  # VIOLATION
    )
    return response
```

```javascript
// Node.js - VIOLATION: Allowing old TLS versions
const https = require('https');

const options = {
    hostname: 'payment-gateway.example.com',
    port: 443,
    method: 'POST',
    // VIOLATION - allows TLS 1.0/1.1
    secureProtocol: 'TLS_method'
};

https.request(options, callback);

// Node.js - VIOLATION: HTTP for payment
const http = require('http');  // VIOLATION - should be https

http.post('http://gateway.example.com/charge', paymentData);
```

```java
// Java - VIOLATION: Accepting all certificates
import javax.net.ssl.*;

public class PaymentClient {
    public void submitPayment(PaymentData data) {
        // VIOLATION - trust all certificates
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new SecureRandom());  // VIOLATION
    }
}
```

##### Compliant Code

```python
# Python - Compliant: HTTPS with TLS 1.2+
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

class TLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2  # COMPLIANT
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def submit_payment(card_data):
    session = requests.Session()
    session.mount('https://', TLS12Adapter())
    
    # COMPLIANT - HTTPS with TLS 1.2+
    response = session.post(
        'https://payment-gateway.example.com/charge',
        json=card_data,
        verify=True  # COMPLIANT - certificate validation enabled
    )
    return response.json()
```

```javascript
// Node.js - Compliant: TLS 1.2+ enforcement
const https = require('https');
const tls = require('tls');

const options = {
    hostname: 'payment-gateway.example.com',
    port: 443,
    method: 'POST',
    minVersion: 'TLSv1.2',  // COMPLIANT - TLS 1.2 minimum
    rejectUnauthorized: true  // COMPLIANT - verify certificates
};

https.request(options, callback);

// Using axios with TLS 1.2+
const axios = require('axios');
const https = require('https');

const httpsAgent = new https.Agent({
    minVersion: 'TLSv1.2',  // COMPLIANT
    rejectUnauthorized: true
});

axios.post('https://gateway.example.com/charge', paymentData, {
    httpsAgent: httpsAgent  // COMPLIANT
});
```

```java
// Java - Compliant: TLS 1.2+ with proper certificate validation
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class SecurePaymentClient {
    private static final String[] PROTOCOLS = {"TLSv1.2", "TLSv1.3"};
    
    public void submitPayment(PaymentData data) throws Exception {
        // COMPLIANT - TLS 1.2+ with proper validation
        SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
        sslContext.init(null, null, null);
        
        SSLSocketFactory factory = sslContext.getSocketFactory();
        
        HttpsURLConnection conn = (HttpsURLConnection) 
            new URL("https://gateway.example.com/charge").openConnection();
        
        conn.setSSLSocketFactory(factory);
        
        // Set enabled protocols
        SSLParameters sslParams = new SSLParameters();
        sslParams.setProtocols(PROTOCOLS);  // COMPLIANT
        conn.setSSLParameters(sslParams);
        
        // Certificate validation enabled by default - COMPLIANT
    }
}
```

#### Remediation Steps
1. **Audit all HTTP clients**: Search codebase for payment-related network calls
2. **Enforce HTTPS**: Block HTTP for any cardholder data transmission
3. **Configure TLS minimum**: Set TLS 1.2 as minimum in all HTTP clients
4. **Enable certificate validation**: Never disable SSL/TLS verification
5. **Test configuration**: Use SSL Labs or similar tools to verify
6. **Monitor**: Alert on any HTTP transmission of payment data

---

## A4. Cryptographic Key Management

### Rule: PCI-SSS-A4.1 - Secure Key Storage for CHD Encryption

**Severity:** Critical  
**PCI SSS Reference:** Module A, Requirement A4.1

#### Description
Cryptographic keys used to encrypt cardholder data must be stored securely and separately from the encrypted data. Keys must:
- Be stored in a secure key management system (KMS)
- Never be stored in the same location as encrypted data
- Be protected with equivalent or stronger encryption
- Have restricted access controls

#### Rationale
If encryption keys are compromised along with encrypted data, the encryption provides no protection.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Configuration analysis + Code patterns
- **Looks for:**
  - Keys in configuration files
  - Keys in same database as encrypted data
  - Keys in environment variables (for production)
  - Hardcoded keys

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: Key in same database as data
def encrypt_and_store_pan(pan):
    key = db.query("SELECT encryption_key FROM keys WHERE active = true")[0]
    encrypted = encrypt(pan, key)
    # VIOLATION - key and data in same database
    db.execute("INSERT INTO cards (encrypted_pan) VALUES (?)", encrypted)

# Python - VIOLATION: Key in config file
# config.py
ENCRYPTION_KEY = "abc123def456..."  # VIOLATION - hardcoded key

def get_key():
    return ENCRYPTION_KEY  # VIOLATION
```

```javascript
// JavaScript - VIOLATION: Key in environment variable (production)
// .env file in production - VIOLATION
ENCRYPTION_KEY=a1b2c3d4e5f6...

// app.js
const encryptionKey = process.env.ENCRYPTION_KEY;  // VIOLATION for production

function encryptCardData(cardNumber) {
    return encrypt(cardNumber, encryptionKey);
}
```

```java
// Java - VIOLATION: Key in properties file
// application.properties
encryption.key=mySecretKey123  // VIOLATION

@Component
public class EncryptionService {
    @Value("${encryption.key}")
    private String encryptionKey;  // VIOLATION
    
    public String encryptPAN(String pan) {
        return encrypt(pan, encryptionKey);
    }
}
```

##### Compliant Code

```python
# Python - Compliant: Key from AWS KMS
import boto3
import base64

def get_encryption_key():
    """Retrieve data key from AWS KMS"""
    kms_client = boto3.client('kms')
    
    response = kms_client.generate_data_key(
        KeyId='arn:aws:kms:region:account:key/key-id',
        KeySpec='AES_256'
    )
    
    # COMPLIANT - key from KMS, not stored with data
    return response['Plaintext']

def encrypt_and_store_pan(pan):
    data_key = get_encryption_key()
    encrypted_pan = encrypt(pan, data_key)
    
    # Store only encrypted data, key remains in KMS
    db.execute("INSERT INTO cards (encrypted_pan) VALUES (?)", encrypted_pan)
    
    # Securely wipe key from memory
    del data_key  # COMPLIANT

# Python - Compliant: Azure Key Vault
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def get_encryption_key():
    """Retrieve key from Azure Key Vault"""
    credential = DefaultAzureCredential()
    client = SecretClient(
        vault_url="https://myvault.vault.azure.net/",
        credential=credential
    )
    
    # COMPLIANT - key from Key Vault
    secret = client.get_secret("card-encryption-key")
    return secret.value
```

```javascript
// Node.js - Compliant: AWS KMS integration
const AWS = require('aws-sdk');
const kms = new AWS.KMS();

async function getEncryptionKey() {
    const params = {
        KeyId: 'arn:aws:kms:region:account:key/key-id',
        KeySpec: 'AES_256'
    };
    
    // COMPLIANT - key from KMS
    const result = await kms.generateDataKey(params).promise();
    return result.Plaintext;
}

async function encryptAndStorePAN(cardNumber) {
    const dataKey = await getEncryptionKey();
    const encryptedPAN = encrypt(cardNumber, dataKey);
    
    // Store encrypted data only
    await db.query(
        'INSERT INTO cards (encrypted_pan) VALUES (?)',
        [encryptedPAN]
    );  // COMPLIANT - key separate from data
}

// Node.js - Compliant: HashiCorp Vault
const vault = require('node-vault')({
    endpoint: 'https://vault.example.com:8200',
    token: process.env.VAULT_TOKEN
});

async function getEncryptionKey() {
    // COMPLIANT - key from Vault
    const result = await vault.read('secret/data/card-encryption-key');
    return result.data.data.key;
}
```

```java
// Java - Compliant: AWS KMS with SDK
import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.AWSKMSClientBuilder;
import com.amazonaws.services.kms.model.*;

@Service
public class SecureEncryptionService {
    private final AWSKMS kmsClient;
    private final String keyId;
    
    public SecureEncryptionService() {
        this.kmsClient = AWSKMSClientBuilder.defaultClient();
        this.keyId = "arn:aws:kms:region:account:key/key-id";
    }
    
    public byte[] getDataKey() {
        GenerateDataKeyRequest request = new GenerateDataKeyRequest()
            .withKeyId(keyId)
            .withKeySpec(DataKeySpec.AES_256);
        
        GenerateDataKeyResult result = kmsClient.generateDataKey(request);
        // COMPLIANT - key from KMS
        return result.getPlaintext().array();
    }
    
    public String encryptPAN(String pan) {
        byte[] dataKey = getDataKey();
        String encrypted = encrypt(pan, dataKey);
        
        // Clear key from memory
        Arrays.fill(dataKey, (byte) 0);  // COMPLIANT
        
        return encrypted;
    }
}
```

#### Remediation Steps
1. **Migrate to KMS**: Move all encryption keys to secure key management service
   - AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault
2. **Remove hardcoded keys**: Search codebase for key material
3. **Separate storage**: Ensure keys never stored with encrypted data
4. **Access controls**: Restrict KMS access to encryption service only
5. **Key rotation**: Implement automated key rotation schedule
6. **Audit**: Log all key access and usage

---

## A5. Data Retention and Disposal

### Rule: PCI-SSS-A5.1 - Secure Deletion of Cardholder Data

**Severity:** High  
**PCI SSS Reference:** Module A, Requirement A5.1

#### Description
Cardholder data that is no longer needed for business or legal reasons must be securely deleted. This includes:
- Database records
- Log files
- Backup media
- Memory/cache
- Temporary files

#### Rationale
Retaining unnecessary cardholder data increases risk exposure. Secure deletion ensures data cannot be recovered.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Data lifecycle analysis
- **Looks for:**
  - DELETE operations without secure overwrite
  - Missing data retention policies in code
  - Temporary file creation without cleanup
  - Memory not cleared after processing

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: Simple deletion (recoverable)
def delete_payment_method(payment_id):
    # VIOLATION - data may be recoverable from disk
    db.execute("DELETE FROM payment_methods WHERE id = ?", payment_id)

# Python - VIOLATION: PAN in temp file without cleanup
def process_batch_payments(payment_file):
    with open(payment_file, 'r') as f:
        payments = json.load(f)
    
    for payment in payments:
        process_payment(payment['card_number'])
    
    # VIOLATION - temp file not securely deleted
    # File may contain PANs and remains on disk

# Python - VIOLATION: Memory not cleared
card_number = input("Enter card number: ")
process_payment(card_number)
# VIOLATION - card_number remains in memory
```

```javascript
// JavaScript - VIOLATION: Browser storage not cleared
function processPayment(cardData) {
    // Store temporarily
    sessionStorage.setItem('tempCard', JSON.stringify(cardData));
    
    submitPayment(cardData);
    
    // VIOLATION - not removed after use
}

// Node.js - VIOLATION: Buffer not cleared
function encryptCard(cardNumber) {
    const buffer = Buffer.from(cardNumber, 'utf8');
    const encrypted = encrypt(buffer);
    
    // VIOLATION - sensitive data remains in buffer
    return encrypted;
}
```

```java
// Java - VIOLATION: Soft delete (data remains)
@Entity
public class PaymentMethod {
    @Id
    private Long id;
    
    private String encryptedPAN;
    
    private boolean deleted = false;  // VIOLATION - soft delete
}

public void deletePaymentMethod(Long id) {
    PaymentMethod pm = repository.findById(id);
    pm.setDeleted(true);  // VIOLATION - data still in database
    repository.save(pm);
}
```

##### Compliant Code

```python
# Python - Compliant: Secure overwrite before deletion
import os
import secrets

def secure_delete_payment_method(payment_id):
    # First overwrite with random data
    random_data = secrets.token_hex(16)
    db.execute(
        "UPDATE payment_methods SET encrypted_pan = ? WHERE id = ?",
        (random_data, payment_id)
    )
    
    # Then delete the record
    db.execute("DELETE FROM payment_methods WHERE id = ?", payment_id)
    # COMPLIANT - data overwritten before deletion

# Python - Compliant: Secure temp file handling
import tempfile
import os

def process_batch_payments(payment_file):
    # Use secure temporary file
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
        temp_path = temp.name
        with open(payment_file, 'r') as f:
            payments = json.load(f)
        
        for payment in payments:
            process_payment(payment['card_number'])
    
    # Securely delete temporary file
    if os.path.exists(temp_path):
        # Overwrite before deletion
        with open(temp_path, 'wb') as f:
            f.write(os.urandom(os.path.getsize(temp_path)))
        os.remove(temp_path)  # COMPLIANT

# Python - Compliant: Clear sensitive data from memory
def process_payment_secure(card_number):
    try:
        result = process_payment(card_number)
        return result
    finally:
        # Overwrite string in memory (Python limitation: strings are immutable)
        # Use bytearray for sensitive data instead
        card_number = None
        import gc
        gc.collect()  # COMPLIANT - attempt to clear memory
```

```javascript
// JavaScript - Compliant: Clear browser storage
function processPayment(cardData) {
    // Use only for duration of request
    sessionStorage.setItem('tempCard', JSON.stringify(cardData));
    
    try {
        await submitPayment(cardData);
    } finally {
        // COMPLIANT - remove after use
        sessionStorage.removeItem('tempCard');
    }
}

// Node.js - Compliant: Explicit buffer clearing
function encryptCard(cardNumber) {
    const buffer = Buffer.from(cardNumber, 'utf8');
    
    try {
        const encrypted = encrypt(buffer);
        return encrypted;
    } finally {
        // COMPLIANT - zero out buffer
        buffer.fill(0);
    }
}

// Node.js - Compliant: Secure file deletion
const fs = require('fs').promises;
const crypto = require('crypto');

async function secureDeleteFile(filepath) {
    const stats = await fs.stat(filepath);
    const size = stats.size;
    
    // Overwrite with random data
    const randomData = crypto.randomBytes(size);
    await fs.writeFile(filepath, randomData);
    
    // Delete file
    await fs.unlink(filepath);  // COMPLIANT
}
```

```java
// Java - Compliant: Hard delete with overwrite
@Service
public class SecurePaymentService {
    
    public void deletePaymentMethod(Long id) {
        PaymentMethod pm = repository.findById(id)
            .orElseThrow(() -> new NotFoundException());
        
        // Overwrite sensitive data first
        pm.setEncryptedPAN(generateRandomString(32));
        repository.save(pm);
        
        // Hard delete from database
        repository.deleteById(id);  // COMPLIANT
        
        // Also purge from audit logs if necessary
        auditService.purgePaymentMethodRecords(id);
    }
    
    private String generateRandomString(int length) {
        byte[] random = new byte[length];
        new SecureRandom().nextBytes(random);
        return Base64.getEncoder().encodeToString(random);
    }
}

// Java - Compliant: Clear sensitive arrays
public class SecureCardProcessor {
    public void processCard(char[] cardNumber) {
        try {
            String pan = new String(cardNumber);
            processPayment(pan);
        } finally {
            // COMPLIANT - zero out array
            Arrays.fill(cardNumber, '0');
        }
    }
}
```

#### Remediation Steps
1. **Implement data retention policy**: Define how long to keep CHD
2. **Automated purging**: Schedule jobs to delete old CHD
3. **Secure overwrite**: Overwrite data before deletion
4. **Memory clearing**: Zero out sensitive data after use
5. **Backup rotation**: Include CHD in backup retention policies
6. **Audit trail**: Log all CHD deletion operations

---

## A6. Account Data Display and Logging

### Rule: PCI-SSS-A6.1 - No PAN in Application Logs

**Severity:** Critical  
**PCI SSS Reference:** Module A, Requirement A6.1

#### Description
Primary Account Numbers must never appear in application logs, system logs, error messages, or debug output. This includes:
- Application log files
- Web server logs
- Database query logs
- Error tracking systems
- Debug output

#### Rationale
Logs are often stored insecurely, retained longer than necessary, and accessible to many personnel. PAN in logs creates significant exposure.

#### Detection Pattern
- **Languages:** All
- **Pattern Type:** Logging statements + PAN patterns
- **Looks for:**
  - Logging statements with card/pan variables
  - PAN-like patterns in log output
  - Exception messages containing PAN
  - Request/response logging with CHD

#### Examples

##### Non-Compliant Code

```python
# Python - VIOLATION: PAN in logs
import logging

def process_payment(card_number, amount):
    logging.info(f"Processing payment for card {card_number}")  # VIOLATION
    
    try:
        result = gateway.charge(card_number, amount)
        logging.debug(f"Gateway response: {result}")  # VIOLATION - may contain PAN
    except Exception as e:
        logging.error(f"Payment failed for {card_number}: {e}")  # VIOLATION

# Python - VIOLATION: PAN in error tracking
import sentry_sdk

def charge_card(payment_data):
    try:
        gateway.charge(payment_data)
    except Exception as e:
        # VIOLATION - payment_data may contain PAN
        sentry_sdk.capture_exception(e, extra={'payment': payment_data})
```

```javascript
// JavaScript - VIOLATION: PAN in console logs
function processPayment(cardNumber, cvv, amount) {
    console.log('Payment request:', { cardNumber, cvv, amount });  // VIOLATION
    
    try {
        return gateway.charge(cardNumber, cvv, amount);
    } catch (error) {
        console.error('Payment error:', error, cardNumber);  // VIOLATION
        throw error;
    }
}

// Express.js - VIOLATION: Request logging with PAN
app.use((req, res, next) => {
    // VIOLATION - logs entire request body
    logger.info('Request:', req.body);
    next();
});
```

```java
// Java - VIOLATION: PAN in log4j
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PaymentService {
    private static final Logger logger = LoggerFactory.getLogger(PaymentService.class);
    
    public void processPayment(PaymentRequest request) {
        // VIOLATION - request contains PAN
        logger.info("Processing payment: {}", request);
        
        try {
            gateway.charge(request);
        } catch (Exception e) {
            // VIOLATION - exception message may contain PAN
            logger.error("Payment failed for card " + request.getCardNumber(), e);
        }
    }
}
```

##### Compliant Code

```python
# Python - Compliant: Masked PAN in logs
import logging
import re

def mask_pan(text):
    """Mask PAN patterns in text"""
    # Match 13-19 digit card numbers
    pattern = r'\b\d{13,19}\b'
    return re.sub(pattern, '****-****-****-****', text)

def safe_log(message):
    """Log with automatic PAN masking"""
    masked = mask_pan(message)
    logging.info(masked)

def process_payment(card_number, amount):
    # Only log last 4 digits
    last_four = card_number[-4:]
    logging.info(f"Processing payment for card ending {last_four}")  # COMPLIANT
    
    try:
        result = gateway.charge(card_number, amount)
        # Don't log gateway response that may contain PAN
        logging.info(f"Payment successful, auth code: {result.auth_code}")  # COMPLIANT
    except Exception as e:
        # Log error without PAN
        logging.error(f"Payment failed for card ending {last_four}: {type(e).__name__}")  # COMPLIANT

# Python - Compliant: Scrub sensitive data from error tracking
import sentry_sdk

def before_send(event, hint):
    """Scrub PAN before sending to Sentry"""
    if 'extra' in event:
        for key, value in event['extra'].items():
            if isinstance(value, str):
                event['extra'][key] = mask_pan(value)  # COMPLIANT
    return event

sentry_sdk.init(before_send=before_send)
```

```javascript
// JavaScript - Compliant: PAN scrubbing in logs
const PANPattern = /\b\d{13,19}\b/g;

function maskPAN(text) {
    if (typeof text === 'string') {
        return text.replace(PANPattern, '****-****-****-****');
    }
    return text;
}

function safeLog(message, data) {
    // Mask any PAN in data
    const safeData = JSON.parse(JSON.stringify(data));
    if (safeData.cardNumber) {
        safeData.cardNumber = safeData.cardNumber.slice(-4);
    }
    console.log(message, safeData);  // COMPLIANT
}

function processPayment(cardNumber, cvv, amount) {
    safeLog('Payment request', { 
        cardLast4: cardNumber.slice(-4),  // COMPLIANT
        amount 
    });
    
    try {
        return gateway.charge(cardNumber, cvv, amount);
    } catch (error) {
        const safeError = {
            message: error.message,
            code: error.code,
            cardLast4: cardNumber.slice(-4)
        };
        console.error('Payment error:', safeError);  // COMPLIANT
        throw error;
    }
}

// Express.js - Compliant: Request sanitization
const sanitizeBody = (body) => {
    const safe = { ...body };
    if (safe.cardNumber) {
        safe.cardNumber = safe.cardNumber.slice(-4);
    }
    if (safe.cvv) {
        safe.cvv = '***';
    }
    return safe;
};

app.use((req, res, next) => {
    const safeBody = sanitizeBody(req.body);
    logger.info('Request:', safeBody);  // COMPLIANT
    next();
});
```

```java
// Java - Compliant: Custom log filter
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.regex.Pattern;

public class SecureLogger {
    private static final Pattern PAN_PATTERN = 
        Pattern.compile("\\b\\d{13,19}\\b");
    
    public static String maskPAN(String message) {
        if (message == null) return null;
        return PAN_PATTERN.matcher(message)
            .replaceAll("****-****-****-****");
    }
}

public class PaymentService {
    private static final Logger logger = 
        LoggerFactory.getLogger(PaymentService.class);
    
    public void processPayment(PaymentRequest request) {
        // Log only last 4 digits
        String lastFour = request.getCardNumber()
            .substring(request.getCardNumber().length() - 4);
        logger.info("Processing payment for card ending {}", lastFour);  // COMPLIANT
        
        try {
            gateway.charge(request);
            logger.info("Payment successful");  // COMPLIANT
        } catch (Exception e) {
            // Log exception without PAN
            String safeMessage = SecureLogger.maskPAN(e.getMessage());
            logger.error("Payment failed: {}", safeMessage, e);  // COMPLIANT
        }
    }
}

// Java - Compliant: Log4j2 pattern with masking
// log4j2.xml
<Configuration>
    <Appenders>
        <RollingFile name="FileAppender" fileName="app.log">
            <PatternLayout>
                <!-- Custom pattern that masks PAN -->
                <Pattern>%d{yyyy-MM-dd HH:mm:ss} %-5p %c{1} - %replace{%m}{'\b\d{13,19}\b'}{'****-****-****-****'}%n</Pattern>
            </PatternLayout>
        </RollingFile>
    </Appenders>
</Configuration>
```

#### Remediation Steps
1. **Audit all logging**: Search codebase for logging statements near payment code
2. **Implement log scrubbing**: Create utility to mask PAN in all log output
3. **Configure log filters**: Use logging framework filters to remove PAN
4. **Review log aggregation**: Ensure PAN masking in Splunk, ELK, etc.
5. **Test logging**: Verify no PAN in log files during QA testing
6. **Monitor logs**: Alert on PAN patterns detected in production logs

#### Automated Check

**Semgrep Rule:**
```yaml
rules:
  - id: pci-sss-a6.1-pan-in-logs
    patterns:
      - pattern-either:
          - pattern: logging.$LEVEL(..., $CARD, ...)
          - pattern: console.log(..., $CARD, ...)
          - pattern: logger.$LEVEL(..., $CARD, ...)
          - pattern: System.out.println(... + $CARD + ...)
      - metavariable-regex:
          metavariable: $CARD
          regex: (card|pan|account.?number)
    message: |
      Potential PAN in log statement detected. PCI SSS A6.1 prohibits
      logging of Primary Account Numbers. Use masking or log only last 4 digits.
    severity: ERROR
    languages: [python, javascript, java, go]
    metadata:
      category: security
      cwe: "CWE-532: Information Exposure Through Log Files"
      framework: PCI-SSS
      requirement: "A6.1"
```

---

## Summary and Compliance Checklist

### Module A Requirements Coverage

**Account Data Protection:**
- [x] A1.1: No SAD storage after authorization
- [x] A2.1: PAN encryption at rest
- [x] A2.2: PAN masking in display
- [x] A3.1: Encryption in transit (TLS 1.2+)
- [x] A4.1: Secure key storage
- [x] A5.1: Secure data deletion
- [x] A6.1: No PAN in logs

### Quick Reference: Data Classifications

**Never Store (Prohibited):**
- Full magnetic stripe data
- CAV2/CVC2/CVV2/CID
- PIN/PIN Block

**Store Only If Encrypted:**
- Primary Account Number (PAN)
- Cardholder Name
- Expiration Date
- Service Code

**Can Store Unencrypted:**
- Last 4 digits of PAN
- Card brand (Visa, Mastercard, etc.)
- Transaction authorization code
- Tokenized PAN reference

### Implementation Priority

**Phase 1 - Critical (Week 1):**
1. Eliminate all SAD storage
2. Implement PAN encryption at rest
3. Enforce TLS 1.2+ for all transmissions
4. Remove PAN from logs

**Phase 2 - High (Week 2-3):**
5. Implement PAN masking in UI
6. Migrate keys to KMS
7. Implement secure deletion
8. Add automated detection rules

**Phase 3 - Ongoing:**
9. Regular security audits
10. Continuous monitoring
11. Developer training
12. Penetration testing

### Testing Checklist

**Before Deployment:**
- [ ] No SAD found in database dumps
- [ ] All PAN encrypted with strong cryptography
- [ ] Keys stored in separate KMS
- [ ] TLS 1.2+ enforced for all payment traffic
- [ ] PAN masked in all UI displays
- [ ] No PAN patterns in log files
- [ ] Secure deletion implemented for old data
- [ ] All requirements covered by automated tests

### Related Documentation

- **[Core Requirements](core-requirements.md)** - Base security requirements
- **[Module B: Terminal Software](module-b-terminal.md)** - POI device requirements
- **[Module C: Web Software](module-c-web.md)** - Web application requirements
- **[PCI DSS Overview](README.md)** - Framework structure and guidance

---

**Need help?** Open an issue or discussion in the main repository.
