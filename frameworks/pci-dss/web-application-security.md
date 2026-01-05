# PCI Secure Software Standard - Module C: Web Software

**Standard Version:** v1.2.1  
**Document Version:** 1.0  
**Last Updated:** 2024-11-19  
**Module Type:** Module C - Web Software Requirements

---

## Overview

This document contains code-level compliance rules for **Module C: Web Software** of the PCI Secure Software Standard (PCI SSS). These requirements apply specifically to payment software that uses Internet technologies, protocols, and languages to initiate or support electronic payment transactions.

### About This Module

Module C establishes security requirements for web-based payment software including:
- E-commerce checkout applications
- Payment gateway integrations
- Hosted payment pages
- Payment APIs and web services
- Single-page applications (SPAs) handling payments
- Mobile web payment applications

These requirements are in addition to Core Requirements and Module A requirements, focusing on:
- Web application security vulnerabilities
- Browser security controls
- API security
- Session management
- Client-side security
- Content Security Policy

### Applicability

This module applies to software if it:
- Accepts payment card data through web interfaces
- Processes payments via web APIs
- Integrates with payment gateways over HTTP/HTTPS
- Provides hosted payment pages
- Uses JavaScript to handle payment data

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

- [C1. Input Validation and Output Encoding](#c1-input-validation-and-output-encoding)
- [C2. Authentication and Session Management](#c2-authentication-and-session-management)
- [C3. Browser Security Controls](#c3-browser-security-controls)
- [C4. API Security](#c4-api-security)
- [C5. Client-Side Security](#c5-client-side-security)
- [C6. Content Security Policy](#c6-content-security-policy)
- [C7. Payment Data Protection in Web Context](#c7-payment-data-protection-in-web-context)

---

## C1. Input Validation and Output Encoding

### Rule: PCI-SSS-C1.1 - Server-Side Input Validation

**Severity:** Critical  
**PCI SSS Reference:** Module C, Requirement C1.1

#### Description
All input from web clients must be validated on the server side, regardless of client-side validation. This includes:
- Form submissions
- Query parameters
- Request headers
- API payloads
- File uploads
- Cookie values

#### Rationale
Client-side validation can be bypassed. Server-side validation is the security control that prevents injection attacks and data integrity issues.

#### Detection Pattern
- **Languages:** Python, JavaScript, Java, PHP, Ruby
- **Pattern Type:** Request handling analysis
- **Looks for:**
  - Direct use of request parameters without validation
  - Missing validation on API endpoints
  - Client-side only validation

#### Examples

##### Non-Compliant Code

```python
# Python Flask - VIOLATION: No server-side validation
from flask import Flask, request

@app.route('/payment', methods=['POST'])
def process_payment():
    # VIOLATION - using request data without validation
    amount = request.form['amount']
    card_number = request.form['card_number']
    
    # Direct database insertion without validation
    db.execute(
        "INSERT INTO transactions (amount, card) VALUES (?, ?)",
        (amount, card_number)
    )  # VIOLATION
    
    return "Payment processed"

# Python - VIOLATION: Trusting client-side validation only
@app.route('/checkout', methods=['POST'])
def checkout():
    # Assuming client validated the data
    data = request.json
    # VIOLATION - no server-side checks
    return process_order(data)
```

```javascript
// Express.js - VIOLATION: No input validation
app.post('/api/payment', (req, res) => {
    const { amount, cardNumber, cvv } = req.body;
    
    // VIOLATION - no validation before processing
    paymentGateway.charge({
        amount: amount,
        card: cardNumber,
        cvv: cvv
    });
    
    res.json({ success: true });
});

// Express.js - VIOLATION: Weak validation
app.post('/api/charge', (req, res) => {
    // VIOLATION - only checks if field exists, not validity
    if (req.body.amount) {
        processPayment(req.body.amount);
    }
});
```

```php
// PHP - VIOLATION: Using $_POST directly
<?php
// VIOLATION - no validation
$amount = $_POST['amount'];
$card = $_POST['card_number'];

$query = "INSERT INTO payments (amount, card) VALUES ('$amount', '$card')";
mysqli_query($conn, $query);  // VIOLATION - SQL injection risk
?>
```

##### Compliant Code

```python
# Python Flask - Compliant: Comprehensive server-side validation
from flask import Flask, request, abort
import re
from decimal import Decimal, InvalidOperation

def validate_amount(amount_str):
    """Validate payment amount"""
    try:
        amount = Decimal(amount_str)
        if amount <= 0:
            raise ValueError("Amount must be positive")
        if amount > Decimal('999999.99'):
            raise ValueError("Amount exceeds maximum")
        return amount
    except (InvalidOperation, ValueError) as e:
        raise ValueError(f"Invalid amount: {e}")

def validate_card_number(card_number):
    """Validate card number format (Luhn algorithm)"""
    # Remove spaces and hyphens
    card = re.sub(r'[\s-]', '', card_number)
    
    # Check format (13-19 digits)
    if not re.match(r'^\d{13,19}$', card):
        raise ValueError("Invalid card number format")
    
    # Luhn algorithm
    def luhn_check(card_num):
        digits = [int(d) for d in card_num]
        checksum = 0
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0
    
    if not luhn_check(card):
        raise ValueError("Invalid card number")
    
    return card

@app.route('/payment', methods=['POST'])
def process_payment():
    try:
        # COMPLIANT - validate all inputs
        amount = validate_amount(request.form.get('amount', ''))
        card_number = validate_card_number(request.form.get('card_number', ''))
        
        # Additional validations
        cvv = request.form.get('cvv', '')
        if not re.match(r'^\d{3,4}$', cvv):
            raise ValueError("Invalid CVV")
        
        # Process with validated data
        result = payment_gateway.charge(
            amount=amount,
            card=card_number,
            cvv=cvv
        )
        
        return jsonify({"success": True, "transaction_id": result.id})
        
    except ValueError as e:
        abort(400, str(e))  # COMPLIANT - proper error handling
```

```javascript
// Express.js - Compliant: Input validation with library
const { body, validationResult } = require('express-validator');

app.post('/api/payment',
    // COMPLIANT - server-side validation rules
    [
        body('amount')
            .isFloat({ min: 0.01, max: 999999.99 })
            .withMessage('Invalid amount'),
        body('cardNumber')
            .matches(/^\d{13,19}$/)
            .custom(luhnCheck)
            .withMessage('Invalid card number'),
        body('cvv')
            .matches(/^\d{3,4}$/)
            .withMessage('Invalid CVV'),
        body('expiryMonth')
            .isInt({ min: 1, max: 12 })
            .withMessage('Invalid expiry month'),
        body('expiryYear')
            .isInt({ min: new Date().getFullYear() })
            .withMessage('Invalid expiry year')
    ],
    async (req, res) => {
        // Check validation results
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        // COMPLIANT - all inputs validated
        const { amount, cardNumber, cvv } = req.body;
        
        try {
            const result = await paymentGateway.charge({
                amount: amount,
                card: cardNumber,
                cvv: cvv
            });
            
            res.json({ success: true, transactionId: result.id });
        } catch (error) {
            res.status(500).json({ error: 'Payment failed' });
        }
    }
);

function luhnCheck(cardNumber) {
    // Luhn algorithm implementation
    const digits = cardNumber.split('').map(Number);
    let sum = 0;
    let isEven = false;
    
    for (let i = digits.length - 1; i >= 0; i--) {
        let digit = digits[i];
        
        if (isEven) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        
        sum += digit;
        isEven = !isEven;
    }
    
    return sum % 10 === 0;
}
```

```java
// Spring Boot - Compliant: Bean validation
import javax.validation.Valid;
import javax.validation.constraints.*;

@RestController
@RequestMapping("/api/payment")
public class PaymentController {
    
    @PostMapping
    public ResponseEntity<?> processPayment(
            @Valid @RequestBody PaymentRequest request) {
        
        // COMPLIANT - validation happens automatically via @Valid
        try {
            PaymentResult result = paymentService.charge(request);
            return ResponseEntity.ok(result);
        } catch (PaymentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}

// Payment request with validation annotations
public class PaymentRequest {
    
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", message = "Amount must be positive")
    @DecimalMax(value = "999999.99", message = "Amount exceeds maximum")
    @Digits(integer = 6, fraction = 2)
    private BigDecimal amount;
    
    @NotBlank(message = "Card number is required")
    @Pattern(regexp = "^\\d{13,19}$", message = "Invalid card format")
    @LuhnCheck  // Custom validator
    private String cardNumber;
    
    @NotBlank(message = "CVV is required")
    @Pattern(regexp = "^\\d{3,4}$", message = "Invalid CVV")
    private String cvv;
    
    @NotNull
    @Min(1) @Max(12)
    private Integer expiryMonth;
    
    @NotNull
    @Min(2024)
    private Integer expiryYear;
    
    // Getters and setters
}

// Custom Luhn validator
@Constraint(validatedBy = LuhnCheckValidator.class)
@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
public @interface LuhnCheck {
    String message() default "Invalid card number";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

public class LuhnCheckValidator 
        implements ConstraintValidator<LuhnCheck, String> {
    
    @Override
    public boolean isValid(String cardNumber, 
                          ConstraintValidatorContext context) {
        if (cardNumber == null) return false;
        
        // Luhn algorithm implementation
        int sum = 0;
        boolean alternate = false;
        
        for (int i = cardNumber.length() - 1; i >= 0; i--) {
            int digit = Character.getNumericValue(cardNumber.charAt(i));
            
            if (alternate) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            
            sum += digit;
            alternate = !alternate;
        }
        
        return sum % 10 == 0;  // COMPLIANT
    }
}
```

#### Remediation Steps
1. **Never trust client input**: Validate everything on the server
2. **Use validation libraries**: express-validator, Joi, Bean Validation
3. **Implement allowlists**: Define what's valid, reject everything else
4. **Validate data types**: Ensure correct types before processing
5. **Range validation**: Check min/max values for amounts, dates
6. **Format validation**: Use regex for card numbers, dates, etc.
7. **Business logic validation**: Check card expiry, amount limits, etc.

---

### Rule: PCI-SSS-C1.2 - Context-Aware Output Encoding

**Severity:** High  
**PCI SSS Reference:** Module C, Requirement C1.2

#### Description
All output to web clients must be encoded based on the output context:
- HTML context: HTML entity encoding
- JavaScript context: JavaScript encoding
- URL context: URL encoding
- CSS context: CSS encoding
- JSON context: JSON encoding

#### Rationale
Different contexts require different encoding schemes. Incorrect encoding leads to XSS vulnerabilities.

#### Detection Pattern
- **Languages:** Python, JavaScript, PHP, Java
- **Pattern Type:** Template rendering analysis
- **Looks for:**
  - Unescaped output in templates
  - Direct string concatenation in HTML
  - Unsafe DOM manipulation

#### Examples

##### Non-Compliant Code

```python
# Python Flask - VIOLATION: Unescaped output
from flask import Flask

@app.route('/receipt')
def show_receipt():
    customer_name = request.args.get('name')
    amount = request.args.get('amount')
    
    # VIOLATION - no escaping
    html = f"""
    <html>
        <body>
            <h1>Receipt for {customer_name}</h1>
            <p>Amount: ${amount}</p>
        </body>
    </html>
    """
    return html  # VIOLATION - XSS risk

# Python - VIOLATION: JavaScript context without encoding
@app.route('/checkout')
def checkout():
    user_data = get_user_data()
    # VIOLATION - inserting into JavaScript without proper encoding
    return f"""
    <script>
        var userData = {{
            name: "{user_data['name']}",
            email: "{user_data['email']}"
        }};
    </script>
    """
```

```javascript
// Express.js - VIOLATION: Unescaped template literals
app.get('/receipt', (req, res) => {
    const { name, amount } = req.query;
    
    // VIOLATION - no escaping in template
    const html = `
        <html>
            <body>
                <h1>Receipt for ${name}</h1>
                <p>Amount: $${amount}</p>
            </body>
        </html>
    `;
    res.send(html);  // VIOLATION
});

// Client-side - VIOLATION: Direct DOM manipulation
function displayPaymentSuccess(customerName, amount) {
    // VIOLATION - innerHTML with unescaped data
    document.getElementById('receipt').innerHTML = `
        <h2>Thank you, ${customerName}!</h2>
        <p>Payment of $${amount} processed</p>
    `;
}
```

##### Compliant Code

```python
# Python Flask - Compliant: Auto-escaping with Jinja2
from flask import Flask, render_template_string

@app.route('/receipt')
def show_receipt():
    customer_name = request.args.get('name', '')
    amount = request.args.get('amount', '0.00')
    
    # COMPLIANT - Jinja2 auto-escapes by default
    template = """
    <html>
        <body>
            <h1>Receipt for {{ name }}</h1>
            <p>Amount: ${{ amount }}</p>
        </body>
    </html>
    """
    return render_template_string(template, name=customer_name, amount=amount)

# Python - Compliant: JSON encoding for JavaScript context
import json

@app.route('/checkout')
def checkout():
    user_data = get_user_data()
    
    # COMPLIANT - proper JSON encoding
    user_data_json = json.dumps(user_data)
    
    return f"""
    <script>
        var userData = {user_data_json};
    </script>
    """

# Python - Compliant: Using template files
@app.route('/payment-form')
def payment_form():
    # COMPLIANT - Jinja2 template file with auto-escaping
    return render_template('payment.html', 
                          user=get_current_user(),
                          csrf_token=generate_csrf_token())
```

```javascript
// Express.js - Compliant: Using template engine
const handlebars = require('handlebars');

app.get('/receipt', (req, res) => {
    const { name, amount } = req.query;
    
    // COMPLIANT - Handlebars escapes by default
    const template = handlebars.compile(`
        <html>
            <body>
                <h1>Receipt for {{name}}</h1>
                <p>Amount: ${{amount}}</p>
            </body>
        </html>
    `);
    
    res.send(template({ name, amount }));
});

// Express.js - Compliant: Manual escaping when needed
const escapeHtml = require('escape-html');

app.get('/custom-receipt', (req, res) => {
    const name = escapeHtml(req.query.name || '');
    const amount = escapeHtml(req.query.amount || '0.00');
    
    // COMPLIANT - manually escaped
    const html = `
        <html>
            <body>
                <h1>Receipt for ${name}</h1>
                <p>Amount: $${amount}</p>
            </body>
        </html>
    `;
    res.send(html);
});

// Client-side - Compliant: Safe DOM manipulation
function displayPaymentSuccess(customerName, amount) {
    const receiptDiv = document.getElementById('receipt');
    
    // COMPLIANT - using textContent (auto-escapes)
    const heading = document.createElement('h2');
    heading.textContent = `Thank you, ${customerName}!`;
    
    const paragraph = document.createElement('p');
    paragraph.textContent = `Payment of $${amount} processed`;
    
    receiptDiv.appendChild(heading);
    receiptDiv.appendChild(paragraph);
}

// Client-side - Compliant: DOMPurify for necessary HTML
import DOMPurify from 'dompurify';

function displayRichContent(content) {
    const sanitized = DOMPurify.sanitize(content);
    document.getElementById('content').innerHTML = sanitized;  // COMPLIANT
}
```

```java
// Spring Boot - Compliant: Thymeleaf auto-escaping
@Controller
public class PaymentController {
    
    @GetMapping("/receipt")
    public String showReceipt(
            @RequestParam String name,
            @RequestParam String amount,
            Model model) {
        
        // COMPLIANT - Thymeleaf escapes by default
        model.addAttribute("customerName", name);
        model.addAttribute("amount", amount);
        
        return "receipt";  // receipt.html template
    }
}
```

```html
<!-- Thymeleaf template - receipt.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<body>
    <!-- COMPLIANT - th:text escapes automatically -->
    <h1 th:text="'Receipt for ' + ${customerName}"></h1>
    <p th:text="'Amount: $' + ${amount}"></p>
    
    <!-- For unescaped HTML (use with extreme caution) -->
    <!-- <div th:utext="${trustedHtmlContent}"></div> -->
</body>
</html>
```

#### Remediation Steps
1. **Use template engines**: Jinja2, Handlebars, Thymeleaf auto-escape
2. **Context-specific encoding**:
   - HTML: Use HTML entity encoding
   - JavaScript: JSON.stringify() for data
   - URL: URL encoding for parameters
   - CSS: Avoid dynamic CSS, use allowlists
3. **Client-side**: Use textContent, not innerHTML
4. **Sanitization libraries**: DOMPurify for necessary HTML
5. **Content Security Policy**: Add CSP headers as defense-in-depth

---

## C2. Authentication and Session Management

### Rule: PCI-SSS-C2.1 - Secure Session Management

**Severity:** High  
**PCI SSS Reference:** Module C, Requirement C2.1

#### Description
Web application sessions must be managed securely with:
- Secure session ID generation
- HTTPOnly and Secure flags on cookies
- Session timeout implementation
- Session regeneration after authentication
- Proper session termination

#### Rationale
Session hijacking is a primary attack vector for web applications handling payment data. Secure session management prevents unauthorized access.

#### Detection Pattern
- **Languages:** Python, JavaScript, PHP, Java
- **Pattern Type:** Session configuration analysis
- **Looks for:**
  - Insecure cookie settings
  - Missing session timeouts
  - No session regeneration
  - Predictable session IDs

#### Examples

##### Non-Compliant Code

```python
# Python Flask - VIOLATION: Insecure session configuration
from flask import Flask, session

app = Flask(__name__)
app.secret_key = 'mysecretkey'  # VIOLATION - hardcoded

# VIOLATION - no secure cookie settings
app.config['SESSION_COOKIE_SECURE'] = False  # Should be True
app.config['SESSION_COOKIE_HTTPONLY'] = False  # Should be True
app.config['SESSION_COOKIE_SAMESITE'] = None  # Should be 'Strict' or 'Lax'

@app.route('/login', methods=['POST'])
def login():
    user = authenticate_user(request.form['username'], 
                            request.form['password'])
    if user:
        # VIOLATION - no session regeneration
        session['user_id'] = user.id
        return redirect('/dashboard')
```

```javascript
// Express.js - VIOLATION: Weak session configuration
const session = require('express-session');

app.use(session({
    secret: 'keyboard cat',  // VIOLATION - weak secret
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,  // VIOLATION - should be true in production
        httpOnly: false,  // VIOLATION - should be true
        maxAge: 24 * 60 * 60 * 1000  // VIOLATION - 24 hours too long
    }
}));

app.post('/login', (req, res) => {
    const user = authenticateUser(req.body.username, req.body.password);
    if (user) {
        // VIOLATION - no session regeneration
        req.session.userId = user.id;
        res.redirect('/dashboard');
    }
});
```

```php
// PHP - VIOLATION: Insecure session handling
<?php
// VIOLATION - no secure/httponly flags
session_start();

if (authenticate_user($_POST['username'], $_POST['password'])) {
    // VIOLATION - no session regeneration
    $_SESSION['user_id'] = $user_id;
    $_SESSION['authenticated'] = true;
}
?>
```

##### Compliant Code

```python
# Python Flask - Compliant: Secure session configuration
from flask import Flask, session
import os
from datetime import timedelta

app = Flask(__name__)

# COMPLIANT - secure secret from environment
app.secret_key = os.environ.get('SECRET_KEY') or os.urandom(32)

# COMPLIANT - secure cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Strict', # CSRF protection
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # 30-minute timeout
    SESSION_COOKIE_NAME='__Secure-session'  # Secure prefix
)

@app.route('/login', methods=['POST'])
def login():
    user = authenticate_user(
        request.form.get('username'),
        request.form.get('password')
    )
    
    if user:
        # COMPLIANT - regenerate session ID
        session.clear()
        session.permanent = True
        
        # Set session data
        session['user_id'] = user.id
        session['authenticated'] = True
        session['login_time'] = datetime.utcnow().isoformat()
        
        # Log successful login
        audit_log.info(f"User {user.id} logged in")
        
        return redirect('/dashboard')
    else:
        return render_template('login.html', error='Invalid credentials')

@app.route('/logout')
def logout():
    # COMPLIANT - proper session termination
    user_id = session.get('user_id')
    session.clear()
    
    if user_id:
        audit_log.info(f"User {user_id} logged out")
    
    return redirect('/login')

@app.before_request
def check_session_timeout():
    """Check for session timeout"""
    if 'login_time' in session:
        login_time = datetime.fromisoformat(session['login_time'])
        if datetime.utcnow() - login_time > timedelta(minutes=30):
            session.clear()
            return redirect('/login?timeout=true')
```

```javascript
// Express.js - Compliant: Secure session configuration
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');

// COMPLIANT - Redis for session storage
const redisClient = redis.createClient({
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT
});

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,  // COMPLIANT - from environment
    resave: false,
    saveUninitialized: false,
    name: '__Secure-sessionid',  // COMPLIANT - secure name
    cookie: {
        secure: true,       // COMPLIANT - HTTPS only
        httpOnly: true,     // COMPLIANT - no JavaScript access
        maxAge: 30 * 60 * 1000,  // COMPLIANT - 30 minutes
        sameSite: 'strict'  // COMPLIANT - CSRF protection
    },
    rolling: true  // COMPLIANT - reset maxAge on each request
}));

app.post('/login', async (req, res) => {
    const user = await authenticateUser(
        req.body.username,
        req.body.password
    );
    
    if (user) {
        // COMPLIANT - regenerate session
        req.session.regenerate((err) => {
            if (err) {
                return res.status(500).json({ error: 'Session error' });
            }
            
            // Set session data
            req.session.userId = user.id;
            req.session.authenticated = true;
            req.session.loginTime = Date.now();
            
            // Save session
            req.session.save((err) => {
                if (err) {
                    return res.status(500).json({ error: 'Session save error' });
                }
                
                auditLog.info(`User ${user.id} logged in`);
                res.json({ success: true });
            });
        });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.post('/logout', (req, res) => {
    const userId = req.session.userId;
    
    // COMPLIANT - destroy session
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout error' });
        }
        
        res.clearCookie('__Secure-sessionid');
        
        if (userId) {
            auditLog.info(`User ${userId} logged out`);
        }
        
        res.json({ success: true });
    });
});

// COMPLIANT - Session timeout middleware
app.use((req, res, next) => {
    if (req.session.loginTime) {
        const elapsed = Date.now() - req.session.loginTime;
        const timeout = 30 * 60 * 1000;  // 30 minutes
        
        if (elapsed > timeout) {
            req.session.destroy();
            return res.status(401).json({ error: 'Session timeout' });
        }
    }
    next();
});
```

```java
// Spring Boot - Compliant: Secure session configuration
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/login?invalid=true")
                .maximumSessions(1)  // One session per user
                .expiredUrl("/login?expired=true")
                .maxSessionsPreventsLogin(false)
                .and()
                .sessionFixation().newSession()  // COMPLIANT - regenerate on auth
            .and()
            .rememberMe().disable()  // Disable remember-me for payment apps
            .and()
            .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .invalidateHttpSession(true)  // COMPLIANT - destroy session
                .deleteCookies("JSESSIONID")
                .clearAuthentication(true);
    }
    
    @Bean
    public ServletContextInitializer servletContextInitializer() {
        return servletContext -> {
            // COMPLIANT - secure cookie settings
            SessionCookieConfig sessionCookieConfig = 
                servletContext.getSessionCookieConfig();
            sessionCookieConfig.setHttpOnly(true);
            sessionCookieConfig.setSecure(true);
            sessionCookieConfig.setName("__Secure-JSESSIONID");
            sessionCookieConfig.setMaxAge(1800);  // 30 minutes
        };
    }
}
```

#### Remediation Steps
1. **Secure cookie flags**:
   - `Secure`: true (HTTPS only)
   - `HttpOnly`: true (no JavaScript access)
   - `SameSite`: 'Strict' or 'Lax'
2. **Session timeout**: 15-30 minutes for payment applications
3. **Regenerate session ID**: After login, privilege escalation
4. **Secure session storage**: Redis, database, not filesystem
5. **Strong secret key**: From environment, never hardcoded
6. **Session monitoring**: Log creation, destruction, timeout
7. **Proper logout**: Destroy session server-side, clear cookies

---

## C3. Browser Security Controls

### Rule: PCI-SSS-C3.1 - HTTP Security Headers

**Severity:** High  
**PCI SSS Reference:** Module C, Requirement C3.1

#### Description
Web applications must implement security headers to provide defense-in-depth:
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection (for legacy browsers)
- Referrer-Policy

#### Rationale
Security headers provide additional layers of protection against common web attacks including XSS, clickjacking, MIME sniffing, and protocol downgrade attacks.

#### Detection Pattern
- **Languages:** All server-side languages
- **Pattern Type:** HTTP response header analysis
- **Looks for:**
  - Missing security headers
  - Weak CSP policies
  - Missing HSTS headers
  - Permissive X-Frame-Options

#### Examples

##### Non-Compliant Code

```python
# Python Flask - VIOLATION: No security headers
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/checkout')
def checkout():
    # VIOLATION - no security headers set
    return render_template('checkout.html')
```

```javascript
// Express.js - VIOLATION: Missing security headers
app.get('/payment', (req, res) => {
    // VIOLATION - no security headers
    res.send('<html>...</html>');
});
```

##### Compliant Code

```python
# Python Flask - Compliant: Comprehensive security headers
from flask import Flask, render_template

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    
    # COMPLIANT - Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://js.stripe.com; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' https:; "
        "font-src 'self'; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-src https://js.stripe.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    
    # COMPLIANT - Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # COMPLIANT - Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    
    # COMPLIANT - HSTS for HTTPS enforcement
    response.headers['Strict-Transport-Security'] = (
        'max-age=31536000; includeSubDomains; preload'
    )
    
    # COMPLIANT - Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # COMPLIANT - Permissions policy
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=(self)'
    )
    
    return response

@app.route('/checkout')
def checkout():
    # Headers automatically added by after_request
    return render_template('checkout.html')
```

```javascript
// Express.js - Compliant: Using Helmet.js
const helmet = require('helmet');

// COMPLIANT - Helmet sets multiple security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://js.stripe.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "https:"],
            connectSrc: ["'self'", "https://api.stripe.com"],
            frameSrc: ["https://js.stripe.com"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: {
        action: 'deny'
    },
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    }
}));

app.get('/payment', (req, res) => {
    // Security headers automatically added by Helmet
    res.render('payment');
});
```

```java
// Spring Boot - Compliant: Security headers configuration
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .contentSecurityPolicy(
                    "default-src 'self'; " +
                    "script-src 'self' https://js.stripe.com; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "frame-src https://js.stripe.com; " +
                    "frame-ancestors 'none'"
                )
                .and()
                .xssProtection()
                    .block(true)
                .and()
                .contentTypeOptions()
                .and()
                .frameOptions()
                    .deny()
                .and()
                .httpStrictTransportSecurity()
                    .maxAgeInSeconds(31536000)
                    .includeSubDomains(true)
                    .preload(true)
                .and()
                .referrerPolicy(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy
                        .STRICT_ORIGIN_WHEN_CROSS_ORIGIN
                );
    }
}
```

#### Remediation Steps
1. **Implement CSP**: Start with restrictive policy, allow only necessary sources
2. **Enable HSTS**: Force HTTPS with long max-age
3. **Prevent clickjacking**: Use X-Frame-Options: DENY or SAMEORIGIN
4. **MIME sniffing protection**: X-Content-Type-Options: nosniff
5. **Test headers**: Use securityheaders.com or Mozilla Observatory
6. **Monitor CSP violations**: Set up CSP reporting endpoint

---

## C4. API Security

### Rule: PCI-SSS-C4.1 - API Authentication and Authorization

**Severity:** Critical  
**PCI SSS Reference:** Module C, Requirement C4.1

#### Description
Payment APIs must implement strong authentication and authorization:
- API key management
- Token-based authentication (JWT, OAuth 2.0)
- Rate limiting
- Request signing
- Scope-based authorization

#### Rationale
APIs handling payment data are prime targets for attacks. Proper authentication prevents unauthorized access.

#### Examples

##### Non-Compliant Code

```python
# Python Flask - VIOLATION: No API authentication
@app.route('/api/payment', methods=['POST'])
def create_payment():
    # VIOLATION - no authentication check
    data = request.json
    return process_payment(data)

# Python - VIOLATION: Weak API key check
@app.route('/api/charge', methods=['POST'])
def charge_card():
    api_key = request.headers.get('X-API-Key')
    # VIOLATION - simple string comparison, timing attack vulnerable
    if api_key == 'secret_key_12345':
        return process_charge(request.json)
    return jsonify({'error': 'Unauthorized'}), 401
```

```javascript
// Express.js - VIOLATION: No authentication
app.post('/api/payment', (req, res) => {
    // VIOLATION - anyone can call this endpoint
    const result = processPayment(req.body);
    res.json(result);
});
```

##### Compliant Code

```python
# Python Flask - Compliant: JWT authentication
from flask import Flask, request, jsonify
from functools import wraps
import jwt
import secrets
from datetime import datetime, timedelta

SECRET_KEY = os.environ['JWT_SECRET_KEY']

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # COMPLIANT - verify JWT token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            
            # Check expiration
            if datetime.utcfromtimestamp(payload['exp']) < datetime.utcnow():
                return jsonify({'error': 'Token expired'}), 401
            
            # Add user info to request
            request.user_id = payload['user_id']
            request.permissions = payload.get('permissions', [])
            
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def require_permission(permission):
    """Decorator to check specific permissions"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if permission not in request.permissions:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/payment', methods=['POST'])
@require_auth
@require_permission('payment:create')
def create_payment():
    # COMPLIANT - authenticated and authorized
    data = request.json
    
    # Additional validation
    if not validate_payment_data(data):
        return jsonify({'error': 'Invalid payment data'}), 400
    
    # Process payment with user context
    result = process_payment(data, user_id=request.user_id)
    
    # Audit log
    audit_log.info(f"Payment created by user {request.user_id}")
    
    return jsonify(result)

# COMPLIANT - API key management with constant-time comparison
@app.route('/api/webhook', methods=['POST'])
def webhook():
    api_key = request.headers.get('X-API-Key', '')
    
    # Retrieve expected key from secure storage
    expected_key = get_api_key_from_secure_storage(request.json.get('client_id'))
    
    # COMPLIANT - constant-time comparison
    if not secrets.compare_digest(api_key, expected_key):
        return jsonify({'error': 'Invalid API key'}), 401
    
    # Verify request signature
    signature = request.headers.get('X-Signature')
    if not verify_webhook_signature(request.data, signature):
        return jsonify({'error': 'Invalid signature'}), 401
    
    process_webhook(request.json)
    return jsonify({'status': 'received'})
```

```javascript
// Express.js - Compliant: JWT middleware
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

// COMPLIANT - Rate limiting for API endpoints
const paymentLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Max 100 requests per windowMs
    message: 'Too many payment requests, please try again later'
});

// COMPLIANT - JWT authentication middleware
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    const token = authHeader.substring(7);
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        
        req.user = user;
        next();
    });
};

// COMPLIANT - Permission check middleware
const requirePermission = (permission) => {
    return (req, res, next) => {
        if (!req.user.permissions.includes(permission)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// COMPLIANT - Protected payment endpoint
app.post('/api/payment',
    paymentLimiter,
    authenticateJWT,
    requirePermission('payment:create'),
    async (req, res) => {
        try {
            // Validate input
            const errors = validatePaymentData(req.body);
            if (errors.length > 0) {
                return res.status(400).json({ errors });
            }
            
            // Process payment with user context
            const result = await processPayment(req.body, req.user.id);
            
            // Audit log
            auditLog.info({
                action: 'payment_created',
                userId: req.user.id,
                transactionId: result.id
            });
            
            res.json(result);
        } catch (error) {
            logger.error('Payment processing error', error);
            res.status(500).json({ error: 'Payment processing failed' });
        }
    }
);

// COMPLIANT - Request signature verification
const crypto = require('crypto');

function verifySignature(req, res, next) {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    
    // Check timestamp to prevent replay attacks
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 300) { // 5 minutes
        return res.status(401).json({ error: 'Request too old' });
    }
    
    // Verify signature
    const payload = timestamp + JSON.stringify(req.body);
    const expectedSignature = crypto
        .createHmac('sha256', process.env.WEBHOOK_SECRET)
        .update(payload)
        .digest('hex');
    
    if (!crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expectedSignature)
    )) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    
    next();
}

app.post('/api/webhook',
    verifySignature,
    async (req, res) => {
        await processWebhook(req.body);
        res.json({ status: 'received' });
    }
);
```

#### Remediation Steps
1. **Implement JWT or OAuth 2.0**: For API authentication
2. **Use API keys securely**: Store hashed, rotate regularly
3. **Implement rate limiting**: Prevent abuse and DoS
4. **Request signing**: Verify request integrity and authenticity
5. **Scope-based permissions**: Principle of least privilege
6. **Monitor API usage**: Track anomalous patterns
7. **Audit logging**: Log all API access and actions

---

## C5. Client-Side Security

### Rule: PCI-SSS-C5.1 - No Sensitive Data in Browser Storage

**Severity:** Critical  
**PCI SSS Reference:** Module C, Requirement C5.1

#### Description
Cardholder data must NEVER be stored in browser storage mechanisms:
- localStorage
- sessionStorage
- IndexedDB
- Cookies (for PAN/CVV)
- Service Worker cache

#### Rationale
Browser storage is accessible via JavaScript, making it vulnerable to XSS attacks. PAN and CVV must never persist client-side.

#### Examples

##### Non-Compliant Code

```javascript
// VIOLATION: Storing PAN in localStorage
function savePaymentMethod(cardNumber, cvv) {
    // CRITICAL VIOLATION
    localStorage.setItem('cardNumber', cardNumber);
    localStorage.setItem('cvv', cvv);
}

// VIOLATION: Storing in sessionStorage
function cachePaymentInfo(paymentData) {
    sessionStorage.setItem('payment', JSON.stringify(paymentData));
}

// VIOLATION: Storing in cookie
function rememberCard(cardNumber) {
    document.cookie = `card=${cardNumber}; path=/`;
}
```

##### Compliant Code

```javascript
// COMPLIANT: No client-side storage of PAN
function processPayment(cardData) {
    // Send directly to server, never store
    return fetch('/api/payment', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(cardData)
    })
    .then(response => response.json())
    .then(result => {
        // COMPLIANT - store only token, not PAN
        if (result.token) {
            localStorage.setItem('paymentToken', result.token);
        }
        return result;
    });
}

// COMPLIANT: Use tokenization
async function savePaymentMethod(cardData) {
    // Get token from server
    const response = await fetch('/api/tokenize', {
        method: 'POST',
        body: JSON.stringify(cardData)
    });
    
    const { token, last4, cardType } = await response.json();
    
    // COMPLIANT - store only non-sensitive data
    localStorage.setItem('savedCard', JSON.stringify({
        token: token,
        last4: last4,
        type: cardType
    }));
}

// COMPLIANT: Use payment gateway's hosted fields
function initializePaymentForm() {
    // Stripe.js example - PAN never touches your JavaScript
    const stripe = Stripe('pk_live_...');
    const elements = stripe.elements();
    
    const cardElement = elements.create('card');
    cardElement.mount('#card-element');
    
    // When form submitted, create token via Stripe
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        
        const {token, error} = await stripe.createToken(cardElement);
        
        if (error) {
            displayError(error.message);
        } else {
            // Send token to server, not card data
            submitPayment(token.id);
        }
    });
}
```

#### Remediation Steps
1. **Never store PAN client-side**: No exceptions
2. **Use tokenization**: Get tokens from payment gateway
3. **Hosted payment fields**: Use iframe solutions (Stripe Elements, PayPal)
4. **Memory-only**: If PAN in memory, clear after submission
5. **Code review**: Search for localStorage/sessionStorage/IndexedDB usage
6. **Content Security Policy**: Restrict script execution

---

## C7. Payment Data Protection in Web Context

### Rule: PCI-SSS-C7.1 - Secure Payment Form Implementation

**Severity:** Critical  
**PCI SSS Reference:** Module C, Requirement C7.1

#### Description
Payment forms must be implemented securely:
- HTTPS required for all payment pages
- No PAN in GET parameters or URLs
- Autocomplete=off for sensitive fields
- Input masking for card numbers
- No caching of payment data
- Form validation before submission

#### Examples

##### Non-Compliant Code

```html
<!-- VIOLATION: Form over HTTP -->
<form action="http://example.com/payment" method="POST">
    <input name="cardNumber" />
    <input name="cvv" />
    <button>Pay</button>
</form>

<!-- VIOLATION: Using GET method -->
<form action="/payment" method="GET">
    <input name="card" />
</form>

<!-- VIOLATION: No autocomplete protection -->
<input type="text" name="cardNumber" />
<input type="text" name="cvv" />
```

##### Compliant Code

```html
<!-- COMPLIANT: Secure payment form -->
<form id="payment-form" action="https://secure.example.com/payment" method="POST">
    <!-- COMPLIANT: Autocomplete off for sensitive fields -->
    <label for="card-number">Card Number</label>
    <input 
        type="text" 
        id="card-number" 
        name="cardNumber"
        autocomplete="off"
        inputmode="numeric"
        pattern="[0-9\s]{13,19}"
        maxlength="19"
        required
    />
    
    <label for="cvv">CVV</label>
    <input 
        type="text" 
        id="cvv" 
        name="cvv"
        autocomplete="off"
        inputmode="numeric"
        pattern="[0-9]{3,4}"
        maxlength="4"
        required
    />
    
    <label for="expiry">Expiry (MM/YY)</label>
    <input 
        type="text" 
        id="expiry" 
        name="expiry"
        autocomplete="off"
        pattern="(0[1-9]|1[0-2])\/[0-9]{2}"
        placeholder="MM/YY"
        required
    />
    
    <button type="submit">Pay Securely</button>
</form>

<script>
// COMPLIANT: Client-side validation and masking
document.getElementById('card-number').addEventListener('input', function(e) {
    // Format card number with spaces
    let value = e.target.value.replace(/\s/g, '');
    let formattedValue = value.match(/.{1,4}/g)?.join(' ') || value;
    e.target.value = formattedValue;
});

document.getElementById('payment-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Clear any previous errors
    clearErrors();
    
    // Validate before submission
    const cardNumber = document.getElementById('card-number').value.replace(/\s/g, '');
    const cvv = document.getElementById('cvv').value;
    
    if (!luhnCheck(cardNumber)) {
        showError('Invalid card number');
        return;
    }
    
    if (!/^\d{3,4}$/.test(cvv)) {
        showError('Invalid CVV');
        return;
    }
    
    // Disable submit button to prevent double submission
    const submitButton = this.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    submitButton.textContent = 'Processing...';
    
    try {
        // Submit to server
        const response = await fetch(this.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                cardNumber: cardNumber,
                cvv: cvv,
                expiry: document.getElementById('expiry').value
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Clear form
            this.reset();
            
            // Redirect to success page
            window.location.href = '/payment-success';
        } else {
            showError(result.error || 'Payment failed');
            submitButton.disabled = false;
            submitButton.textContent = 'Pay Securely';
        }
    } catch (error) {
        showError('Network error, please try again');
        submitButton.disabled = false;
        submitButton.textContent = 'Pay Securely';
    }
});

// Luhn algorithm for card validation
function luhnCheck(cardNumber) {
    let sum = 0;
    let isEven = false;
    
    for (let i = cardNumber.length - 1; i >= 0; i--) {
        let digit = parseInt(cardNumber.charAt(i), 10);
        
        if (isEven) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;
            }
        }
        
        sum += digit;
        isEven = !isEven;
    }
    
    return (sum % 10) === 0;
}
</script>
```

#### Remediation Steps
1. **Force HTTPS**: All payment pages must use HTTPS
2. **POST method only**: Never use GET for payment forms
3. **Autocomplete off**: For card number, CVV, sensitive fields
4. **Input validation**: Both client and server-side
5. **Prevent double submission**: Disable submit button after click
6. **Clear after submission**: Don't leave data in form fields
7. **No caching**: Set cache-control headers

---

## Summary and Compliance Checklist

### Module C Requirements Coverage

**Web Software Security:**
- [x] C1.1: Server-side input validation
- [x] C1.2: Context-aware output encoding
- [x] C2.1: Secure session management
- [x] C3.1: HTTP security headers
- [x] C4.1: API authentication and authorization
- [x] C5.1: No sensitive data in browser storage
- [x] C7.1: Secure payment form implementation

### Web Application Security Priorities

**Phase 1 - Critical (Week 1):**
1. Implement server-side input validation
2. Enable security headers (CSP, HSTS, X-Frame-Options)
3. Secure session management
4. Remove any PAN from client-side storage

**Phase 2 - High (Week 2-3):**
5. API authentication and authorization
6. Output encoding in all contexts
7. Secure payment form implementation
8. Rate limiting on payment endpoints

**Phase 3 - Ongoing:**
9. Regular security testing
10. CSP violation monitoring
11. Session security audits
12. API usage monitoring

### Testing Checklist

**Before Deployment:**
- [ ] All payment pages use HTTPS
- [ ] Security headers present on all responses
- [ ] Session cookies have Secure, HTTPOnly, SameSite flags
- [ ] No PAN in URLs, logs, or client storage
- [ ] Input validation on all endpoints
- [ ] Output encoding in all contexts
- [ ] API authentication working correctly
- [ ] Rate limiting functional
- [ ] CSP policy doesn't break functionality
- [ ] Payment forms have autocomplete=off

### Browser Compatibility

Test security features in:
- Chrome/Edge (Chromium)
- Firefox
- Safari
- Mobile browsers (iOS Safari, Chrome Mobile)

### Security Testing Tools

- **OWASP ZAP**: Web application security scanner
- **Burp Suite**: Manual security testing
- **securityheaders.com**: Header validation
- **Mozilla Observatory**: Overall security score
- **Chrome DevTools**: CSP violation monitoring
- **Lighthouse**: Security audit

### Related Documentation

- **[Core Requirements](core-requirements.md)** - Base security requirements
- **[Module A: Account Data Protection](module-a-account-data.md)** - CHD protection
- **[Module B: Terminal Software](module-b-terminal.md)** - Terminal requirements
- **[PCI DSS Overview](README.md)** - Framework structure and guidance

### Important Notes

**Scope Reduction Strategies:**
- Use hosted payment pages (Stripe Checkout, PayPal)
- Implement payment iframes (Stripe Elements)
- Tokenize immediately at point of capture
- Never store PAN in your environment

**SAQ Types:**
- **SAQ A**: Fully outsourced payments (redirect to payment gateway)
- **SAQ A-EP**: E-commerce with payment gateway iframe
- **SAQ D**: Full merchant control (highest compliance burden)

---

**Need help?** Open an issue or discussion in the main repository.

**Repository:** https://github.com/cj-juntunen/security-framework-linters
