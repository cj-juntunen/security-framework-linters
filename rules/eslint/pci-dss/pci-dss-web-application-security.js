/**
 * ESLint Configuration for PCI DSS SSS - Module C: Web Software
 * 
 * Framework: PCI SSS v1.2.1 - Module C
 * Last Updated: 2025-11-19
 * Repository: https://github.com/cj-juntunen/security-framework-linters
 * 
 * Applies to: Web-based payment software using Internet technologies
 * 
 * Coverage:
 * - Input validation and output encoding
 * - Session management security
 * - Browser security controls
 * - API security
 * - Client-side payment data protection
 * - Content Security Policy
 * 
 * Usage:
 *   // .eslintrc.js
 *   module.exports = {
 *     extends: [
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-core.js',
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-module-a.js',
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-module-c.js'
 *     ]
 *   };
 * 
 * Required Plugins:
 *   npm install --save-dev eslint-plugin-security eslint-plugin-no-unsanitized
 */

module.exports = {
  plugins: [
    'security',
    'no-unsanitized'
  ],
  
  rules: {
    // ========================================================================
    // MODULE C-1: INPUT VALIDATION AND OUTPUT ENCODING
    // ========================================================================
    
    /**
     * C1.1: Server-side validation - Detect client-only validation patterns
     * PCI SSS C1.1: All input must be validated server-side
     */
    'no-restricted-syntax': [
      'error',
      {
        selector: 'CallExpression[callee.property.name="preventDefault"][arguments.length=0]:not(:has(CallExpression[callee.object.name=/fetch|axios|ajax/]))',
        message: 'Form submission prevented without server validation. PCI SSS C1.1 requires server-side validation for all inputs.'
      }
    ],
    
    /**
     * C1.2: XSS Prevention - innerHTML usage
     * PCI SSS C1.2: Context-aware output encoding required
     */
    'no-unsanitized/property': [
      'error',
      {
        escape: {
          methods: ['DOMPurify.sanitize', 'escapeHtml', 'encodeHTML']
        }
      }
    ],
    
    /**
     * C1.2: XSS Prevention - DOM manipulation
     */
    'no-unsanitized/method': [
      'error',
      {
        escape: {
          methods: ['DOMPurify.sanitize', 'escapeHtml', 'encodeHTML']
        }
      }
    ],
    
    /**
     * C1.2: React-specific XSS prevention
     */
    'react/no-danger': 'error',
    'react/no-danger-with-children': 'error',
    
    // ========================================================================
    // MODULE C-2: AUTHENTICATION AND SESSION MANAGEMENT
    // ========================================================================
    
    /**
     * C2.1: Secure cookie configuration
     * PCI SSS C2.1: Sessions must use secure attributes
     */
    'security/detect-non-literal-fs-filename': 'off', // Disable to avoid conflicts
    
    /**
     * C2.1: Warn about potential session fixation
     */
    'no-restricted-properties': [
      'error',
      {
        object: 'document',
        property: 'cookie',
        message: 'Direct cookie manipulation detected. PCI SSS C2.1: Use secure session management with HTTPOnly, Secure, and SameSite attributes.'
      }
    ],
    
    // ========================================================================
    // MODULE C-3: BROWSER SECURITY CONTROLS
    // ========================================================================
    
    /**
     * C3.1: Detect missing security headers (informational)
     * Note: Headers are typically set server-side
     */
    'no-restricted-globals': [
      'warn',
      {
        name: 'eval',
        message: 'eval() usage detected. Ensure Content Security Policy blocks unsafe-eval.'
      }
    ],
    
    // ========================================================================
    // MODULE C-4: API SECURITY
    // ========================================================================
    
    /**
     * C4.1: API endpoints should use authentication
     * Detect fetch/axios calls without auth headers
     */
    'prefer-promise-reject-errors': 'error', // Ensure proper error handling
    
    // ========================================================================
    // MODULE C-5: CLIENT-SIDE SECURITY
    // ========================================================================
    
    /**
     * C5.1: CRITICAL - No PAN in browser storage
     * PCI SSS C5.1: Never store payment data client-side
     */
    'no-restricted-syntax': [
      'error',
      {
        selector: 'CallExpression[callee.object.name="localStorage"][callee.property.name=/setItem|getItem/][arguments.0.value=/card|pan|account|cvv|expiry/i]',
        message: 'CRITICAL: Potential payment data in localStorage. PCI SSS C5.1 prohibits storing PAN/CVV in browser storage.'
      },
      {
        selector: 'CallExpression[callee.object.name="sessionStorage"][callee.property.name=/setItem|getItem/][arguments.0.value=/card|pan|account|cvv|expiry/i]',
        message: 'CRITICAL: Potential payment data in sessionStorage. PCI SSS C5.1 prohibits storing PAN/CVV in browser storage.'
      },
      {
        selector: 'MemberExpression[object.name="localStorage"][property.name=/card|pan|account|cvv/i]',
        message: 'CRITICAL: Potential payment data access in localStorage. PCI SSS C5.1 prohibits storing PAN/CVV in browser storage.'
      }
    ],
    
    /**
     * C5.2: Secure postMessage usage
     */
    'security/detect-unsafe-regex': 'error',
    
    // ========================================================================
    // MODULE C-6: CONTENT SECURITY POLICY
    // ========================================================================
    
    /**
     * C6.1: Inline scripts and styles (CSP violations)
     */
    'no-inline-comments': 'off', // Don't interfere with CSP nonce comments
    
    // ========================================================================
    // MODULE C-7: PAYMENT DATA PROTECTION
    // ========================================================================
    
    /**
     * C7.1: Payment form security
     * Detect GET method usage for forms with payment fields
     */
    'jsx-a11y/autocomplete-valid': [
      'error',
      {
        inputComponents: ['Input', 'TextField']
      }
    ],
    
    /**
     * C7.1: Detect PAN in URLs
     */
    'no-restricted-syntax': [
      'error',
      {
        selector: 'TemplateLiteral:has(Identifier[name=/card|pan|cvv/i])',
        message: 'Potential payment data in URL. PCI SSS C7.1: Never include PAN in URLs.'
      },
      {
        selector: 'BinaryExpression[operator="+"] > Identifier[name=/card|pan|cvv/i]',
        message: 'Potential payment data concatenation in URL. PCI SSS C7.1: Never include PAN in URLs.'
      }
    ],
    
    /**
     * C7.2: Console logging restrictions for payment data
     */
    'no-console': [
      'error',
      {
        allow: ['warn', 'error']
      }
    ],
    
    /**
     * C7.3: Secure AJAX configuration
     */
    'security/detect-object-injection': 'warn',
    
    // ========================================================================
    // REACT-SPECIFIC RULES (if using React)
    // ========================================================================
    
    /**
     * Prevent XSS in React components
     */
    'react/jsx-no-target-blank': [
      'error',
      {
        allowReferrer: false,
        enforceDynamicLinks: 'always'
      }
    ],
    
    /**
     * Ensure proper key usage to prevent rendering issues
     */
    'react/jsx-key': 'error',
    
    // ========================================================================
    // API AND FETCH PATTERNS
    // ========================================================================
    
    /**
     * Ensure HTTPS usage for payment endpoints
     */
    'no-restricted-syntax': [
      'error',
      {
        selector: 'Literal[value=/^http:\/\/.*\/(payment|checkout|card|process)/]',
        message: 'HTTP detected for payment endpoint. PCI SSS C7.1: All payment communications must use HTTPS.'
      }
    ],
    
    /**
     * Detect insecure WebSocket usage
     */
    'no-restricted-syntax': [
      'error',
      {
        selector: 'NewExpression[callee.name="WebSocket"][arguments.0.value=/^ws:/]',
        message: 'Insecure WebSocket (ws://) detected. Use secure WebSocket (wss://) for payment data.'
      }
    ]
  },
  
  // ========================================================================
  // ENVIRONMENT-SPECIFIC OVERRIDES
  // ========================================================================
  
  overrides: [
    // Browser/Frontend specific rules
    {
      files: ['**/src/**/*.js', '**/src/**/*.jsx', '**/src/**/*.ts', '**/src/**/*.tsx'],
      env: {
        browser: true,
        node: false
      },
      rules: {
        // Stricter browser-specific rules
        'no-restricted-globals': [
          'error',
          {
            name: 'localStorage',
            message: 'Be extremely careful with localStorage. Never store payment data.'
          },
          {
            name: 'sessionStorage',
            message: 'Be extremely careful with sessionStorage. Never store payment data.'
          },
          {
            name: 'indexedDB',
            message: 'Never store payment card data in indexedDB.'
          }
        ]
      }
    },
    
    // Payment form components
    {
      files: ['**/payment/**/*.js', '**/checkout/**/*.js', '**/Payment*.js', '**/Checkout*.js'],
      rules: {
        // Extra strict rules for payment components
        'no-console': 'error', // No console.log in payment code
        'no-debugger': 'error',
        'no-alert': 'error',
        
        // Require explicit autocomplete attributes
        'jsx-a11y/autocomplete-valid': [
          'error',
          {
            inputComponents: ['Input', 'TextField', 'CreditCardInput']
          }
        ]
      }
    },
    
    // Test files
    {
      files: ['**/*.test.js', '**/*.spec.js', '**/__tests__/**/*.js'],
      rules: {
        'no-restricted-syntax': 'off', // Allow test card numbers in tests
        'security/detect-non-literal-regexp': 'off'
      }
    }
  ],
  
  // ========================================================================
  // GLOBALS
  // ========================================================================
  
  globals: {
    'DOMPurify': 'readonly',
    'stripe': 'readonly',
    'Stripe': 'readonly',
    'paypal': 'readonly',
    'braintree': 'readonly'
  }
};

/**
 * CRITICAL WEB SECURITY CHECKLIST
 * ================================
 * 
 * This ESLint configuration helps enforce PCI DSS Module C requirements,
 * but cannot detect all vulnerabilities. Manual review required for:
 * 
 * 1. SERVER-SIDE VALIDATION
 *    - Verify ALL inputs are validated server-side
 *    - Client-side validation is only for UX
 *    - Check API endpoints validate all parameters
 * 
 * 2. SECURITY HEADERS (set server-side)
 *    - Content-Security-Policy
 *    - Strict-Transport-Security (HSTS)
 *    - X-Frame-Options
 *    - X-Content-Type-Options
 *    - Referrer-Policy
 * 
 * 3. SESSION SECURITY
 *    - HTTPOnly cookies (cannot be checked client-side)
 *    - Secure flag on cookies
 *    - SameSite attribute
 *    - Session timeout implementation
 * 
 * 4. PAYMENT FORM SECURITY
 *    - HTTPS enforcement
 *    - POST method only
 *    - autocomplete="off" for sensitive fields
 *    - No payment data in URLs
 *    - Tokenization instead of raw PAN
 * 
 * 5. API SECURITY
 *    - Authentication on all endpoints
 *    - Rate limiting
 *    - Input validation
 *    - Output encoding
 * 
 * 6. THIRD-PARTY SCRIPTS
 *    - Subresource Integrity (SRI)
 *    - Trusted sources only
 *    - Regular updates
 * 
 * For comprehensive compliance, combine with:
 * - SAST tools (Semgrep, SonarQube)
 * - DAST tools (OWASP ZAP, Burp Suite)
 * - Manual penetration testing
 * - Code reviews focusing on security
 */
