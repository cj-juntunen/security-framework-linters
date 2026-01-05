/**
 * ESLint Configuration for PCI DSS SSS - Module A: Account Data Protection
 * 
 * Framework: PCI SSS v1.2.1 - Module A
 * Last Updated: 2025-11-19
 * Repository: https://github.com/cj-juntunen/security-framework-linters
 * 
 * Applies to: Software that stores, processes, or transmits account data
 * 
 * Coverage:
 * - Sensitive Authentication Data (SAD) protection
 * - Primary Account Number (PAN) protection
 * - Cardholder data encryption
 * - Key management for account data
 * - Data retention and disposal
 * - Account data logging and display
 * 
 * Usage:
 *   // .eslintrc.js
 *   module.exports = {
 *     extends: [
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-core.js',
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-module-a.js'
 *     ]
 *   };
 * 
 * CRITICAL: This module enforces rules around payment card data handling.
 * Violations can lead to data breaches and PCI DSS non-compliance.
 */

module.exports = {
  rules: {
    // ========================================================================
    // MODULE A-1.1: SENSITIVE AUTHENTICATION DATA (SAD) PROTECTION
    // ========================================================================
    
    /**
     * CRITICAL: Detect potential CVV/CVC storage
     * PCI SSS A1.1: CVV must NEVER be stored after authorization
     * 
     * This rule cannot fully detect all CVV storage patterns, but flags
     * suspicious variable names that may contain CVV data.
     */
    'no-restricted-syntax': ['error', {
      selector: 'Identifier[name=/cvv|cvc|cvv2|cvc2|cav|cid/i]',
      message: 'CRITICAL: Potential CVV/CVC variable detected. PCI SSS A1.1 strictly prohibits storing card verification codes after authorization. Ensure this variable is used only transiently for authorization and never persisted.'
    }],
    
    /**
     * CRITICAL: Detect potential PIN handling
     * PCI SSS A1.1: PIN must never exist in application code
     * 
     * PIN should only be handled in secure hardware (HSM/secure element)
     */
    'no-restricted-properties': ['error', {
      object: '*',
      property: 'pin',
      message: 'CRITICAL: PIN property detected. PCI SSS A1.1: PIN must NEVER be handled in application code. PIN entry and encryption must occur entirely in secure hardware.'
    }, {
      object: '*',
      property: 'pinBlock',
      message: 'CRITICAL: PIN block property detected. PIN blocks must be created and encrypted in secure hardware only.'
    }],
    
    // ========================================================================
    // MODULE A-2: PRIMARY ACCOUNT NUMBER (PAN) PROTECTION
    // ========================================================================
    
    /**
     * Detect potential PAN in variable names
     * PCI SSS A2: PAN must be encrypted at rest and masked in display
     * 
     * This is a warning because legitimate uses exist (encrypted PAN, tokens)
     */
    // Note: This would be too noisy as an error, documented in comments instead
    
    // ========================================================================
    // MODULE A-5: CLIENT-SIDE STORAGE PROTECTION
    // ========================================================================
    
    /**
     * CRITICAL: Prevent storage of payment data in localStorage
     * PCI SSS A5.1: Never store PAN, CVV, or SAD in browser storage
     */
    'no-restricted-globals': ['error', {
      name: 'localStorage',
      message: 'WARNING: localStorage usage detected. PCI SSS A5.1: NEVER store PAN, CVV, PIN, or any sensitive authentication data in localStorage. Use server-side tokenization instead.'
    }, {
      name: 'sessionStorage',
      message: 'WARNING: sessionStorage usage detected. PCI SSS A5.1: NEVER store PAN, CVV, PIN, or any sensitive authentication data in sessionStorage. Use server-side tokenization instead.'
    }],
    
    // ========================================================================
    // MODULE A-6: ACCOUNT DATA LOGGING
    // ========================================================================
    
    /**
     * Enhanced console restrictions for payment data
     * PCI SSS A6.1: PAN must never appear in logs
     */
    'no-console': ['error', {
      allow: ['warn', 'error']
    }],
    
    // ========================================================================
    // CUSTOM RULES FOR COMMON PATTERNS
    // ========================================================================
    
    /**
     * Detect common payment-related patterns that need review
     * These are warnings because context matters
     */
    'no-warning-comments': ['warn', {
      terms: ['TODO: PCI', 'FIXME: payment', 'XXX: card', 'HACK: cvv', 'FIXME: PAN'],
      location: 'anywhere'
    }]
  },
  
  // ========================================================================
  // ENVIRONMENT-SPECIFIC OVERRIDES
  // ========================================================================
  
  overrides: [
    // Frontend/Browser code - strict client-side rules
    {
      files: ['**/client/**/*.js', '**/frontend/**/*.js', '**/public/**/*.js'],
      env: {
        browser: true,
        node: false
      },
      rules: {
        // Extra strict on client-side storage
        'no-restricted-globals': ['error', {
          name: 'localStorage',
          message: 'CRITICAL: Never store payment data in localStorage. This is a PCI DSS violation.'
        }, {
          name: 'sessionStorage',
          message: 'CRITICAL: Never store payment data in sessionStorage. This is a PCI DSS violation.'
        }, {
          name: 'indexedDB',
          message: 'WARNING: IndexedDB detected. Never store PAN, CVV, or SAD in IndexedDB.'
        }]
      }
    },
    
    // Test files - allow test card numbers
    {
      files: ['**/*.test.js', '**/*.spec.js', '**/tests/**/*.js', '**/fixtures/**/*.js'],
      rules: {
        'no-restricted-syntax': 'off'
      }
    }
  ]
};

/**
 * MANUAL CODE REVIEW CHECKLIST
 * ==============================
 * 
 * ESLint cannot detect all PCI DSS violations. Manual review required for:
 * 
 * A1.1 - Sensitive Authentication Data (SAD):
 *   [ ] CVV/CVC is never stored in database, files, or logs
 *   [ ] PIN is never handled in application code (use secure hardware)
 *   [ ] Full magnetic stripe data (track 1/track 2) is never stored
 *   [ ] SAD is used only transiently for authorization
 * 
 * A2.1 - PAN Encryption:
 *   [ ] PAN is encrypted before storage (AES-256 or tokenization)
 *   [ ] Encryption keys stored separately from encrypted data
 *   [ ] Keys managed via KMS (AWS KMS, Azure Key Vault, etc.)
 * 
 * A2.2 - PAN Masking:
 *   [ ] PAN display shows only first 6 and last 4 digits
 *   [ ] Masking applied in all UI components
 *   [ ] API responses mask PAN appropriately
 * 
 * A3.1 - Encryption in Transit:
 *   [ ] TLS 1.2+ for all cardholder data transmission
 *   [ ] Certificate validation enabled
 *   [ ] No plaintext transmission of CHD
 * 
 * A4.1 - Key Management:
 *   [ ] No hardcoded encryption keys (check with no-secrets plugin)
 *   [ ] Keys stored in KMS, not with encrypted data
 *   [ ] Key rotation procedures in place
 * 
 * A5.1 - Client-Side Storage:
 *   [ ] No PAN in localStorage
 *   [ ] No PAN in sessionStorage  
 *   [ ] No PAN in cookies (except encrypted tokens)
 *   [ ] No PAN in IndexedDB
 *   [ ] Service Worker cache doesn't store PAN
 * 
 * A6.1 - Logging:
 *   [ ] PAN never in application logs
 *   [ ] PAN never in error messages
 *   [ ] PAN never in debug output
 *   [ ] Analytics/monitoring doesn't capture PAN
 *   [ ] Search for: console.log, logger.info, etc. near payment code
 */

/**
 * PAYMENT DATA PATTERNS TO SEARCH FOR
 * =====================================
 * 
 * Use your editor's search to find these patterns and review manually:
 * 
 * 1. CVV/CVC Storage:
 *    Search: cvv|cvc|cav|cid (case-insensitive)
 *    Near: .save(|.insert(|INSERT INTO|UPDATE
 * 
 * 2. PIN Handling:
 *    Search: pin|pinBlock (case-insensitive)
 *    Anywhere in non-test code should be reviewed
 * 
 * 3. Track Data:
 *    Search: track1|track2|trackData|magneticStripe
 *    Near: storage or persistence operations
 * 
 * 4. PAN in Logs:
 *    Search: console.log|logger|log.info
 *    Near: card|pan|cardNumber|payment
 * 
 * 5. Client-Side Storage:
 *    Search: localStorage.setItem|sessionStorage.setItem
 *    Near: card|payment|pan
 * 
 * 6. Unencrypted PAN:
 *    Search: cardNumber|pan|card_number
 *    Near: .save(|INSERT INTO|fs.writeFile
 *    Verify encryption is applied before storage
 */

/**
 * TOKENIZATION PATTERN (RECOMMENDED)
 * ===================================
 * 
 * Instead of storing PAN, use tokenization:
 * 
 * Good pattern:
 *   const tokenResult = await paymentGateway.tokenize(cardNumber);
 *   localStorage.setItem('paymentToken', tokenResult.token); // OK - token, not PAN
 * 
 * Bad pattern:
 *   localStorage.setItem('cardNumber', cardNumber); // VIOLATION - PAN in storage
 * 
 * Scope reduction strategies:
 *   - Use hosted payment pages (Stripe Checkout, PayPal)
 *   - Use iframe solutions (Stripe Elements)
 *   - Tokenize immediately at point of capture
 *   - Never let PAN touch your server (SAQ A compliance)
 */
