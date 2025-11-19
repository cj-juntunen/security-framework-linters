/**
 * ESLint Configuration for PCI DSS Secure Software Standard - Core Requirements
 * 
 * Framework: PCI SSS v1.2.1 - Core Requirements
 * Last Updated: 2025-11-19
 * Repository: https://github.com/cj-juntunen/security-framework-linters
 * 
 * Applies to: ALL payment software regardless of function or technology
 * 
 * Coverage:
 * - Input validation and injection prevention
 * - Output encoding and XSS prevention
 * - Authentication and access control
 * - Secure communications (TLS)
 * - Cryptographic key management
 * - Security logging
 * - Secure configuration
 * 
 * Usage:
 *   // .eslintrc.js
 *   module.exports = {
 *     extends: [
 *       './node_modules/security-framework-linters/rules/eslint/pci-dss-core.js'
 *     ]
 *   };
 * 
 * Required Plugins:
 *   npm install --save-dev eslint-plugin-security eslint-plugin-no-secrets
 */

module.exports = {
  env: {
    browser: true,
    node: true,
    es2021: true
  },
  
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: 'module',
    ecmaFeatures: {
      jsx: true
    }
  },
  
  plugins: [
    'security',
    'no-secrets'
  ],
  
  extends: [
    'eslint:recommended',
    'plugin:security/recommended'
  ],
  
  rules: {
    // ========================================================================
    // CORE-1.1: INPUT VALIDATION - Injection Prevention
    // ========================================================================
    
    /**
     * Prevent eval and related functions (command injection risk)
     * PCI SSS Core 1.1: All input must be validated
     */
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    
    /**
     * Prevent dangerous dynamic code execution
     */
    'no-script-url': 'error',
    
    /**
     * Detect SQL injection patterns
     * PCI SSS Core 1.1
     */
    'security/detect-sql-injection': 'error',
    
    /**
     * Detect command injection via child_process
     * PCI SSS Core 1.1
     */
    'security/detect-child-process': 'warn',
    
    /**
     * Detect non-literal require (code injection)
     * PCI SSS Core 1.1
     */
    'security/detect-non-literal-require': 'error',
    
    /**
     * Detect non-literal fs operations (path traversal)
     * PCI SSS Core 1.1
     */
    'security/detect-non-literal-fs-filename': 'warn',
    
    /**
     * Detect object injection
     * PCI SSS Core 1.1
     * Note: High false positive rate, but important for security
     */
    'security/detect-object-injection': 'warn',
    
    /**
     * Detect unsafe regex (ReDoS - Regular Expression Denial of Service)
     * PCI SSS Core 1.1
     */
    'security/detect-unsafe-regex': 'warn',
    
    // ========================================================================
    // CORE-1.2: OUTPUT ENCODING - XSS Prevention
    // ========================================================================
    
    /**
     * Note: XSS prevention requires eslint-plugin-no-unsanitized
     * Install: npm install --save-dev eslint-plugin-no-unsanitized
     * 
     * Then add to plugins: ['no-unsanitized']
     * And enable rules:
     *   'no-unsanitized/method': 'error',
     *   'no-unsanitized/property': 'error'
     * 
     * These rules detect:
     * - innerHTML assignments
     * - insertAdjacentHTML usage
     * - document.write/writeln
     */
    
    // ========================================================================
    // CORE-2.1: AUTHENTICATION - Password Requirements
    // ========================================================================
    
    /**
     * Password complexity is typically enforced server-side
     * Client-side validation is convenience, not security
     * 
     * Requirements:
     * - Minimum 12 characters (recommended), OR
     * - Minimum 8 characters with complexity
     */
    
    // ========================================================================
    // CORE-2.2: AUTHENTICATION - Multi-Factor Authentication
    // ========================================================================
    
    /**
     * MFA enforcement is typically implemented at framework/route level
     * Review authentication middleware for MFA requirements
     */
    
    // ========================================================================
    // CORE-3.1: SECURE COMMUNICATIONS - TLS Configuration
    // ========================================================================
    
    /**
     * TLS configuration happens at server/framework level
     * Ensure:
     * - TLS 1.2 minimum
     * - Certificate validation enabled
     * - Strong cipher suites
     * 
     * See documentation for Express/Fastify/Next.js configuration
     */
    
    // ========================================================================
    // CORE-4.1: CRYPTOGRAPHIC KEY MANAGEMENT
    // ========================================================================
    
    /**
     * Detect hardcoded secrets and API keys
     * PCI SSS Core 4.1: Keys must not be hardcoded
     */
    'no-secrets/no-secrets': ['error', {
      tolerance: 4.5,
      additionalRegexes: {
        'Basic Auth': 'Authorization:\\s*Basic\\s+[A-Za-z0-9+/=]+',
        'Bearer Token': 'Authorization:\\s*Bearer\\s+[A-Za-z0-9\\-._~+/]+=*',
        'API Key': '[aA][pP][iI]_?[kK][eE][yY].*[\'"][0-9a-zA-Z]{32,}[\'"]',
        'AWS Access Key': 'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': '[\'"][0-9a-zA-Z/+=]{40}[\'"]',
        'Private Key': '-----BEGIN\\s+(?:RSA|OPENSSH|DSA|EC)\\s+PRIVATE\\s+KEY-----',
        'Generic Secret': '[sS][eE][cC][rR][eE][tT].*[\'"][0-9a-zA-Z]{16,}[\'"]',
        'Stripe Key': 'sk_(?:live|test)_[0-9a-zA-Z]{24,}',
        'PayPal Token': 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}'
      }
    }],
    
    /**
     * Detect weak cryptographic functions
     * PCI SSS Core 4.1: Use strong cryptography
     */
    'security/detect-pseudoRandomBytes': 'error',
    
    /**
     * Detect insecure random for security purposes
     * PCI SSS Core 4.1: Use crypto.randomBytes, not Math.random
     */
    'security/detect-insecure-randomness': 'error',
    
    // ========================================================================
    // CORE-5.1: SECURITY LOGGING
    // ========================================================================
    
    /**
     * Restrict console usage (may expose sensitive data in logs)
     * PCI SSS Core 5.1: No sensitive data in logs
     * 
     * Allow console.warn and console.error for legitimate error reporting
     * Disallow console.log to prevent accidental sensitive data logging
     */
    'no-console': ['error', {
      allow: ['warn', 'error']
    }],
    
    /**
     * Detect debugger statements (must not be in production)
     * PCI SSS Core 7.1: Secure configuration
     */
    'no-debugger': 'error',
    
    /**
     * Detect alert/confirm/prompt (should not be in production)
     * PCI SSS Core 7.1
     */
    'no-alert': 'error',
    
    // ========================================================================
    // CORE-6.1: SOFTWARE UPDATES AND VULNERABILITY MANAGEMENT
    // ========================================================================
    
    /**
     * Use npm audit or yarn audit to detect vulnerable dependencies
     * Run regularly: npm audit --audit-level=moderate
     */
    
    // ========================================================================
    // CORE-7.1: SECURE CONFIGURATION
    // ========================================================================
    
    /**
     * Prevent use of deprecated or unsafe APIs
     */
    'no-deprecated-api': 'off', // Not a built-in rule, document below
    
    /**
     * Detect use of Buffer constructor (deprecated, use Buffer.from/Buffer.alloc)
     */
    'security/detect-buffer-noassert': 'error',
    
    /**
     * Detect possible timing attacks in string comparison
     * PCI SSS Core 4.1: Use constant-time comparison for secrets
     */
    'security/detect-possible-timing-attacks': 'warn',
    
    // ========================================================================
    // BEST PRACTICES
    // ========================================================================
    
    /**
     * Strict equality (prevents type coercion bugs)
     */
    'eqeqeq': ['error', 'always'],
    
    /**
     * Prevent accidental globals
     */
    'no-undef': 'error',
    
    /**
     * Prevent unused variables (code quality)
     */
    'no-unused-vars': ['warn', {
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_'
    }],
    
    /**
     * Require use strict in function scope
     */
    'strict': ['error', 'function'],
    
    /**
     * Prevent use of undeclared variables
     */
    'no-undef': 'error',
    
    /**
     * Prevent returning values from setters
     */
    'no-setter-return': 'error',
    
    /**
     * Prevent unreachable code
     */
    'no-unreachable': 'error',
    
    /**
     * Prevent use of variables before definition
     */
    'no-use-before-define': ['error', {
      functions: false,
      classes: true,
      variables: true
    }]
  },
  
  // ========================================================================
  // OVERRIDES FOR SPECIFIC ENVIRONMENTS
  // ========================================================================
  
  overrides: [
    // Test files can use console.log and have relaxed rules
    {
      files: ['**/*.test.js', '**/*.spec.js', '**/tests/**/*.js'],
      rules: {
        'no-console': 'off',
        'security/detect-object-injection': 'off',
        'security/detect-non-literal-fs-filename': 'off'
      }
    },
    
    // Configuration files
    {
      files: ['**/*.config.js', '**/webpack.config.js', '**/rollup.config.js'],
      rules: {
        'security/detect-non-literal-require': 'off'
      }
    }
  ]
};

/**
 * ADDITIONAL RECOMMENDED PLUGINS
 * ================================
 * 
 * For enhanced XSS protection:
 *   npm install --save-dev eslint-plugin-no-unsanitized
 *   plugins: ['no-unsanitized']
 *   rules: {
 *     'no-unsanitized/method': 'error',
 *     'no-unsanitized/property': 'error'
 *   }
 * 
 * For React applications:
 *   npm install --save-dev eslint-plugin-react eslint-plugin-react-hooks
 *   extends: ['plugin:react/recommended', 'plugin:react-hooks/recommended']
 *   rules: {
 *     'react/no-danger': 'error',
 *     'react/no-danger-with-children': 'error'
 *   }
 * 
 * For TypeScript:
 *   npm install --save-dev @typescript-eslint/eslint-plugin @typescript-eslint/parser
 *   parser: '@typescript-eslint/parser'
 *   plugins: ['@typescript-eslint']
 *   extends: ['plugin:@typescript-eslint/recommended']
 * 
 * For Node.js security:
 *   npm install --save-dev eslint-plugin-node
 *   extends: ['plugin:node/recommended']
 */

/**
 * USAGE EXAMPLES
 * ===============
 * 
 * Basic usage:
 *   // .eslintrc.js
 *   module.exports = {
 *     extends: ['./rules/eslint/pci-dss-core.js']
 *   };
 * 
 * With additional configurations:
 *   module.exports = {
 *     extends: [
 *       './rules/eslint/pci-dss-core.js',
 *       './rules/eslint/pci-dss-module-a.js'
 *     ],
 *     rules: {
 *       // Your custom overrides
 *     }
 *   };
 * 
 * Run ESLint:
 *   npx eslint .
 *   npx eslint . --fix
 *   npx eslint . --max-warnings 0
 */
