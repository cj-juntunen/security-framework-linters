# PCI Secure Software Standard - Module B: Terminal Software

**Standard Version:** v1.2.1  
**Document Version:** 1.0  
**Last Updated:** 2024-11-19  
**Module Type:** Module B - Terminal Software Requirements

---

## Overview

This document contains code-level compliance rules for **Module B: Terminal Software** of the PCI Secure Software Standard (PCI SSS). These requirements apply specifically to payment software designed for deployment and operation on PCI-approved Point of Interaction (POI) devices.

### About This Module

Module B establishes security requirements for terminal software that runs on payment acceptance devices such as:
- Point-of-sale (POS) terminals
- Payment PIN entry devices (PED)
- Unattended payment terminals (UPT)
- Mobile POS (mPOS) devices
- Integrated payment terminals

These requirements are in addition to Core Requirements and Module A requirements, focusing on:
- Physical security controls
- PIN handling and protection
- Secure boot and firmware integrity
- Anti-tampering mechanisms
- Secure communications with payment networks
- Terminal authentication

### Applicability

This module applies to software if it:
- Runs on PCI PTS-approved POI devices
- Handles PIN entry and encryption
- Manages terminal configuration and keys
- Communicates directly with payment networks
- Controls terminal security features

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

- [B1. PIN Security](#b1-pin-security)
- [B2. Secure Boot and Firmware Integrity](#b2-secure-boot-and-firmware-integrity)
- [B3. Anti-Tampering Controls](#b3-anti-tampering-controls)
- [B4. Cryptographic Key Management](#b4-cryptographic-key-management)
- [B5. Terminal Authentication](#b5-terminal-authentication)
- [B6. Secure Communications](#b6-secure-communications)
- [B7. Terminal Configuration Security](#b7-terminal-configuration-security)

---

## B1. PIN Security

### Rule: PCI-SSS-B1.1 - PIN Block Encryption

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B1.1

#### Description
PIN blocks must be encrypted immediately upon entry using approved encryption methods. The PIN must never exist in clear text outside of the secure cryptographic device (SCD). PIN encryption must use:
- TDES (3DES) or AES encryption
- DUKPT (Derived Unique Key Per Transaction) key management
- Approved PIN block formats (ISO 9564)

#### Rationale
Unencrypted PINs represent the highest security risk in payment processing. PIN compromise allows complete account takeover and fraudulent withdrawals.

#### Detection Pattern
- **Languages:** C, C++, Java (embedded), Python
- **Pattern Type:** Cryptographic operations + PIN handling
- **Looks for:**
  - PIN variables without immediate encryption
  - PIN transmission without encryption
  - PIN stored in memory buffers
  - Weak encryption algorithms for PIN

#### Examples

##### Non-Compliant Code

```c
// C - CRITICAL VIOLATION: Unencrypted PIN handling
void process_pin_entry(char* pin_digits) {
    // VIOLATION - PIN in plaintext
    char pin_buffer[4];
    memcpy(pin_buffer, pin_digits, 4);
    
    // VIOLATION - sending unencrypted PIN
    send_to_host(pin_buffer);
    
    // VIOLATION - logging PIN
    log_debug("PIN entered: %s", pin_buffer);
}

// C - VIOLATION: Weak PIN encryption
void encrypt_pin_weak(char* pin) {
    // VIOLATION - XOR is not secure encryption
    for (int i = 0; i < 4; i++) {
        pin[i] ^= 0xAA;
    }
    transmit_pin(pin);
}
```

```java
// Java - VIOLATION: PIN in memory without encryption
public class PINPad {
    private String enteredPIN;  // VIOLATION - plaintext storage
    
    public void onPINDigit(char digit) {
        enteredPIN += digit;  // VIOLATION - builds plaintext PIN
        
        if (enteredPIN.length() == 4) {
            processPayment(enteredPIN);  // VIOLATION - transmitted without encryption
        }
    }
}

// Java - VIOLATION: Improper PIN block creation
public byte[] createPINBlock(String pin, String pan) {
    // VIOLATION - custom PIN block format (not ISO 9564)
    String combined = pin + pan.substring(pan.length() - 13);
    return combined.getBytes();
}
```

```python
# Python - VIOLATION: PIN handling in high-level language
def handle_pin_entry(pin_digits):
    # VIOLATION - PIN should never be in Python string
    pin = "".join(pin_digits)
    
    # VIOLATION - no encryption before transmission
    response = requests.post('https://processor.example.com/auth',
                           json={'pin': pin})
    return response.json()
```

##### Compliant Code

```c
// C - Compliant: Immediate PIN encryption in SCD
#include <openssl/evp.h>
#include <openssl/rand.h>

// PIN encryption happens in secure hardware module
int encrypt_pin_block(const unsigned char* pin_digits, 
                      size_t pin_len,
                      const unsigned char* pan,
                      unsigned char* encrypted_pin_block) {
    
    // Create ISO 9564 Format 0 PIN block
    unsigned char pin_block[8];
    
    // Control field: 0x0 + PIN length
    pin_block[0] = 0x00 | (pin_len & 0x0F);
    
    // PIN digits (padded with 0xF)
    for (int i = 0; i < 7; i++) {
        if (i < pin_len) {
            pin_block[i/2 + 1] |= (i % 2 == 0) ? 
                (pin_digits[i] << 4) : pin_digits[i];
        } else {
            pin_block[i/2 + 1] |= (i % 2 == 0) ? 0xF0 : 0x0F;
        }
    }
    
    // XOR with PAN (last 12 digits excluding check digit)
    unsigned char pan_block[8] = {0};
    // Extract and format PAN...
    
    for (int i = 0; i < 8; i++) {
        pin_block[i] ^= pan_block[i];
    }
    
    // Encrypt with DUKPT key in secure hardware
    // This happens in HSM/SCD, not in application code
    return hsm_encrypt_pin_block(pin_block, encrypted_pin_block);
    // COMPLIANT - encrypted in secure hardware
}

// Clear PIN from memory immediately
void secure_clear_pin(unsigned char* pin, size_t len) {
    volatile unsigned char* p = pin;
    while (len--) {
        *p++ = 0;
    }
}
```

```java
// Java - Compliant: PIN handled only in secure module
public class SecurePINPad {
    // PIN never stored as String or in application memory
    
    public void onPINDigit(byte digit) {
        // Send directly to secure PIN encryption device
        secureModule.addPINDigit(digit);  // COMPLIANT
        
        // Digit never stored in application memory
    }
    
    public EncryptedPINBlock getPINBlock() {
        // Retrieve already-encrypted PIN block from secure module
        return secureModule.getEncryptedPINBlock();  // COMPLIANT
    }
}

// Java - Compliant: ISO 9564 Format 0 PIN block
public class ISO9564PINBlock {
    private final SecureHardwareModule hsm;
    
    public byte[] createPINBlock(byte[] pin, String pan) {
        // PIN block creation happens in HSM, not application
        return hsm.createISO9564Format0(pin, pan);  // COMPLIANT
    }
}

// Java - Compliant: DUKPT key management
public class DUKPTKeyManager {
    private final SecurityModule securityModule;
    
    public EncryptedPINBlock encryptPIN(byte[] pinBlock) {
        // Get current DUKPT key from secure module
        DUKPTKey key = securityModule.getCurrentKey();
        
        // Encrypt in hardware
        byte[] encrypted = securityModule.encryptWithDUKPT(
            pinBlock, 
            key
        );  // COMPLIANT
        
        // Increment key counter for next transaction
        securityModule.incrementKeyCounter();
        
        return new EncryptedPINBlock(encrypted, key.getKeySerialNumber());
    }
}
```

```python
# Python - Compliant: No PIN handling in application layer
# Note: Terminal software should be in C/C++, not Python

# If Python must be used (e.g., for terminal management):
def request_pin_from_secure_module():
    """
    Application requests encrypted PIN block from secure hardware module.
    PIN never enters Python application space.
    """
    # COMPLIANT - PIN handled entirely in hardware
    encrypted_pin_block = secure_hardware.get_encrypted_pin_block()
    
    # Application only handles encrypted result
    return encrypted_pin_block

# Configuration only - never actual PIN handling
SECURE_PIN_CONFIG = {
    'encryption_algorithm': 'TDES',  # Or AES
    'key_management': 'DUKPT',
    'pin_block_format': 'ISO_9564_FORMAT_0',
    'minimum_pin_length': 4,
    'maximum_pin_length': 12
}
```

#### Remediation Steps
1. **Hardware requirement**: Implement secure cryptographic device (SCD)
2. **Immediate encryption**: Encrypt PIN within SCD immediately upon entry
3. **DUKPT implementation**: Use Derived Unique Key Per Transaction
4. **ISO 9564 compliance**: Use approved PIN block formats
5. **Memory protection**: Never allow PIN in application-accessible memory
6. **Testing**: Verify PIN never exists unencrypted outside SCD
7. **Certification**: Ensure PCI PTS POI certification

---

### Rule: PCI-SSS-B1.2 - PIN Entry Device Security

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B1.2

#### Description
PIN entry must occur only through secure, tamper-resistant hardware. The software must:
- Validate PED (PIN Entry Device) integrity before accepting PIN
- Detect and respond to tamper attempts
- Disable PIN acceptance if security compromised
- Implement timeout for PIN entry

#### Rationale
Compromised PIN entry devices can capture PINs before encryption. Software must verify hardware security before trusting PIN input.

#### Detection Pattern
- **Languages:** C, C++, Java (embedded)
- **Pattern Type:** Hardware validation + State checking
- **Looks for:**
  - PIN acceptance without hardware validation
  - Missing tamper detection checks
  - No timeout implementation
  - Bypassed security checks

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: No hardware validation
void accept_pin_entry() {
    char pin[MAX_PIN_LENGTH];
    
    // VIOLATION - accepting PIN without checking device security
    for (int i = 0; i < 4; i++) {
        pin[i] = read_keypad();
    }
    
    process_pin(pin);
}

// C - VIOLATION: No tamper detection
void initialize_pin_pad() {
    // VIOLATION - no tamper checks
    enable_keypad();
    
    // VIOLATION - no timeout set
    accept_pin_entry();
}
```

```java
// Java - VIOLATION: Bypassing security checks
public class PINEntryService {
    private boolean debugMode = false;
    
    public void acceptPIN() {
        if (debugMode) {
            // VIOLATION - bypassing security in debug mode
            processPINUnsafe();
            return;
        }
        
        // Normal processing
        processPINSecure();
    }
}
```

##### Compliant Code

```c
// C - Compliant: Hardware validation before PIN acceptance
typedef enum {
    PED_STATUS_SECURE,
    PED_STATUS_TAMPERED,
    PED_STATUS_UNINITIALIZED,
    PED_STATUS_ERROR
} PEDStatus;

PEDStatus validate_ped_security() {
    // Check tamper-evident seals
    if (!check_physical_tamper_detection()) {
        return PED_STATUS_TAMPERED;
    }
    
    // Verify firmware signature
    if (!verify_firmware_integrity()) {
        return PED_STATUS_TAMPERED;
    }
    
    // Check secure element status
    if (!secure_element_operational()) {
        return PED_STATUS_ERROR;
    }
    
    return PED_STATUS_SECURE;  // COMPLIANT
}

int accept_pin_entry_secure(EncryptedPINBlock* output) {
    // COMPLIANT - validate hardware before accepting PIN
    PEDStatus status = validate_ped_security();
    
    if (status != PED_STATUS_SECURE) {
        log_security_event("PED security check failed: %d", status);
        disable_pin_entry();
        return ERROR_DEVICE_COMPROMISED;
    }
    
    // Set timeout for PIN entry
    set_pin_entry_timeout(30);  // 30 seconds
    
    // Accept PIN only if hardware is secure
    int result = secure_hardware_get_pin(output);
    
    // Clear timeout
    clear_pin_entry_timeout();
    
    return result;  // COMPLIANT
}

// Tamper detection interrupt handler
void tamper_detected_handler() {
    // Immediately disable all crypto operations
    disable_secure_operations();
    
    // Zeroize all keys
    zeroize_all_keys();
    
    // Set tamper flag
    set_tamper_flag();
    
    // Log event
    log_critical_event("TAMPER DETECTED");
    
    // COMPLIANT - device locked until service
}
```

```java
// Java - Compliant: Comprehensive security checks
public class SecurePINEntry {
    private final HardwareSecurityModule hsm;
    private final TamperDetection tamperDetector;
    private static final int PIN_ENTRY_TIMEOUT_MS = 30000;
    
    public Result<EncryptedPINBlock> acceptPIN() throws SecurityException {
        // COMPLIANT - verify device security first
        DeviceStatus status = validateDeviceSecurity();
        
        if (status != DeviceStatus.SECURE) {
            logSecurityEvent("Device not secure: " + status);
            lockDevice();
            throw new SecurityException("Device security compromised");
        }
        
        // Set timeout
        Future<EncryptedPINBlock> pinFuture = executor.submit(() -> {
            return hsm.capturePIN();
        });
        
        try {
            // COMPLIANT - timeout enforced
            EncryptedPINBlock pinBlock = pinFuture.get(
                PIN_ENTRY_TIMEOUT_MS, 
                TimeUnit.MILLISECONDS
            );
            
            return Result.success(pinBlock);
            
        } catch (TimeoutException e) {
            pinFuture.cancel(true);
            logEvent("PIN entry timeout");
            return Result.error("PIN entry timeout");
        }
    }
    
    private DeviceStatus validateDeviceSecurity() {
        // Check tamper detection sensors
        if (tamperDetector.isTampered()) {
            return DeviceStatus.TAMPERED;  // COMPLIANT
        }
        
        // Verify firmware signature
        if (!hsm.verifyFirmwareSignature()) {
            return DeviceStatus.FIRMWARE_INVALID;
        }
        
        // Check encryption keys loaded
        if (!hsm.areKeysLoaded()) {
            return DeviceStatus.KEYS_NOT_LOADED;
        }
        
        return DeviceStatus.SECURE;  // COMPLIANT
    }
    
    private void lockDevice() {
        hsm.disableAllOperations();
        tamperDetector.setLockState(true);
        // Device must be serviced to unlock
    }
}
```

#### Remediation Steps
1. **Pre-flight checks**: Validate PED security before each PIN entry session
2. **Tamper detection**: Implement hardware and software tamper detection
3. **Timeout enforcement**: Set and enforce PIN entry timeouts
4. **Fail-secure**: Disable operations if any security check fails
5. **Audit logging**: Log all security validation results
6. **Response procedures**: Define and implement tamper response
7. **Regular validation**: Periodic security checks during operation

---

## B2. Secure Boot and Firmware Integrity

### Rule: PCI-SSS-B2.1 - Firmware Signature Verification

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B2.1

#### Description
Terminal firmware must be cryptographically signed and verified before execution. The boot process must:
- Verify digital signature of all firmware components
- Use hardware-backed root of trust
- Prevent execution of unsigned or modified firmware
- Log all boot integrity checks

#### Rationale
Compromised firmware can bypass all security controls. Signature verification ensures only authorized firmware executes on the device.

#### Detection Pattern
- **Languages:** C, C++, Assembly
- **Pattern Type:** Boot sequence analysis
- **Looks for:**
  - Boot code without signature verification
  - Optional or bypassable signature checks
  - Weak signature algorithms
  - Missing chain of trust

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: No firmware signature verification
void boot_firmware() {
    // VIOLATION - loading firmware without verification
    load_firmware_from_flash(FIRMWARE_ADDRESS);
    
    // VIOLATION - jumping to firmware without checks
    jump_to_firmware(FIRMWARE_ADDRESS);
}

// C - VIOLATION: Optional signature verification
void boot_with_optional_check() {
    bool verify_signature = get_config_value("verify_firmware");
    
    if (verify_signature) {  // VIOLATION - optional check
        if (!check_firmware_signature()) {
            // VIOLATION - only warning, still boots
            log_warning("Firmware signature invalid");
        }
    }
    
    load_and_execute_firmware();
}

// C - VIOLATION: Weak signature algorithm
bool verify_firmware_weak() {
    uint32_t checksum = calculate_crc32(firmware_data);
    
    // VIOLATION - CRC is not cryptographic signature
    return checksum == expected_checksum;
}
```

##### Compliant Code

```c
// C - Compliant: Secure boot with signature verification
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

typedef struct {
    uint8_t signature[256];      // RSA-2048 signature
    uint32_t firmware_size;
    uint32_t firmware_version;
    uint8_t hash[32];            // SHA-256 hash
} FirmwareHeader;

// Hardware-backed public key (burned into OTP/ROM)
extern const uint8_t DEVICE_PUBLIC_KEY[256];

bool verify_firmware_signature_secure() {
    FirmwareHeader* header = (FirmwareHeader*)FIRMWARE_HEADER_ADDRESS;
    uint8_t* firmware = (uint8_t*)FIRMWARE_START_ADDRESS;
    
    // Calculate SHA-256 hash of firmware
    uint8_t calculated_hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, firmware, header->firmware_size);
    mbedtls_sha256_finish(&sha_ctx, calculated_hash);
    mbedtls_sha256_free(&sha_ctx);
    
    // Verify hash matches header
    if (memcmp(calculated_hash, header->hash, 32) != 0) {
        return false;
    }
    
    // Verify RSA signature
    mbedtls_rsa_context rsa;
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    
    // Import public key from hardware
    mbedtls_rsa_import_raw(&rsa,
                           DEVICE_PUBLIC_KEY, 256,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0,
                           NULL, 0);
    
    // Verify signature
    int result = mbedtls_rsa_pkcs1_verify(&rsa,
                                          NULL, NULL,
                                          MBEDTLS_RSA_PUBLIC,
                                          MBEDTLS_MD_SHA256,
                                          32,
                                          calculated_hash,
                                          header->signature);
    
    mbedtls_rsa_free(&rsa);
    
    return (result == 0);  // COMPLIANT - cryptographic verification
}

void secure_boot_sequence() {
    // COMPLIANT - mandatory signature verification
    log_boot_event("Starting secure boot");
    
    if (!verify_firmware_signature_secure()) {
        log_critical("Firmware signature verification FAILED");
        
        // COMPLIANT - halt if verification fails
        enter_safe_mode();
        lockdown_device();
        return;  // Never execute unverified firmware
    }
    
    log_boot_event("Firmware signature verified");
    
    // Additional integrity checks
    if (!verify_firmware_version()) {
        log_critical("Firmware version check failed");
        enter_safe_mode();
        return;
    }
    
    // Only now execute firmware
    execute_verified_firmware();  // COMPLIANT
}

void enter_safe_mode() {
    // Minimal functionality mode
    // - Display error message
    // - Allow firmware update only
    // - No payment processing
    disable_all_payment_operations();
    enable_firmware_update_mode();
}
```

```c
// C - Compliant: Chain of trust implementation
typedef enum {
    BOOT_STAGE_ROM,
    BOOT_STAGE_BOOTLOADER,
    BOOT_STAGE_FIRMWARE,
    BOOT_STAGE_APPLICATION
} BootStage;

bool verify_boot_chain() {
    BootStage current_stage = BOOT_STAGE_ROM;
    
    // Stage 1: ROM (immutable, hardware root of trust)
    // Verifies bootloader
    if (!verify_component_signature(BOOTLOADER_ADDRESS, 
                                    ROM_PUBLIC_KEY)) {
        return false;
    }
    current_stage = BOOT_STAGE_BOOTLOADER;
    log_boot_stage(current_stage);
    
    // Stage 2: Bootloader
    // Verifies firmware
    if (!verify_component_signature(FIRMWARE_ADDRESS,
                                    BOOTLOADER_PUBLIC_KEY)) {
        return false;
    }
    current_stage = BOOT_STAGE_FIRMWARE;
    log_boot_stage(current_stage);
    
    // Stage 3: Firmware
    // Verifies application
    if (!verify_component_signature(APPLICATION_ADDRESS,
                                    FIRMWARE_PUBLIC_KEY)) {
        return false;
    }
    current_stage = BOOT_STAGE_APPLICATION;
    log_boot_stage(current_stage);
    
    return true;  // COMPLIANT - complete chain verified
}
```

#### Remediation Steps
1. **Implement root of trust**: Use hardware-backed key storage
2. **Sign all firmware**: Use RSA-2048 or ECDSA-P256 minimum
3. **Verify before execute**: Never execute unverified code
4. **Chain of trust**: Each stage verifies next stage
5. **Fail-secure**: Halt device if verification fails
6. **Version checks**: Prevent downgrade attacks
7. **Logging**: Record all boot verification events

---

## B3. Anti-Tampering Controls

### Rule: PCI-SSS-B3.1 - Physical Tamper Detection

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B3.1

#### Description
Terminal software must monitor physical tamper detection sensors and respond appropriately. Required responses include:
- Immediate zeroization of cryptographic keys
- Disable all secure operations
- Log tamper event
- Require service intervention to restore
- Cannot be bypassed or disabled in software

#### Rationale
Physical tamper attempts indicate sophisticated attack. Device must render itself inoperable to protect keys and cardholder data.

#### Detection Pattern
- **Languages:** C, C++
- **Pattern Type:** Interrupt handlers + State management
- **Looks for:**
  - Missing tamper handlers
  - Inadequate tamper responses
  - Bypassable tamper detection
  - Keys not zeroized on tamper

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: Inadequate tamper response
void tamper_interrupt_handler() {
    // VIOLATION - only logging, no protective action
    log_warning("Tamper detected");
    
    // VIOLATION - continuing normal operation
    return;
}

// C - VIOLATION: Bypassable tamper detection
bool check_tamper_status() {
    if (debug_mode_enabled()) {
        // VIOLATION - tamper detection disabled in debug mode
        return false;
    }
    
    return read_tamper_sensor();
}

// C - VIOLATION: Keys not zeroized
void handle_tamper_event() {
    set_tamper_flag(true);
    display_error_message();
    
    // VIOLATION - keys still in memory
    // continue_operation();
}
```

##### Compliant Code

```c
// C - Compliant: Comprehensive tamper response
typedef struct {
    volatile bool tamper_detected;
    volatile bool keys_zeroized;
    volatile bool device_locked;
    uint32_t tamper_count;
    uint64_t tamper_timestamp;
} TamperState;

static TamperState tamper_state = {false, false, false, 0, 0};

// Tamper interrupt - highest priority
void __attribute__((interrupt)) tamper_interrupt_handler() {
    // COMPLIANT - immediate protective actions
    
    // 1. Set tamper flag (cannot be cleared by software)
    tamper_state.tamper_detected = true;
    write_tamper_flag_to_nvram(true);
    
    // 2. Immediately zeroize all cryptographic material
    zeroize_all_cryptographic_keys();
    zeroize_pin_encryption_keys();
    zeroize_master_keys();
    zeroize_session_keys();
    tamper_state.keys_zeroized = true;
    
    // 3. Disable all secure operations
    disable_pin_entry();
    disable_card_reading();
    disable_transaction_processing();
    disable_key_loading();
    tamper_state.device_locked = true;
    
    // 4. Log tamper event (if possible)
    tamper_state.tamper_count++;
    tamper_state.tamper_timestamp = get_secure_timestamp();
    log_critical_event_atomic("TAMPER DETECTED - DEVICE LOCKED");
    
    // 5. Visual/audio indication
    activate_tamper_indicator();
    sound_tamper_alarm();
    
    // Device now inoperable - requires service
    // COMPLIANT - comprehensive response
}

void zeroize_all_cryptographic_keys() {
    // Zeroize working key memory
    volatile uint8_t* key_memory = (volatile uint8_t*)KEY_STORAGE_ADDRESS;
    size_t key_memory_size = KEY_STORAGE_SIZE;
    
    // Multiple pass zeroization
    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < key_memory_size; i++) {
            key_memory[i] = 0x00;
        }
    }
    
    // Zeroize hardware security module
    hsm_zeroize_all_keys();
    
    // Clear key cache
    clear_key_cache();
    
    // COMPLIANT - thorough key destruction
}

// Startup check - device cannot boot if tampered
bool pre_boot_tamper_check() {
    // Check persistent tamper flag
    if (read_tamper_flag_from_nvram()) {
        // COMPLIANT - device stays locked
        display_message("DEVICE TAMPERED - SERVICE REQUIRED");
        enter_lockdown_mode();
        return false;  // Cannot proceed
    }
    
    // Check all tamper sensors
    if (read_physical_tamper_sensors() != SENSORS_SECURE) {
        trigger_tamper_response();
        return false;
    }
    
    // Check firmware integrity
    if (!verify_firmware_integrity()) {
        trigger_tamper_response();
        return false;
    }
    
    return true;  // COMPLIANT - all checks passed
}

void enter_lockdown_mode() {
    while(1) {
        // Infinite loop - device inoperable
        // Only way out is hardware service
        display_tamper_message();
        delay_ms(1000);
        
        // Check for authorized service tool connection
        if (service_tool_authenticated()) {
            // Only authorized service can restore
            handle_service_mode();
        }
    }
}
```

```c
// C - Compliant: Multi-layer tamper detection
typedef enum {
    TAMPER_NONE = 0,
    TAMPER_CASE_OPENED = (1 << 0),
    TAMPER_MESH_CUT = (1 << 1),
    TAMPER_VOLTAGE_ANOMALY = (1 << 2),
    TAMPER_TEMPERATURE_ANOMALY = (1 << 3),
    TAMPER_FREQUENCY_ANOMALY = (1 << 4),
    TAMPER_PROBE_DETECTED = (1 << 5)
} TamperType;

uint32_t monitor_tamper_sensors() {
    uint32_t tamper_flags = TAMPER_NONE;
    
    // Physical sensors
    if (case_opening_detected()) {
        tamper_flags |= TAMPER_CASE_OPENED;
    }
    
    if (tamper_mesh_broken()) {
        tamper_flags |= TAMPER_MESH_CUT;
    }
    
    // Environmental sensors
    float voltage = read_voltage_sensor();
    if (voltage < MIN_SAFE_VOLTAGE || voltage > MAX_SAFE_VOLTAGE) {
        tamper_flags |= TAMPER_VOLTAGE_ANOMALY;
    }
    
    float temperature = read_temperature_sensor();
    if (temperature < MIN_SAFE_TEMP || temperature > MAX_SAFE_TEMP) {
        tamper_flags |= TAMPER_TEMPERATURE_ANOMALY;
    }
    
    // Clock/frequency monitoring
    if (clock_glitch_detected()) {
        tamper_flags |= TAMPER_FREQUENCY_ANOMALY;
    }
    
    // Probing detection
    if (invasive_probe_detected()) {
        tamper_flags |= TAMPER_PROBE_DETECTED;
    }
    
    // COMPLIANT - any tamper triggers response
    if (tamper_flags != TAMPER_NONE) {
        trigger_tamper_response();
        log_tamper_details(tamper_flags);
    }
    
    return tamper_flags;
}
```

#### Remediation Steps
1. **Implement comprehensive sensors**: Multiple tamper detection methods
2. **Interrupt-driven response**: Immediate action on tamper detection
3. **Key zeroization**: Complete destruction of all cryptographic material
4. **Persistent state**: Tamper flag survives power cycles
5. **No bypass**: Tamper response cannot be disabled in software
6. **Service requirement**: Only authorized service can restore device
7. **Testing**: Regular tamper detection testing

---

## B4. Cryptographic Key Management

### Rule: PCI-SSS-B4.1 - Secure Key Loading and Storage

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B4.1

#### Description
Terminal cryptographic keys must be loaded and stored securely. Requirements include:
- Keys loaded only through secure authenticated channels
- Keys stored in hardware-protected memory (secure element)
- Key management procedures follow TR-31 or TR-34 standards
- Keys never exposed in clear text outside secure boundaries
- Support for remote key injection with mutual authentication

#### Rationale
Compromised key loading procedures allow attackers to inject their own keys, enabling complete control of encrypted transactions.

#### Detection Pattern
- **Languages:** C, C++
- **Pattern Type:** Key management operations
- **Looks for:**
  - Keys in plaintext memory
  - Insecure key loading procedures
  - Missing authentication for key loading
  - Keys not stored in secure element

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: Insecure key loading
void load_master_key(uint8_t* key_data) {
    // VIOLATION - key in plaintext memory
    uint8_t master_key[32];
    memcpy(master_key, key_data, 32);
    
    // VIOLATION - no authentication of key source
    store_key_in_memory(master_key);
}

// C - VIOLATION: Key storage in regular memory
typedef struct {
    uint8_t pin_key[16];      // VIOLATION - not in secure storage
    uint8_t mac_key[16];      // VIOLATION
    uint8_t master_key[32];   // VIOLATION
} KeyStorage;

KeyStorage terminal_keys;  // VIOLATION - accessible memory

// C - VIOLATION: No mutual authentication
int remote_key_loading(uint8_t* new_key) {
    // VIOLATION - accepting key without authentication
    load_key(new_key);
    return 0;
}
```

##### Compliant Code

```c
// C - Compliant: Secure key loading with TR-34
#include "secure_element.h"
#include "tr34_protocol.h"

typedef struct {
    uint8_t krd_id[16];           // Key Receiving Device ID
    uint8_t krd_certificate[512]; // KRD Certificate
    uint8_t krd_private_key;      // Reference to secure key (not actual key)
} SecureKeyContext;

// COMPLIANT - Keys only handled in secure element
int load_key_tr34(const uint8_t* encrypted_key_block,
                  size_t block_size,
                  const uint8_t* kdh_certificate,
                  size_t cert_size) {
    
    // 1. Validate Key Distribution Host (KDH) certificate
    if (!validate_certificate_chain(kdh_certificate, cert_size)) {
        log_error("Invalid KDH certificate");
        return ERROR_INVALID_CERTIFICATE;
    }
    
    // 2. Perform mutual authentication
    if (!perform_mutual_authentication(kdh_certificate)) {
        log_error("Mutual authentication failed");
        return ERROR_AUTH_FAILED;
    }
    
    // 3. Verify TR-34 key block format
    TR34KeyBlock* key_block = parse_tr34_key_block(encrypted_key_block, block_size);
    if (!key_block || !verify_tr34_integrity(key_block)) {
        log_error("Invalid TR-34 key block");
        return ERROR_INVALID_KEY_BLOCK;
    }
    
    // 4. Decrypt key block in secure element (never in application memory)
    // COMPLIANT - key decryption happens in hardware
    SecureKeyHandle key_handle = secure_element_decrypt_and_store_key(
        key_block,
        SE_KEY_STORAGE_PERMANENT,
        SE_KEY_TYPE_PIN_ENCRYPTION
    );
    
    if (key_handle == INVALID_KEY_HANDLE) {
        log_error("Key loading failed in secure element");
        return ERROR_KEY_LOAD_FAILED;
    }
    
    // 5. Verify key check value
    uint8_t kcv[3];
    secure_element_calculate_kcv(key_handle, kcv);
    
    if (memcmp(kcv, key_block->key_check_value, 3) != 0) {
        log_error("Key check value mismatch");
        secure_element_delete_key(key_handle);
        return ERROR_KCV_MISMATCH;
    }
    
    // 6. Log successful key load
    log_security_event("Key loaded successfully: KSN=%s", 
                      key_block->key_serial_number);
    
    return SUCCESS;  // COMPLIANT - key never in application memory
}

// COMPLIANT - Secure element API abstraction
SecureKeyHandle secure_element_decrypt_and_store_key(
    const TR34KeyBlock* encrypted_block,
    KeyStorageType storage_type,
    KeyType key_type) {
    
    // This function executes in secure element firmware
    // Application never sees plaintext key
    
    // 1. Decrypt using KRD private key (in secure element)
    uint8_t* plaintext_key = se_internal_decrypt(
        encrypted_block->encrypted_key,
        encrypted_block->key_length,
        SE_KRD_PRIVATE_KEY_SLOT
    );
    
    // 2. Store in secure key storage
    SecureKeyHandle handle = se_store_key(
        plaintext_key,
        key_type,
        storage_type
    );
    
    // 3. Immediately zeroize plaintext (still in secure element)
    se_zeroize(plaintext_key, encrypted_block->key_length);
    
    return handle;  // Only handle returned, never key material
}

// COMPLIANT - Key usage without exposure
int encrypt_pin_with_secure_key(SecureKeyHandle key_handle,
                                const uint8_t* pin_block,
                                uint8_t* encrypted_output) {
    
    // Encryption happens entirely in secure element
    // Application passes data in, gets encrypted data out
    // Key never leaves secure element
    
    return secure_element_encrypt(
        key_handle,
        pin_block,
        8,  // PIN block size
        encrypted_output,
        SE_ALGORITHM_TDES_CBC
    );  // COMPLIANT
}
```

```c
// C - Compliant: DUKPT key management
typedef struct {
    uint8_t bdk_id[4];           // Base Derivation Key ID
    SecureKeyHandle bdk_handle;  // Reference, not actual key
    uint64_t key_serial_number;  // KSN
    uint32_t transaction_counter;
} DUKPTContext;

// COMPLIANT - BDK stored and used only in secure element
int initialize_dukpt(const uint8_t* initial_ksn,
                    SecureKeyHandle bdk_handle) {
    
    DUKPTContext* ctx = allocate_dukpt_context();
    
    // Store only KSN and BDK reference
    ctx->bdk_handle = bdk_handle;  // COMPLIANT - not actual key
    memcpy(&ctx->key_serial_number, initial_ksn, 8);
    ctx->transaction_counter = 0;
    
    return SUCCESS;
}

// COMPLIANT - DUKPT key derivation in secure element
int dukpt_encrypt_pin(DUKPTContext* ctx,
                     const uint8_t* pin_block,
                     uint8_t* encrypted_output,
                     uint8_t* ksn_output) {
    
    // Current KSN
    memcpy(ksn_output, &ctx->key_serial_number, 8);
    memcpy(ksn_output + 8, &ctx->transaction_counter, 4);
    
    // Derive transaction key in secure element
    // Application never sees derived key
    SecureKeyHandle txn_key = secure_element_derive_dukpt_key(
        ctx->bdk_handle,
        ksn_output,
        12
    );  // COMPLIANT - derivation in hardware
    
    if (txn_key == INVALID_KEY_HANDLE) {
        return ERROR_KEY_DERIVATION_FAILED;
    }
    
    // Encrypt with derived key (in secure element)
    int result = secure_element_encrypt(
        txn_key,
        pin_block,
        8,
        encrypted_output,
        SE_ALGORITHM_TDES_CBC
    );
    
    // Delete transaction key (used once)
    secure_element_delete_key(txn_key);
    
    // Increment counter for next transaction
    ctx->transaction_counter++;
    
    // Check if key exhausted (max 1 million transactions)
    if (ctx->transaction_counter >= 1000000) {
        log_warning("DUKPT key exhausted - rekey required");
        return ERROR_KEY_EXHAUSTED;
    }
    
    return result;  // COMPLIANT
}
```

#### Remediation Steps
1. **Secure element required**: Keys must be in hardware-protected storage
2. **TR-34 implementation**: Use asymmetric key loading protocol
3. **Mutual authentication**: Verify both KDH and KRD identity
4. **Key wrapping**: Always encrypt keys during transfer
5. **Access controls**: Key usage limited to secure element operations
6. **Audit logging**: Log all key management operations
7. **Testing**: Verify keys never accessible outside secure element

---

## B5. Terminal Authentication

### Rule: PCI-SSS-B5.1 - Terminal Identity and Authentication

**Severity:** High  
**PCI SSS Reference:** Module B, Requirement B5.1

#### Description
Terminals must authenticate to payment networks and acquiring hosts. Authentication must include:
- Unique terminal identifier (TID)
- Terminal capability and configuration
- Cryptographic authentication using terminal credentials
- Protection against terminal cloning

#### Rationale
Unauthenticated terminals could be rogue devices inserted into the payment network to capture transactions or inject fraudulent transactions.

#### Detection Pattern
- **Languages:** C, C++, Java
- **Pattern Type:** Authentication flows
- **Looks for:**
  - Missing terminal authentication
  - Weak authentication methods
  - Cloneable terminal identifiers
  - Unencrypted terminal credentials

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: Static terminal ID without authentication
#define TERMINAL_ID "T123456789"

void connect_to_host() {
    // VIOLATION - sending TID without authentication
    send_message("CONNECT", TERMINAL_ID);
    
    // VIOLATION - no cryptographic proof of identity
    wait_for_response();
}

// C - VIOLATION: Cloneable terminal credentials
typedef struct {
    char terminal_id[16];
    char password[32];  // VIOLATION - static password
} TerminalCredentials;

int authenticate_terminal(TerminalCredentials* creds) {
    // VIOLATION - password-based auth (cloneable)
    return send_credentials(creds->terminal_id, creds->password);
}
```

##### Compliant Code

```c
// C - Compliant: Certificate-based terminal authentication
typedef struct {
    uint8_t terminal_id[16];
    SecureKeyHandle device_private_key;  // In secure element
    uint8_t device_certificate[2048];
    size_t certificate_length;
    uint8_t ca_certificate[2048];
    size_t ca_cert_length;
} SecureTerminalIdentity;

// COMPLIANT - Terminal authentication with certificate
int authenticate_terminal_secure(SecureTerminalIdentity* identity) {
    
    // 1. Generate random challenge from host
    uint8_t challenge[32];
    if (!receive_authentication_challenge(challenge, sizeof(challenge))) {
        return ERROR_NO_CHALLENGE;
    }
    
    // 2. Sign challenge with device private key (in secure element)
    uint8_t signature[256];
    int sig_len = secure_element_sign_data(
        identity->device_private_key,
        challenge,
        sizeof(challenge),
        signature,
        SE_SIGNATURE_RSA_2048_PSS
    );  // COMPLIANT - private key never leaves secure element
    
    if (sig_len < 0) {
        return ERROR_SIGNATURE_FAILED;
    }
    
    // 3. Send certificate and signature to host
    AuthenticationMessage msg;
    msg.terminal_id = identity->terminal_id;
    msg.certificate = identity->device_certificate;
    msg.certificate_length = identity->certificate_length;
    msg.signature = signature;
    msg.signature_length = sig_len;
    
    if (!send_authentication_response(&msg)) {
        return ERROR_SEND_FAILED;
    }
    
    // 4. Receive and verify host authentication
    uint8_t host_challenge[32];
    secure_random_bytes(host_challenge, sizeof(host_challenge));
    
    if (!verify_host_authentication(host_challenge, identity->ca_certificate)) {
        log_error("Host authentication failed");
        return ERROR_HOST_AUTH_FAILED;
    }
    
    log_info("Terminal authenticated successfully");
    return SUCCESS;  // COMPLIANT - mutual authentication
}

// COMPLIANT - Terminal capabilities in authentication
typedef struct {
    uint8_t emv_support;
    uint8_t contactless_support;
    uint8_t pin_entry_capability;
    uint8_t crypto_capability;
    char firmware_version[32];
    uint8_t pci_approval_number[16];
} TerminalCapabilities;

int send_terminal_registration(SecureTerminalIdentity* identity,
                               TerminalCapabilities* capabilities) {
    
    // Create signed capability statement
    uint8_t capability_data[256];
    size_t data_len = serialize_capabilities(capabilities, capability_data);
    
    // Sign capabilities with device key
    uint8_t signature[256];
    int sig_len = secure_element_sign_data(
        identity->device_private_key,
        capability_data,
        data_len,
        signature,
        SE_SIGNATURE_RSA_2048_PSS
    );
    
    // Send registration request
    RegistrationRequest req;
    req.terminal_id = identity->terminal_id;
    req.certificate = identity->device_certificate;
    req.capabilities = capability_data;
    req.capabilities_length = data_len;
    req.signature = signature;
    req.signature_length = sig_len;
    
    return send_registration_request(&req);  // COMPLIANT
}
```

```java
// Java - Compliant: Terminal attestation
public class TerminalAuthenticationService {
    private final SecureElement secureElement;
    private final CertificateManager certificateManager;
    
    public boolean authenticateToHost(String hostAddress) {
        try {
            // 1. Establish TLS connection with client certificate
            SSLContext sslContext = createMutualTLSContext();
            SSLSocket socket = (SSLSocket) sslContext
                .getSocketFactory()
                .createSocket(hostAddress, 443);
            
            // 2. Send terminal attestation
            TerminalAttestation attestation = createAttestation();
            sendAttestation(socket, attestation);
            
            // 3. Receive and verify host response
            HostResponse response = receiveHostResponse(socket);
            
            if (!verifyHostResponse(response)) {
                logger.error("Host verification failed");
                return false;
            }
            
            // 4. Complete authentication handshake
            completeHandshake(socket);
            
            logger.info("Terminal authenticated successfully");
            return true;  // COMPLIANT
            
        } catch (Exception e) {
            logger.error("Authentication failed", e);
            return false;
        }
    }
    
    private TerminalAttestation createAttestation() {
        // COMPLIANT - attestation includes device identity proof
        TerminalAttestation attestation = new TerminalAttestation();
        
        // Terminal information
        attestation.setTerminalId(getTerminalId());
        attestation.setFirmwareVersion(getFirmwareVersion());
        attestation.setCapabilities(getTerminalCapabilities());
        
        // Cryptographic proof
        byte[] nonce = generateNonce();
        byte[] attestationData = serializeAttestationData(attestation);
        
        // Sign with device private key (in secure element)
        byte[] signature = secureElement.sign(
            attestationData,
            SignatureAlgorithm.RSA_2048_PSS_SHA256
        );
        
        attestation.setNonce(nonce);
        attestation.setSignature(signature);
        attestation.setCertificate(certificateManager.getDeviceCertificate());
        
        return attestation;  // COMPLIANT
    }
    
    private SSLContext createMutualTLSContext() throws Exception {
        // COMPLIANT - mutual TLS with device certificate
        KeyStore keyStore = secureElement.getKeyStore();
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, null);  // Password handled by secure element
        
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        tmf.init(certificateManager.getTrustedCACertificates());
        
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
        sslContext.init(
            kmf.getKeyManagers(),
            tmf.getTrustManagers(),
            new SecureRandom()
        );
        
        return sslContext;  // COMPLIANT - mutual authentication
    }
}
```

#### Remediation Steps
1. **Certificate-based authentication**: Use X.509 device certificates
2. **Secure element storage**: Private keys in tamper-resistant hardware
3. **Mutual authentication**: Verify both terminal and host identity
4. **Attestation**: Include terminal capabilities and firmware version
5. **Anti-cloning**: Unique device keys that cannot be extracted
6. **Certificate validation**: Verify certificate chain to trusted root
7. **Audit logging**: Log all authentication attempts

---

## B6. Secure Communications

### Rule: PCI-SSS-B6.1 - End-to-End Encryption to Payment Network

**Severity:** Critical  
**PCI SSS Reference:** Module B, Requirement B6.1

#### Description
All communication between terminal and payment network must be encrypted end-to-end. Requirements include:
- TLS 1.2 or higher with strong cipher suites
- Certificate pinning for known hosts
- Protection against man-in-the-middle attacks
- Encrypted message authentication

#### Rationale
Terminal communications carry sensitive payment data and must be protected from interception and modification at all network layers.

#### Detection Pattern
- **Languages:** C, C++, Java
- **Pattern Type:** Network communication analysis
- **Looks for:**
  - Unencrypted payment data transmission
  - Weak TLS configuration
  - Missing certificate validation
  - No message authentication

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: Unencrypted communication
int send_transaction_data(TransactionData* txn) {
    // VIOLATION - HTTP not HTTPS
    char url[256];
    sprintf(url, "http://acquiring-host.example.com/transaction");
    
    // VIOLATION - plaintext transmission
    return http_post(url, txn, sizeof(TransactionData));
}

// C - VIOLATION: Disabled certificate validation
void configure_tls_weak() {
    ssl_context_t ctx;
    ssl_init(&ctx);
    
    // VIOLATION - accepting any certificate
    ssl_set_verify(&ctx, SSL_VERIFY_NONE);
    
    ssl_connect(&ctx, "host.example.com", 443);
}
```

##### Compliant Code

```c
// C - Compliant: Secure TLS 1.3 communication
#include <openssl/ssl.h>
#include <openssl/err.h>

// COMPLIANT - Strong TLS configuration
SSL_CTX* create_secure_ssl_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    
    if (!ctx) {
        log_error("Failed to create SSL context");
        return NULL;
    }
    
    // Set minimum TLS version to 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    // Prefer TLS 1.3
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // Set strong cipher suites only
    const char* cipher_list = 
        "TLS_AES_256_GCM_SHA384:"
        "TLS_AES_128_GCM_SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256";
    
    if (!SSL_CTX_set_cipher_list(ctx, cipher_list)) {
        log_error("Failed to set cipher list");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // Load trusted CA certificates
    if (!SSL_CTX_load_verify_locations(ctx, CA_CERT_PATH, NULL)) {
        log_error("Failed to load CA certificates");
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    // COMPLIANT - Enable certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
                      verify_callback);
    
    // Enable hostname verification
    SSL_CTX_set_hostflags(ctx, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    
    return ctx;  // COMPLIANT
}

// COMPLIANT - Certificate pinning
typedef struct {
    char* hostname;
    uint8_t cert_sha256[32];
} PinnedCertificate;

static PinnedCertificate pinned_certs[] = {
    {"acquiring-host.example.com", {0x1a, 0x2b, /* ... */}},
    {"backup-host.example.com", {0x3c, 0x4d, /* ... */}},
    {NULL, {0}}
};

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {
    if (!preverify_ok) {
        return 0;  // Standard verification failed
    }
    
    X509* cert = X509_STORE_CTX_get_current_cert(ctx);
    SSL* ssl = X509_STORE_CTX_get_ex_data(ctx, 
                  SSL_get_ex_data_X509_STORE_CTX_idx());
    
    const char* hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    
    // Calculate certificate fingerprint
    uint8_t fingerprint[32];
    unsigned int len = sizeof(fingerprint);
    X509_digest(cert, EVP_sha256(), fingerprint, &len);
    
    // Check against pinned certificates
    for (int i = 0; pinned_certs[i].hostname != NULL; i++) {
        if (strcmp(hostname, pinned_certs[i].hostname) == 0) {
            if (memcmp(fingerprint, pinned_certs[i].cert_sha256, 32) == 0) {
                log_info("Certificate pinning validated for %s", hostname);
                return 1;  // COMPLIANT - pinned cert matched
            } else {
                log_critical("Certificate pinning failed for %s", hostname);
                return 0;  // COMPLIANT - reject non-pinned cert
            }
        }
    }
    
    log_warning("No pinned certificate for %s", hostname);
    return 1;  // Accept if not in pinned list (optional)
}

// COMPLIANT - Secure transaction transmission
int send_transaction_secure(TransactionData* txn, SSL_CTX* ssl_ctx) {
    SSL* ssl = NULL;
    BIO* bio = NULL;
    int result = -1;
    
    // Create secure connection
    bio = BIO_new_ssl_connect(ssl_ctx);
    if (!bio) {
        log_error("Failed to create BIO");
        goto cleanup;
    }
    
    BIO_get_ssl(bio, &ssl);
    if (!ssl) {
        log_error("Failed to get SSL");
        goto cleanup;
    }
    
    // Set hostname for SNI and certificate verification
    SSL_set_tlsext_host_name(ssl, "acquiring-host.example.com");
    BIO_set_conn_hostname(bio, "acquiring-host.example.com:443");
    
    // Connect
    if (BIO_do_connect(bio) <= 0) {
        log_error("Failed to connect: %s", 
                 ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    // Verify connection established securely
    if (BIO_do_handshake(bio) <= 0) {
        log_error("TLS handshake failed");
        goto cleanup;
    }
    
    // Verify certificate
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        log_error("Certificate verification failed");
        goto cleanup;
    }
    
    // Serialize and send transaction
    uint8_t txn_buffer[4096];
    size_t txn_len = serialize_transaction(txn, txn_buffer, sizeof(txn_buffer));
    
    if (BIO_write(bio, txn_buffer, txn_len) <= 0) {
        log_error("Failed to send transaction");
        goto cleanup;
    }
    
    // Receive response
    uint8_t response_buffer[4096];
    int bytes_read = BIO_read(bio, response_buffer, sizeof(response_buffer));
    
    if (bytes_read > 0) {
        result = process_transaction_response(response_buffer, bytes_read);
    }
    
cleanup:
    if (bio) BIO_free_all(bio);
    return result;  // COMPLIANT - encrypted end-to-end
}
```

```java
// Java - Compliant: Secure payment network communication
public class SecurePaymentNetworkClient {
    private static final String[] STRONG_CIPHER_SUITES = {
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    };
    
    private final SSLContext sslContext;
    private final CertificatePinner certificatePinner;
    
    public SecurePaymentNetworkClient() throws Exception {
        this.sslContext = createSecureSSLContext();
        this.certificatePinner = new CertificatePinner();
    }
    
    private SSLContext createSecureSSLContext() throws Exception {
        // COMPLIANT - TLS 1.3 with strong ciphers
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        
        // Load trusted certificates
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(new FileInputStream(TRUST_STORE_PATH),
                       TRUST_STORE_PASSWORD);
        
        TrustManagerFactory tmf = 
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        
        context.init(null, tmf.getTrustManagers(), new SecureRandom());
        
        return context;  // COMPLIANT
    }
    
    public TransactionResponse sendTransaction(Transaction txn, String host) 
            throws IOException {
        
        URL url = new URL("https://" + host + "/transaction");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        
        // COMPLIANT - Configure secure connection
        conn.setSSLSocketFactory(sslContext.getSocketFactory());
        conn.setHostnameVerifier(new StrictHostnameVerifier());
        
        // Set allowed cipher suites
        SSLSocketFactory factory = (SSLSocketFactory) conn.getSSLSocketFactory();
        SSLSocket socket = (SSLSocket) factory.createSocket();
        socket.setEnabledCipherSuites(STRONG_CIPHER_SUITES);
        
        // Set request properties
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        
        // Send transaction data
        try (OutputStream os = conn.getOutputStream()) {
            byte[] txnData = serializeTransaction(txn);
            os.write(txnData);
            os.flush();
        }
        
        // Verify certificate pinning
        Certificate[] certs = conn.getServerCertificates();
        if (!certificatePinner.verify(host, certs)) {
            throw new SecurityException("Certificate pinning failed");
        }
        
        // Read response
        try (InputStream is = conn.getInputStream()) {
            return parseResponse(is);
        }
        // COMPLIANT - end-to-end encryption with validation
    }
}
```

#### Remediation Steps
1. **TLS 1.2 minimum**: Configure TLS 1.2 or 1.3 only
2. **Strong ciphers**: Use only approved cipher suites
3. **Certificate validation**: Always verify server certificates
4. **Certificate pinning**: Pin certificates for known payment hosts
5. **Hostname verification**: Validate certificate matches hostname
6. **No downgrades**: Prevent protocol downgrade attacks
7. **Testing**: Regular SSL/TLS configuration testing

---

## B7. Terminal Configuration Security

### Rule: PCI-SSS-B7.1 - Secure Configuration Management

**Severity:** High  
**PCI SSS Reference:** Module B, Requirement B7.1

#### Description
Terminal configuration must be protected from unauthorized modification. Requirements include:
- Configuration stored encrypted or integrity-protected
- Configuration changes require authentication
- Audit trail of all configuration changes
- Secure defaults that enforce security

#### Rationale
Tampered terminal configuration can disable security features, redirect transactions, or weaken cryptography.

#### Detection Pattern
- **Languages:** C, C++, Java
- **Pattern Type:** Configuration handling
- **Looks for:**
  - Plaintext configuration files
  - Unauthenticated configuration changes
  - Missing integrity checks
  - No audit logging

#### Examples

##### Non-Compliant Code

```c
// C - VIOLATION: Plaintext configuration
typedef struct {
    char terminal_id[16];
    char host_url[256];
    int pin_timeout;
    bool debug_mode;  // VIOLATION - dangerous setting
} TerminalConfig;

void load_config() {
    FILE* f = fopen("terminal.conf", "r");
    // VIOLATION - plaintext, no integrity check
    fread(&global_config, sizeof(TerminalConfig), 1, f);
    fclose(f);
}

// C - VIOLATION: No authentication for config changes
void update_config(TerminalConfig* new_config) {
    // VIOLATION - no authentication required
    memcpy(&global_config, new_config, sizeof(TerminalConfig));
    save_config();
}
```

##### Compliant Code

```c
// C - Compliant: Encrypted and authenticated configuration
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef struct {
    uint8_t version;
    char terminal_id[16];
    char host_url[256];
    uint16_t pin_timeout;
    uint8_t security_level;
    uint8_t reserved[64];
} TerminalConfigData;

typedef struct {
    uint32_t magic;              // 0x54435046 ("TCFG")
    uint32_t format_version;
    uint8_t iv[16];              // Initialization vector
    uint32_t encrypted_size;
    uint8_t hmac[32];            // HMAC-SHA256 for integrity
    uint8_t encrypted_data[512]; // Encrypted configuration
} SecureConfigFile;

// COMPLIANT - Load encrypted configuration
int load_secure_config(TerminalConfigData* config) {
    SecureConfigFile file_data;
    FILE* f = fopen(SECURE_CONFIG_PATH, "rb");
    
    if (!f) {
        log_error("Config file not found");
        return load_default_config(config);
    }
    
    if (fread(&file_data, sizeof(SecureConfigFile), 1, f) != 1) {
        fclose(f);
        log_error("Failed to read config file");
        return ERROR_READ_FAILED;
    }
    fclose(f);
    
    // Verify magic number
    if (file_data.magic != 0x54435046) {
        log_error("Invalid config file format");
        return ERROR_INVALID_FORMAT;
    }
    
    // Get configuration encryption key from secure element
    SecureKeyHandle config_key = secure_element_get_config_key();
    
    // Verify HMAC before decryption
    uint8_t calculated_hmac[32];
    uint8_t* hmac_key = get_hmac_key_from_secure_element();
    
    HMAC(EVP_sha256(),
         hmac_key,
         32,
         file_data.encrypted_data,
         file_data.encrypted_size,
         calculated_hmac,
         NULL);
    
    if (memcmp(calculated_hmac, file_data.hmac, 32) != 0) {
        log_critical("Config file integrity check failed");
        return ERROR_INTEGRITY_FAILED;  // COMPLIANT - reject tampered config
    }
    
    // Decrypt configuration
    uint8_t decrypted[512];
    int decrypted_len = secure_element_decrypt(
        config_key,
        file_data.encrypted_data,
        file_data.encrypted_size,
        file_data.iv,
        decrypted,
        SE_ALGORITHM_AES_256_CBC
    );
    
    if (decrypted_len < 0) {
        log_error("Config decryption failed");
        return ERROR_DECRYPTION_FAILED;
    }
    
    // Parse and validate configuration
    memcpy(config, decrypted, sizeof(TerminalConfigData));
    
    if (!validate_config(config)) {
        log_error("Invalid configuration values");
        return ERROR_INVALID_CONFIG;
    }
    
    log_info("Configuration loaded successfully");
    return SUCCESS;  // COMPLIANT - encrypted with integrity check
}

// COMPLIANT - Authenticated configuration update
int update_config_secure(TerminalConfigData* new_config,
                        const uint8_t* admin_signature,
                        size_t sig_len) {
    
    // 1. Validate new configuration
    if (!validate_config(new_config)) {
        log_error("Configuration validation failed");
        return ERROR_INVALID_CONFIG;
    }
    
    // 2. Verify administrator signature
    uint8_t config_hash[32];
    SHA256((uint8_t*)new_config, sizeof(TerminalConfigData), config_hash);
    
    if (!verify_admin_signature(config_hash, admin_signature, sig_len)) {
        log_security_event("Unauthorized config change attempt");
        return ERROR_UNAUTHORIZED;  // COMPLIANT - authentication required
    }
    
    // 3. Log configuration change
    log_config_change(get_current_config(), new_config);
    
    // 4. Encrypt and save
    SecureConfigFile file_data;
    file_data.magic = 0x54435046;
    file_data.format_version = 1;
    
    // Generate random IV
    secure_random_bytes(file_data.iv, 16);
    
    // Get encryption key from secure element
    SecureKeyHandle config_key = secure_element_get_config_key();
    
    // Encrypt configuration
    file_data.encrypted_size = secure_element_encrypt(
        config_key,
        (uint8_t*)new_config,
        sizeof(TerminalConfigData),
        file_data.iv,
        file_data.encrypted_data,
        SE_ALGORITHM_AES_256_CBC
    );
    
    // Calculate HMAC
    uint8_t* hmac_key = get_hmac_key_from_secure_element();
    HMAC(EVP_sha256(),
         hmac_key,
         32,
         file_data.encrypted_data,
         file_data.encrypted_size,
         file_data.hmac,
         NULL);
    
    // Save to file
    FILE* f = fopen(SECURE_CONFIG_PATH, "wb");
    if (!f) {
        log_error("Failed to open config file for writing");
        return ERROR_WRITE_FAILED;
    }
    
    fwrite(&file_data, sizeof(SecureConfigFile), 1, f);
    fclose(f);
    
    log_info("Configuration updated successfully");
    return SUCCESS;  // COMPLIANT - authenticated and encrypted
}

// COMPLIANT - Configuration validation
bool validate_config(TerminalConfigData* config) {
    // Check version
    if (config->version > CURRENT_CONFIG_VERSION) {
        log_error("Unsupported config version: %d", config->version);
        return false;
    }
    
    // Validate terminal ID format
    if (!is_valid_terminal_id(config->terminal_id)) {
        log_error("Invalid terminal ID");
        return false;
    }
    
    // Validate host URL
    if (!is_valid_url(config->host_url)) {
        log_error("Invalid host URL");
        return false;
    }
    
    // Validate timeout range
    if (config->pin_timeout < 30 || config->pin_timeout > 90) {
        log_error("Invalid PIN timeout: %d", config->pin_timeout);
        return false;
    }
    
    // Validate security level
    if (config->security_level < MINIMUM_SECURITY_LEVEL) {
        log_error("Security level too low");
        return false;  // COMPLIANT - enforce minimum security
    }
    
    return true;
}

// COMPLIANT - Audit logging for configuration changes
void log_config_change(TerminalConfigData* old_config,
                      TerminalConfigData* new_config) {
    
    AuditLogEntry entry;
    entry.timestamp = get_secure_timestamp();
    entry.event_type = EVENT_CONFIG_CHANGE;
    entry.user_id = get_current_admin_id();
    
    // Log specific changes
    if (strcmp(old_config->host_url, new_config->host_url) != 0) {
        snprintf(entry.details, sizeof(entry.details),
                "Host URL changed from %s to %s",
                old_config->host_url,
                new_config->host_url);
        write_audit_log(&entry);
    }
    
    if (old_config->pin_timeout != new_config->pin_timeout) {
        snprintf(entry.details, sizeof(entry.details),
                "PIN timeout changed from %d to %d",
                old_config->pin_timeout,
                new_config->pin_timeout);
        write_audit_log(&entry);
    }
    
    if (old_config->security_level != new_config->security_level) {
        snprintf(entry.details, sizeof(entry.details),
                "Security level changed from %d to %d",
                old_config->security_level,
                new_config->security_level);
        write_audit_log(&entry);
    }
    
    // COMPLIANT - comprehensive audit trail
}

// COMPLIANT - Secure defaults
TerminalConfigData get_default_config() {
    TerminalConfigData config = {0};
    
    config.version = CURRENT_CONFIG_VERSION;
    strcpy(config.terminal_id, "UNCONFIGURED");
    strcpy(config.host_url, "https://secure-default-host.example.com");
    config.pin_timeout = 30;              // Conservative default
    config.security_level = MAX_SECURITY; // Most secure default
    
    return config;  // COMPLIANT - secure by default
}
```

```java
// Java - Compliant: Secure configuration management
public class SecureConfigurationManager {
    private static final String CONFIG_FILE = "terminal_config.enc";
    private static final int CURRENT_VERSION = 1;
    
    private final SecureElement secureElement;
    private final AuditLogger auditLogger;
    
    // COMPLIANT - Load encrypted configuration
    public TerminalConfiguration loadConfiguration() 
            throws ConfigurationException {
        
        File configFile = new File(CONFIG_FILE);
        if (!configFile.exists()) {
            logger.warn("Config file not found, using defaults");
            return getDefaultConfiguration();
        }
        
        try {
            // Read encrypted file
            byte[] encryptedData = Files.readAllBytes(configFile.toPath());
            
            // Parse header
            ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
            int magic = buffer.getInt();
            int version = buffer.getInt();
            
            if (magic != 0x54435046) {
                throw new ConfigurationException("Invalid config file");
            }
            
            // Read IV and encrypted data
            byte[] iv = new byte[16];
            buffer.get(iv);
            
            byte[] hmac = new byte[32];
            buffer.get(hmac);
            
            int dataLength = buffer.getInt();
            byte[] encrypted = new byte[dataLength];
            buffer.get(encrypted);
            
            // Verify HMAC
            byte[] calculatedHmac = calculateHMAC(encrypted);
            if (!MessageDigest.isEqual(hmac, calculatedHmac)) {
                auditLogger.logSecurityEvent(
                    "Configuration integrity check failed"
                );
                throw new ConfigurationException("Config integrity check failed");
            }
            
            // Decrypt in secure element
            byte[] decrypted = secureElement.decrypt(
                encrypted,
                iv,
                SecureElement.CONFIG_KEY_SLOT
            );
            
            // Deserialize and validate
            TerminalConfiguration config = deserializeConfig(decrypted);
            
            if (!validateConfiguration(config)) {
                throw new ConfigurationException("Invalid configuration");
            }
            
            logger.info("Configuration loaded successfully");
            return config;  // COMPLIANT
            
        } catch (IOException e) {
            throw new ConfigurationException("Failed to load config", e);
        }
    }
    
    // COMPLIANT - Authenticated configuration update
    public void updateConfiguration(
            TerminalConfiguration newConfig,
            byte[] adminSignature) throws ConfigurationException {
        
        // Validate configuration
        if (!validateConfiguration(newConfig)) {
            throw new ConfigurationException("Invalid configuration values");
        }
        
        // Verify administrator authentication
        byte[] configData = serializeConfig(newConfig);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(configData);
        
        if (!secureElement.verifySignature(
                hash,
                adminSignature,
                SecureElement.ADMIN_KEY_SLOT)) {
            
            auditLogger.logSecurityEvent(
                "Unauthorized configuration change attempt"
            );
            throw new SecurityException("Unauthorized configuration change");
        }
        
        // Log changes
        TerminalConfiguration oldConfig = loadConfiguration();
        auditLogger.logConfigurationChange(oldConfig, newConfig);
        
        // Encrypt and save
        try {
            // Generate random IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            
            // Encrypt in secure element
            byte[] encrypted = secureElement.encrypt(
                configData,
                iv,
                SecureElement.CONFIG_KEY_SLOT
            );
            
            // Calculate HMAC
            byte[] hmac = calculateHMAC(encrypted);
            
            // Build file structure
            ByteBuffer buffer = ByteBuffer.allocate(
                4 + 4 + 16 + 32 + 4 + encrypted.length
            );
            buffer.putInt(0x54435046);      // Magic
            buffer.putInt(CURRENT_VERSION); // Version
            buffer.put(iv);                 // IV
            buffer.put(hmac);               // HMAC
            buffer.putInt(encrypted.length);// Length
            buffer.put(encrypted);          // Data
            
            // Write to file with atomic replace
            Path tempFile = Files.createTempFile("config", ".tmp");
            Files.write(tempFile, buffer.array());
            Files.move(tempFile, Paths.get(CONFIG_FILE),
                      StandardCopyOption.ATOMIC_MOVE,
                      StandardCopyOption.REPLACE_EXISTING);
            
            logger.info("Configuration updated successfully");
            // COMPLIANT
            
        } catch (Exception e) {
            throw new ConfigurationException("Failed to save config", e);
        }
    }
    
    // COMPLIANT - Configuration validation
    private boolean validateConfiguration(TerminalConfiguration config) {
        // Version check
        if (config.getVersion() > CURRENT_VERSION) {
            logger.error("Unsupported config version");
            return false;
        }
        
        // Terminal ID validation
        if (!config.getTerminalId().matches("^[A-Z0-9]{8,16}$")) {
            logger.error("Invalid terminal ID format");
            return false;
        }
        
        // Host URL validation
        try {
            URL url = new URL(config.getHostUrl());
            if (!"https".equals(url.getProtocol())) {
                logger.error("Host URL must use HTTPS");
                return false;
            }
        } catch (MalformedURLException e) {
            logger.error("Invalid host URL");
            return false;
        }
        
        // PIN timeout validation
        if (config.getPinTimeout() < 30 || config.getPinTimeout() > 90) {
            logger.error("PIN timeout out of acceptable range");
            return false;
        }
        
        // Security level validation
        if (config.getSecurityLevel() < SecurityLevel.HIGH) {
            logger.error("Security level too low");
            return false;
        }
        
        return true;  // COMPLIANT - comprehensive validation
    }
    
    // COMPLIANT - Secure defaults
    private TerminalConfiguration getDefaultConfiguration() {
        return TerminalConfiguration.builder()
            .version(CURRENT_VERSION)
            .terminalId("UNCONFIGURED")
            .hostUrl("https://secure-default-host.example.com")
            .pinTimeout(30)
            .securityLevel(SecurityLevel.MAXIMUM)
            .debugMode(false)  // Never enabled by default
            .build();  // COMPLIANT - secure defaults
    }
}
```

#### Remediation Steps
1. **Encrypt configuration**: Use AES-256 for configuration files
2. **Integrity protection**: Add HMAC for tamper detection
3. **Authentication required**: Verify admin signature for changes
4. **Audit logging**: Log all configuration access and changes
5. **Validation**: Enforce valid ranges and formats
6. **Secure defaults**: Conservative security settings by default
7. **Version control**: Track configuration version changes

---

## Summary and Compliance Checklist

### Module B Requirements Coverage

**Terminal Software Security:**
- [x] B1.1: PIN block encryption (DUKPT/TDES/AES)
- [x] B1.2: PIN entry device security validation
- [x] B2.1: Firmware signature verification
- [x] B3.1: Physical tamper detection and response
- [x] B4.1: Secure key loading and storage
- [x] B5.1: Terminal authentication to network
- [x] B6.1: End-to-end encryption (TLS 1.2+)
- [x] B7.1: Secure configuration management

### Critical Security Controls for Terminal Software

**Hardware Requirements:**
- Secure Cryptographic Device (SCD) for PIN handling
- Tamper-resistant enclosure with sensors
- Secure element for key storage
- Hardware-backed root of trust

**Software Requirements:**
- Secure boot with signature verification
- Immediate tamper response with key zeroization
- Certificate-based authentication
- Encrypted configuration with integrity checks

### Implementation Priorities

**Phase 1 - Critical Hardware (Weeks 1-4):**
1. Implement secure element integration
2. Deploy tamper detection sensors
3. Establish hardware root of trust
4. Implement secure boot chain

**Phase 2 - PIN Security (Weeks 5-8):**
5. Integrate PIN encryption in SCD
6. Implement DUKPT key management
7. Add PIN timeout and validation
8. Test PIN never in application memory

**Phase 3 - Network Security (Weeks 9-12):**
9. Implement TLS 1.2+ with certificate pinning
10. Add terminal authentication
11. Deploy secure configuration management
12. Complete audit logging

**Phase 4 - Certification (Weeks 13-16):**
13. PCI PTS POI testing preparation
14. Third-party security assessment
15. Penetration testing
16. Certification submission

### Testing Requirements

**Security Testing:**
- [ ] PIN never accessible outside SCD
- [ ] Tamper detection triggers key zeroization
- [ ] Firmware signature verification prevents boot of unsigned code
- [ ] TLS connections use strong ciphers only
- [ ] Certificate pinning prevents MITM attacks
- [ ] Configuration changes require authentication
- [ ] All security events logged

**Penetration Testing:**
- [ ] Physical tamper attempts
- [ ] Firmware modification attempts
- [ ] Key extraction attempts
- [ ] Network interception tests
- [ ] Configuration tampering tests

### Certification Requirements

**PCI PTS POI Certification:**
- Hardware security evaluation
- PIN security testing
- Tamper resistance testing
- Cryptographic implementation review
- Secure software development lifecycle review

**Required Documentation:**
- Hardware security architecture
- Software security design
- Key management procedures
- Tamper response procedures
- Incident response plan

### Related Documentation

- **[Core Requirements](core-requirements.md)** - Base security requirements
- **[Module A: Account Data Protection](module-a-account-data.md)** - CHD protection
- **[Module C: Web Software](module-c-web.md)** - Web application requirements
- **[PCI DSS Overview](README.md)** - Framework structure and guidance

### Important Notes

**Language Considerations:**
- Terminal software should be written in C/C++ for security and performance
- High-level languages (Java, Python) acceptable only for non-critical components
- PIN handling must always be in secure hardware, never in application code

**Hardware Dependencies:**
- Many requirements cannot be met in software alone
- Secure element or HSM is mandatory for key storage
- Physical tamper detection requires hardware sensors
- Secure boot requires hardware root of trust

**Certification Process:**
- PCI PTS POI certification is mandatory for production deployment
- Certification takes 3-6 months typically
- Annual re-certification required
- Any firmware changes require re-certification

---

**Need help?** Open an issue or discussion in the main repository.

**Important:** This module requires PCI PTS POI certification for production use. Consult with QSA (Qualified Security Assessor) and approved test labs.
