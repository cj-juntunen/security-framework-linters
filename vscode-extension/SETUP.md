# VS Code Extension Setup Guide

**Project:** security-framework-linters VS Code Extension  
**Version:** 1.3.0  
**Created:** January 2025

This guide walks through setting up the VS Code extension development environment and integrating it with your existing Semgrep rules.

## Prerequisites

Make sure you have these installed before starting:

- Node.js 20.x or later
- npm 9.x or later
- Visual Studio Code 1.85.0 or later
- Git
- Semgrep (`pip install semgrep`)

Verify installations:

```bash
node --version
npm --version
code --version
semgrep --version
```

## Initial Setup

### 1. Create Extension Directory

In your main repository:

```bash
cd security-framework-linters
mkdir vscode-extension
cd vscode-extension
```

### 2. Install Dependencies

```bash
npm install
```

This installs all packages defined in `package.json`:
- TypeScript compiler and types
- VS Code extension API types
- Language Server Protocol libraries
- ESLint for code quality
- VSCE for packaging

### 3. Compile TypeScript

```bash
npm run compile
```

This compiles `src/extension.ts` and `src/server.ts` into JavaScript in the `out/` directory.

For continuous compilation during development:

```bash
npm run watch
```

## Development Workflow

### Running the Extension

1. Open the `vscode-extension` directory in VS Code
2. Press **F5** or select **Run > Start Debugging**
3. A new VS Code window opens with the extension loaded
4. Open a Python, JavaScript, or other supported file
5. Save the file to trigger a scan
6. Check the Problems panel (Ctrl+Shift+M) for violations

### Testing Commands

In the Extension Development Host window:

- Open Command Palette: **Ctrl+Shift+P** (Cmd+Shift+P on Mac)
- Try these commands:
  - `Security Linters: Scan Current File`
  - `Security Linters: Scan Entire Workspace`
  - `Security Linters: Show Output`

### Debugging

Set breakpoints in `src/extension.ts`:
- Click in the gutter next to line numbers
- Breakpoints pause execution when hit
- Inspect variables in the Debug sidebar
- Use Debug Console for runtime evaluation

View extension logs:
- Command Palette: `Security Linters: Show Output`
- Or open Output panel and select "Security Framework Linters"

## Integrating Your Semgrep Rules

The extension needs access to your existing Semgrep rules from the `frameworks/` directory.

### Option 1: Bundle Rules with Extension

For distribution, bundle rules directly:

1. Copy rule directories into the extension:

```bash
mkdir -p vscode-extension/frameworks
cp -r frameworks/pci-dss vscode-extension/frameworks/
cp -r frameworks/soc2 vscode-extension/frameworks/
```

2. Update `package.json` to include rules in the package:

```json
"files": [
  "out/**/*",
  "frameworks/**/*"
]
```

3. Modify `buildSemgrepArgs()` in `extension.ts` to reference bundled rules:

```typescript
const extensionPath = context.extensionPath;
const rulesPath = path.join(extensionPath, 'frameworks', framework, 'rules', module);
args.push('--config', rulesPath);
```

### Option 2: Reference Local Rules

For development, point to your local rules:

1. Open VS Code settings in the Extension Development Host
2. Set `Security Framework Linters: Rules Path` to your frameworks directory:

```json
{
  "securityFrameworkLinters.rulesPath": "/full/path/to/security-framework-linters/frameworks"
}
```

This lets you test rule changes immediately without rebuilding the extension.

### Option 3: Use Semgrep Registry

For public rules, use the Semgrep registry:

```typescript
args.push('--config', 'p/security-audit');
args.push('--config', 'p/cwe-top-25');
```

## Project Structure

```
vscode-extension/
├── src/
│   ├── extension.ts         # Main extension code
│   └── server.ts            # LSP server (future)
├── out/                     # Compiled JavaScript
├── frameworks/              # Bundled Semgrep rules (if using Option 1)
├── .vscode/
│   ├── launch.json         # Debug configurations
│   └── tasks.json          # Build tasks
├── package.json            # Extension manifest
├── tsconfig.json           # TypeScript config
├── README.md               # User documentation
└── CHANGELOG.md            # Version history
```

## Configuration Reference

### Extension Settings

Users can configure the extension in their VS Code settings:

```json
{
  "securityFrameworkLinters.semgrepPath": "semgrep",
  "securityFrameworkLinters.rulesPath": "",
  "securityFrameworkLinters.enabledFrameworks": ["pci-dss", "soc2"],
  "securityFrameworkLinters.enabledModules": {
    "pci-dss": [
      "account-data-protection",
      "cryptography-key-management",
      "access-control",
      "web-application-security"
    ],
    "soc2": ["security-common-criteria"]
  },
  "securityFrameworkLinters.scanOnSave": true,
  "securityFrameworkLinters.scanOnOpen": false,
  "securityFrameworkLinters.severityFilter": ["ERROR", "WARNING"],
  "securityFrameworkLinters.autoInstallSemgrep": true
}
```

### Per-Workspace Configuration

Add a `.vscode/settings.json` in test projects:

```json
{
  "securityFrameworkLinters.enabledFrameworks": ["pci-dss"],
  "securityFrameworkLinters.enabledModules": {
    "pci-dss": ["account-data-protection"]
  }
}
```

## Building for Distribution

### Package the Extension

Create a `.vsix` file for distribution:

```bash
npm run package
```

This creates `security-framework-linters-1.3.0.vsix` in the current directory.

### Install Locally

Test the packaged extension:

```bash
code --install-extension security-framework-linters-1.3.0.vsix
```

### Publish to VS Code Marketplace

1. Create a publisher account at https://marketplace.visualstudio.com/manage
2. Get a Personal Access Token from Azure DevOps
3. Login with VSCE:

```bash
npx vsce login <publisher-name>
```

4. Publish:

```bash
npm run deploy
```

Or manually:

```bash
npx vsce publish
```

## Testing

### Manual Testing Checklist

- [ ] Extension activates when opening supported files
- [ ] Scans run on file save (if enabled)
- [ ] Diagnostics appear in Problems panel
- [ ] Severity filtering works correctly
- [ ] Workspace scans complete without errors
- [ ] Commands execute from Command Palette
- [ ] Context menu items appear in editor
- [ ] Settings changes take effect immediately
- [ ] Output channel shows scan logs
- [ ] Semgrep installation prompt works

### Test with Sample Violations

Create test files with known violations:

**test-pci-cvv.py:**
```python
# Should trigger account-data-protection rule
cvv_code = "123"
card_cvv = request.form['cvv']
```

**test-hardcoded-key.js:**
```javascript
// Should trigger cryptography-key-management rule
const apiKey = "hardcoded-secret-key-12345";
const encryptionKey = "AES256-KEY-HARDCODED";
```

Save these files and verify violations appear in the Problems panel.

## Troubleshooting

### Extension Won't Activate

- Check that `activationEvents` in `package.json` match your file types
- Verify TypeScript compiled successfully (`npm run compile`)
- Look for errors in Help > Toggle Developer Tools > Console

### Semgrep Not Running

- Verify Semgrep is in PATH: `which semgrep`
- Check Output panel for stderr from Semgrep
- Try running Semgrep manually: `semgrep --config auto test.py`

### No Diagnostics Appearing

- Confirm rules path is correct in settings
- Check severity filter includes violations found
- Verify file language is supported in `isSupportedLanguage()`
- Review Semgrep output in the Output panel

### Performance Issues

- Disable `scanOnOpen` to reduce startup overhead
- Use targeted module selection instead of all frameworks
- Increase buffer size for large files in `execFileAsync` calls

## Next Steps: LSP Implementation

The `src/server.ts` file provides a foundation for Language Server Protocol integration. Future enhancements:

- Real-time validation as you type (not just on save)
- Hover documentation for rules and requirements
- Code actions for automatic fixes
- Quick fixes for common violations
- Inline security suggestions

LSP integration requires:
1. Implementing validation in `validateTextDocument()`
2. Adding hover provider for rule documentation
3. Creating code actions for fixes
4. Launching the server from `extension.ts`

This is planned for v1.4.0 but not essential for the initial release.

## Resources

- VS Code Extension API: https://code.visualstudio.com/api
- Language Server Protocol: https://microsoft.github.io/language-server-protocol/
- Semgrep CLI Reference: https://semgrep.dev/docs/cli-reference/
- Publishing Extensions: https://code.visualstudio.com/api/working-with-extensions/publishing-extension

## Getting Help

For issues specific to the extension:
- Check existing issues: https://github.com/cj-juntunen/security-framework-linters/issues
- Open a new issue with reproduction steps
- Include VS Code version, extension version, and Semgrep version

---

That's it. This setup should get you running with local development. The core integration is functional; the LSP work is optional enhancement for later.
