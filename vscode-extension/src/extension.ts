import * as vscode from 'vscode';
import * as path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import {
    LanguageClient,
    LanguageClientOptions,
    ServerOptions,
    TransportKind,
    ExecutableOptions,
    Executable
} from 'vscode-languageclient/node';

const execFileAsync = promisify(execFile);

let client: LanguageClient | undefined;

interface SemgrepLSPConfig {
    path?: string;
    scan?: {
        configuration?: string[];
        exclude?: string[];
        jobs?: number;
        maxMemory?: number;
        maxTargetBytes?: number;
    };
    metrics?: {
        enabled?: boolean;
    };
}

interface SemgrepFinding {
    check_id: string;
    path: string;
    start: {
        line: number;
        col: number;
    };
    end: {
        line: number;
        col: number;
    };
    extra: {
        message: string;
        severity: string;
        metadata?: {
            cwe?: string[];
            owasp?: string[];
            framework?: string;
            requirement?: string;
        };
    };
}

interface SemgrepOutput {
    results: SemgrepFinding[];
    errors: Array<{ message: string }>;
}

export function activate(context: vscode.ExtensionContext) {
    const outputChannel = vscode.window.createOutputChannel('Security Framework Linters');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('security-framework-linters');
    
    outputChannel.appendLine('Security Framework Linters extension activated');

    // Check if Semgrep is installed
    checkSemgrepInstallation(outputChannel).then(isInstalled => {
        if (isInstalled) {
            // Start the Language Server
            startLanguageServer(context, outputChannel);
        }
    });

    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.scanFile', () => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                scanFile(editor.document, diagnosticCollection, outputChannel);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.scanWorkspace', () => {
            scanWorkspace(diagnosticCollection, outputChannel);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.clearDiagnostics', () => {
            diagnosticCollection.clear();
            outputChannel.appendLine('Cleared all diagnostics');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.showOutput', () => {
            outputChannel.show();
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.installSemgrep', () => {
            installSemgrep(outputChannel);
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.showRuleDoc', async (range: vscode.Range) => {
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                await showRuleDocumentation(editor.document, range, outputChannel);
            }
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('securityFrameworkLinters.restartLSP', () => {
            restartLanguageServer(context, outputChannel);
        })
    );

    // Set up file watchers based on configuration
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    
    if (config.get('scanOnSave')) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument((document) => {
                if (isSupportedLanguage(document.languageId)) {
                    scanFile(document, diagnosticCollection, outputChannel);
                }
            })
        );
    }

    if (config.get('scanOnOpen')) {
        context.subscriptions.push(
            vscode.workspace.onDidOpenTextDocument((document) => {
                if (isSupportedLanguage(document.languageId)) {
                    scanFile(document, diagnosticCollection, outputChannel);
                }
            })
        );
    }

    context.subscriptions.push(diagnosticCollection);
    context.subscriptions.push(outputChannel);
}

async function startLanguageServer(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel
): Promise<void> {
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';
    
    outputChannel.appendLine('Starting Semgrep Language Server...');

    // Build the LSP configuration
    const lspConfig = buildLSPConfig(config);
    
    // Create server options
    const serverOptions: ServerOptions = {
        command: semgrepPath,
        args: ['lsp'],
        options: {
            env: {
                ...process.env,
                SEMGREP_SETTINGS_FILE: path.join(context.globalStorageUri.fsPath, 'semgrep-settings.yml')
            }
        }
    };

    // Define document selectors for supported languages
    const documentSelector = [
        { scheme: 'file', language: 'python' },
        { scheme: 'file', language: 'javascript' },
        { scheme: 'file', language: 'typescript' },
        { scheme: 'file', language: 'javascriptreact' },
        { scheme: 'file', language: 'typescriptreact' },
        { scheme: 'file', language: 'java' },
        { scheme: 'file', language: 'go' },
        { scheme: 'file', language: 'c' },
        { scheme: 'file', language: 'cpp' },
        { scheme: 'file', language: 'ruby' },
        { scheme: 'file', language: 'php' },
        { scheme: 'file', language: 'csharp' },
        { scheme: 'file', language: 'rust' },
        { scheme: 'file', language: 'kotlin' },
        { scheme: 'file', language: 'swift' }
    ];

    // Client options
    const clientOptions: LanguageClientOptions = {
        documentSelector,
        synchronize: {
            // Synchronize configuration changes
            configurationSection: 'securityFrameworkLinters',
            fileEvents: [
                vscode.workspace.createFileSystemWatcher('**/.semgrep.yml'),
                vscode.workspace.createFileSystemWatcher('**/.semgrep/**'),
                vscode.workspace.createFileSystemWatcher('**/semgrep.yml')
            ]
        },
        outputChannel,
        initializationOptions: lspConfig,
        middleware: {
            // Custom diagnostic handling
            handleDiagnostics: (uri, diagnostics, next) => {
                const enhancedDiagnostics = enhanceDiagnostics(diagnostics);
                next(uri, enhancedDiagnostics);
            },
            // Provide custom hover content
            provideHover: async (document, position, token, next) => {
                const hover = await next(document, position, token);
                if (hover) {
                    return enhanceHover(hover);
                }
                return hover;
            },
            // Handle code actions
            provideCodeActions: async (document, range, context, token, next) => {
                const actions = await next(document, range, context, token);
                return enhanceCodeActions(actions, document, range);
            }
        }
    };

    try {
        // Create and start the language client
        client = new LanguageClient(
            'securityFrameworkLinters',
            'Security Framework Linters',
            serverOptions,
            clientOptions
        );

        // Register client-side handlers
        context.subscriptions.push(
            client.onNotification('semgrep/scanComplete', (params: any) => {
                handleScanComplete(params, outputChannel);
            })
        );

        context.subscriptions.push(
            client.onNotification('semgrep/scanProgress', (params: any) => {
                handleScanProgress(params, outputChannel);
            })
        );

        // Start the client
        await client.start();
        
        outputChannel.appendLine('Semgrep Language Server started successfully');
        
        // Send initial configuration
        await client.sendNotification('workspace/didChangeConfiguration', {
            settings: lspConfig
        });

    } catch (error: any) {
        outputChannel.appendLine(`Failed to start Language Server: ${error.message}`);
        vscode.window.showErrorMessage(
            'Failed to start Semgrep Language Server. Check the output panel for details.'
        );
    }
}

function buildLSPConfig(config: vscode.WorkspaceConfiguration): SemgrepLSPConfig {
    const enabledFrameworks = config.get<string[]>('enabledFrameworks') || [];
    const enabledModules = config.get<any>('enabledModules') || {};
    const rulesPath = config.get<string>('rulesPath');
    
    const configPaths: string[] = [];
    
    // Add framework-specific rules
    if (rulesPath && rulesPath.trim() !== '') {
        configPaths.push(rulesPath);
    } else {
        enabledFrameworks.forEach(framework => {
            const modules = enabledModules[framework] || [];
            modules.forEach((module: string) => {
                configPaths.push(`frameworks/${framework}/rules/${module}/`);
            });
        });
    }

    // Fallback to auto config
    if (configPaths.length === 0) {
        configPaths.push('auto');
    }

    return {
        scan: {
            configuration: configPaths,
            exclude: [
                '.git',
                'node_modules',
                '__pycache__',
                '.venv',
                'venv',
                'build',
                'dist',
                '*.min.js'
            ],
            jobs: config.get<number>('maxJobs') || 4,
            maxMemory: config.get<number>('maxMemory') || 5000,
            maxTargetBytes: config.get<number>('maxTargetBytes') || 1000000
        },
        metrics: {
            enabled: config.get<boolean>('telemetryEnabled') || false
        }
    };
}

function enhanceDiagnostics(diagnostics: vscode.Diagnostic[]): vscode.Diagnostic[] {
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const severityFilter = config.get<string[]>('severityFilter') || ['ERROR', 'WARNING'];
    
    return diagnostics
        .filter(diag => {
            // Filter by severity based on configuration
            const severity = diagnosticSeverityToString(diag.severity);
            return severityFilter.includes(severity);
        })
        .map(diag => {
            // Enhance diagnostic with additional metadata
            const enhanced = new vscode.Diagnostic(
                diag.range,
                diag.message,
                diag.severity
            );
            
            enhanced.source = 'Security Framework Linters';
            enhanced.code = diag.code;
            
            // Add related information if available
            if (diag.relatedInformation) {
                enhanced.relatedInformation = diag.relatedInformation;
            }
            
            // Add tags for deprecated or unnecessary code
            if (diag.message.toLowerCase().includes('deprecated')) {
                enhanced.tags = [vscode.DiagnosticTag.Deprecated];
            }
            
            return enhanced;
        });
}

function diagnosticSeverityToString(severity: vscode.DiagnosticSeverity | undefined): string {
    switch (severity) {
        case vscode.DiagnosticSeverity.Error:
            return 'ERROR';
        case vscode.DiagnosticSeverity.Warning:
            return 'WARNING';
        case vscode.DiagnosticSeverity.Information:
            return 'INFO';
        case vscode.DiagnosticSeverity.Hint:
            return 'HINT';
        default:
            return 'WARNING';
    }
}

function enhanceHover(hover: vscode.Hover): vscode.Hover {
    // Enhance hover information with additional context
    if (hover.contents && hover.contents.length > 0) {
        const originalContent = hover.contents[0];
        
        if (typeof originalContent === 'string') {
            // Add visual separator and formatting
            const enhanced = new vscode.MarkdownString();
            enhanced.appendMarkdown('### Security Framework Linters\n\n');
            enhanced.appendMarkdown(originalContent);
            enhanced.appendMarkdown('\n\n---\n\n');
            enhanced.appendMarkdown('💡 *Click on the diagnostic for more details*');
            enhanced.isTrusted = true;
            
            return new vscode.Hover(enhanced, hover.range);
        }
    }
    
    return hover;
}

function enhanceCodeActions(
    actions: vscode.CodeAction[] | undefined,
    document: vscode.TextDocument,
    range: vscode.Range
): vscode.CodeAction[] {
    if (!actions) {
        return [];
    }
    
    // Add custom code actions for common patterns
    const customActions: vscode.CodeAction[] = [];
    
    // Add "Suppress with nosemgrep" action
    const suppressAction = new vscode.CodeAction(
        'Suppress this violation (nosemgrep)',
        vscode.CodeActionKind.QuickFix
    );
    
    const line = document.lineAt(range.start.line);
    const indentation = line.text.match(/^\s*/)?.[0] || '';
    const commentPrefix = getCommentPrefix(document.languageId);
    
    suppressAction.edit = new vscode.WorkspaceEdit();
    suppressAction.edit.insert(
        document.uri,
        new vscode.Position(range.start.line, 0),
        `${indentation}${commentPrefix} nosemgrep\n`
    );
    
    customActions.push(suppressAction);
    
    // Add "View rule documentation" action
    const docAction = new vscode.CodeAction(
        'View rule documentation',
        vscode.CodeActionKind.Empty
    );
    
    docAction.command = {
        command: 'securityFrameworkLinters.showRuleDoc',
        title: 'Show Rule Documentation',
        arguments: [range]
    };
    
    customActions.push(docAction);
    
    return [...actions, ...customActions];
}

function getCommentPrefix(languageId: string): string {
    const commentMap: { [key: string]: string } = {
        'python': '#',
        'ruby': '#',
        'shell': '#',
        'yaml': '#',
        'javascript': '//',
        'typescript': '//',
        'java': '//',
        'go': '//',
        'c': '//',
        'cpp': '//',
        'csharp': '//',
        'rust': '//',
        'php': '//',
        'swift': '//',
        'kotlin': '//'
    };
    
    return commentMap[languageId] || '//';
}

function handleScanComplete(params: any, outputChannel: vscode.OutputChannel): void {
    const { uri, findings, errors } = params;
    
    outputChannel.appendLine(`Scan complete for ${uri}`);
    outputChannel.appendLine(`  Found ${findings?.length || 0} issues`);
    
    if (errors && errors.length > 0) {
        outputChannel.appendLine(`  Errors encountered:`);
        errors.forEach((error: any) => {
            outputChannel.appendLine(`    - ${error.message || error}`);
        });
    }
}

function handleScanProgress(params: any, outputChannel: vscode.OutputChannel): void {
    const { current, total, file } = params;
    
    if (file) {
        outputChannel.appendLine(`Scanning [${current}/${total}]: ${file}`);
    } else {
        outputChannel.appendLine(`Scan progress: ${current}/${total}`);
    }
}

function isSupportedLanguage(languageId: string): boolean {
    const supportedLanguages = ['python', 'javascript', 'typescript', 'java', 'go', 'c', 'cpp'];
    return supportedLanguages.includes(languageId);
}

async function checkSemgrepInstallation(outputChannel: vscode.OutputChannel): Promise<boolean> {
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';

    try {
        await execFileAsync(semgrepPath, ['--version']);
        outputChannel.appendLine(`Semgrep found at: ${semgrepPath}`);
        return true;
    } catch (error) {
        outputChannel.appendLine('Semgrep not found in system PATH');
        
        if (config.get('autoInstallSemgrep')) {
            const choice = await vscode.window.showWarningMessage(
                'Semgrep is required for Security Framework Linters. Would you like to install it?',
                'Install Now',
                'Manual Instructions',
                'Dismiss'
            );

            if (choice === 'Install Now') {
                await installSemgrep(outputChannel);
            } else if (choice === 'Manual Instructions') {
                vscode.env.openExternal(vscode.Uri.parse('https://semgrep.dev/docs/getting-started/'));
            }
        }
        return false;
    }
}

async function installSemgrep(outputChannel: vscode.OutputChannel): Promise<void> {
    outputChannel.show();
    outputChannel.appendLine('Installing Semgrep via pip...');

    try {
        const terminal = vscode.window.createTerminal('Semgrep Installation');
        terminal.show();
        terminal.sendText('pip install semgrep');
        
        vscode.window.showInformationMessage(
            'Semgrep installation started. Check the terminal for progress.'
        );
    } catch (error) {
        outputChannel.appendLine(`Installation error: ${error}`);
        vscode.window.showErrorMessage('Failed to install Semgrep. Please install manually.');
    }
}

async function scanFile(
    document: vscode.TextDocument,
    diagnosticCollection: vscode.DiagnosticCollection,
    outputChannel: vscode.OutputChannel
): Promise<void> {
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';
    const rulesPath = config.get<string>('rulesPath');
    
    outputChannel.appendLine(`Scanning file: ${document.fileName}`);

    try {
        const args = buildSemgrepArgs(rulesPath, config, document.fileName);
        
        const { stdout } = await execFileAsync(semgrepPath, args, {
            maxBuffer: 10 * 1024 * 1024 // 10MB buffer for large outputs
        });

        const results: SemgrepOutput = JSON.parse(stdout);
        const diagnostics = convertToDiagnostics(results, document.uri);
        
        diagnosticCollection.set(document.uri, diagnostics);
        
        outputChannel.appendLine(`Found ${results.results.length} issues in ${document.fileName}`);
        
        if (results.errors.length > 0) {
            results.errors.forEach(err => {
                outputChannel.appendLine(`Error: ${err.message}`);
            });
        }
    } catch (error: any) {
        outputChannel.appendLine(`Scan failed: ${error.message}`);
        if (error.stderr) {
            outputChannel.appendLine(`Semgrep stderr: ${error.stderr}`);
        }
    }
}

async function scanWorkspace(
    diagnosticCollection: vscode.DiagnosticCollection,
    outputChannel: vscode.OutputChannel
): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const semgrepPath = config.get<string>('semgrepPath') || 'semgrep';
    const rulesPath = config.get<string>('rulesPath');
    
    outputChannel.show();
    outputChannel.appendLine('Starting workspace scan...');

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning workspace with Security Framework Linters',
        cancellable: false
    }, async (progress) => {
        for (const folder of workspaceFolders) {
            progress.report({ message: `Scanning ${folder.name}...` });
            
            try {
                const args = buildSemgrepArgs(rulesPath, config, folder.uri.fsPath);
                
                const { stdout } = await execFileAsync(semgrepPath, args, {
                    cwd: folder.uri.fsPath,
                    maxBuffer: 50 * 1024 * 1024 // 50MB for workspace scans
                });

                const results: SemgrepOutput = JSON.parse(stdout);
                
                // Group findings by file
                const findingsByFile = new Map<string, SemgrepFinding[]>();
                results.results.forEach(finding => {
                    const filePath = path.join(folder.uri.fsPath, finding.path);
                    if (!findingsByFile.has(filePath)) {
                        findingsByFile.set(filePath, []);
                    }
                    findingsByFile.get(filePath)!.push(finding);
                });

                // Create diagnostics for each file
                findingsByFile.forEach((findings, filePath) => {
                    const fileUri = vscode.Uri.file(filePath);
                    const mockOutput: SemgrepOutput = { results: findings, errors: [] };
                    const diagnostics = convertToDiagnostics(mockOutput, fileUri);
                    diagnosticCollection.set(fileUri, diagnostics);
                });

                outputChannel.appendLine(`Workspace scan complete: ${results.results.length} issues found`);
            } catch (error: any) {
                outputChannel.appendLine(`Workspace scan failed: ${error.message}`);
            }
        }
    });

    vscode.window.showInformationMessage('Workspace scan complete');
}

function buildSemgrepArgs(
    rulesPath: string | undefined,
    config: vscode.WorkspaceConfiguration,
    targetPath: string
): string[] {
    const args = ['--json', '--quiet'];
    
    // Determine rules source
    if (rulesPath && rulesPath.trim() !== '') {
        args.push('--config', rulesPath);
    } else {
        // Use framework-specific rules from bundled configuration
        const enabledFrameworks = config.get<string[]>('enabledFrameworks') || [];
        const enabledModules = config.get<any>('enabledModules') || {};
        
        enabledFrameworks.forEach(framework => {
            const modules = enabledModules[framework] || [];
            modules.forEach((module: string) => {
                // This assumes rules are bundled with the extension
                // Format: frameworks/{framework}/rules/{module}/
                args.push('--config', `frameworks/${framework}/rules/${module}/`);
            });
        });
        
        // Fallback to all available rules if no specific config
        if (enabledFrameworks.length === 0) {
            args.push('--config', 'auto');
        }
    }
    
    args.push(targetPath);
    
    return args;
}

function convertToDiagnostics(
    results: SemgrepOutput,
    uri: vscode.Uri
): vscode.Diagnostic[] {
    const config = vscode.workspace.getConfiguration('securityFrameworkLinters');
    const severityFilter = config.get<string[]>('severityFilter') || ['ERROR', 'WARNING'];
    
    return results.results
        .filter(finding => severityFilter.includes(finding.extra.severity))
        .map(finding => {
            const range = new vscode.Range(
                new vscode.Position(finding.start.line - 1, finding.start.col - 1),
                new vscode.Position(finding.end.line - 1, finding.end.col - 1)
            );

            const severity = mapSeverity(finding.extra.severity);
            
            let message = finding.extra.message;
            
            // Add metadata context
            if (finding.extra.metadata) {
                const meta = finding.extra.metadata;
                const metaParts = [];
                
                if (meta.framework) {
                    metaParts.push(`Framework: ${meta.framework}`);
                }
                if (meta.requirement) {
                    metaParts.push(`Requirement: ${meta.requirement}`);
                }
                if (meta.cwe && meta.cwe.length > 0) {
                    metaParts.push(`CWE: ${meta.cwe.join(', ')}`);
                }
                if (meta.owasp && meta.owasp.length > 0) {
                    metaParts.push(`OWASP: ${meta.owasp.join(', ')}`);
                }
                
                if (metaParts.length > 0) {
                    message += `\n\n${metaParts.join(' | ')}`;
                }
            }

            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'Security Framework Linters';
            diagnostic.code = finding.check_id;
            
            return diagnostic;
        });
}

function mapSeverity(semgrepSeverity: string): vscode.DiagnosticSeverity {
    switch (semgrepSeverity.toUpperCase()) {
        case 'ERROR':
            return vscode.DiagnosticSeverity.Error;
        case 'WARNING':
            return vscode.DiagnosticSeverity.Warning;
        case 'INFO':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Warning;
    }
}

async function showRuleDocumentation(
    document: vscode.TextDocument,
    range: vscode.Range,
    outputChannel: vscode.OutputChannel
): Promise<void> {
    // Get diagnostics for this location
    const diagnostics = vscode.languages.getDiagnostics(document.uri);
    const diagnostic = diagnostics.find(d => d.range.contains(range));
    
    if (!diagnostic || !diagnostic.code) {
        vscode.window.showInformationMessage('No rule information available at this location');
        return;
    }
    
    const ruleId = diagnostic.code.toString();
    
    // Create a webview panel for rule documentation
    const panel = vscode.window.createWebviewPanel(
        'ruleDocumentation',
        `Rule: ${ruleId}`,
        vscode.ViewColumn.Beside,
        {
            enableScripts: true
        }
    );
    
    // Extract metadata from diagnostic message
    const metadata = extractMetadata(diagnostic.message);
    
    panel.webview.html = getRuleDocumentationHTML(ruleId, diagnostic.message, metadata);
}

function extractMetadata(message: string): {
    framework?: string;
    requirement?: string;
    cwe?: string[];
    owasp?: string[];
} {
    const metadata: any = {};
    
    const frameworkMatch = message.match(/Framework:\s*([^\n|]+)/);
    if (frameworkMatch) {
        metadata.framework = frameworkMatch[1].trim();
    }
    
    const requirementMatch = message.match(/Requirement:\s*([^\n|]+)/);
    if (requirementMatch) {
        metadata.requirement = requirementMatch[1].trim();
    }
    
    const cweMatch = message.match(/CWE:\s*([^\n|]+)/);
    if (cweMatch) {
        metadata.cwe = cweMatch[1].split(',').map(c => c.trim());
    }
    
    const owaspMatch = message.match(/OWASP:\s*([^\n|]+)/);
    if (owaspMatch) {
        metadata.owasp = owaspMatch[1].split(',').map(o => o.trim());
    }
    
    return metadata;
}

function getRuleDocumentationHTML(
    ruleId: string,
    message: string,
    metadata: any
): string {
    const cleanMessage = message.split('\n\n')[0]; // Get first part before metadata
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rule Documentation</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            padding: 20px;
            line-height: 1.6;
            color: var(--vscode-editor-foreground);
            background-color: var(--vscode-editor-background);
        }
        h1 {
            color: var(--vscode-textLink-foreground);
            border-bottom: 2px solid var(--vscode-textLink-foreground);
            padding-bottom: 10px;
        }
        h2 {
            color: var(--vscode-textLink-foreground);
            margin-top: 30px;
        }
        .metadata {
            background-color: var(--vscode-textBlockQuote-background);
            border-left: 4px solid var(--vscode-textLink-foreground);
            padding: 15px;
            margin: 20px 0;
        }
        .metadata-item {
            margin: 10px 0;
        }
        .metadata-label {
            font-weight: bold;
            color: var(--vscode-textLink-foreground);
        }
        .description {
            margin: 20px 0;
            padding: 15px;
            background-color: var(--vscode-textBlockQuote-background);
            border-radius: 4px;
        }
        .links {
            margin-top: 30px;
        }
        .link-button {
            display: inline-block;
            padding: 8px 16px;
            margin: 5px;
            background-color: var(--vscode-button-background);
            color: var(--vscode-button-foreground);
            text-decoration: none;
            border-radius: 4px;
            transition: background-color 0.2s;
        }
        .link-button:hover {
            background-color: var(--vscode-button-hoverBackground);
        }
        code {
            background-color: var(--vscode-textCodeBlock-background);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin: 2px;
            background-color: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
        }
    </style>
</head>
<body>
    <h1>Security Rule Documentation</h1>
    
    <div class="metadata">
        <div class="metadata-item">
            <span class="metadata-label">Rule ID:</span> <code>${ruleId}</code>
        </div>
        ${metadata.framework ? `
        <div class="metadata-item">
            <span class="metadata-label">Framework:</span> ${metadata.framework}
        </div>
        ` : ''}
        ${metadata.requirement ? `
        <div class="metadata-item">
            <span class="metadata-label">Requirement:</span> ${metadata.requirement}
        </div>
        ` : ''}
        ${metadata.cwe && metadata.cwe.length > 0 ? `
        <div class="metadata-item">
            <span class="metadata-label">CWE:</span>
            ${metadata.cwe.map((cwe: string) => `<span class="badge">${cwe}</span>`).join('')}
        </div>
        ` : ''}
        ${metadata.owasp && metadata.owasp.length > 0 ? `
        <div class="metadata-item">
            <span class="metadata-label">OWASP:</span>
            ${metadata.owasp.map((owasp: string) => `<span class="badge">${owasp}</span>`).join('')}
        </div>
        ` : ''}
    </div>
    
    <h2>Description</h2>
    <div class="description">
        ${cleanMessage}
    </div>
    
    <h2>What This Means</h2>
    <p>
        This security rule has detected a potential violation in your code. The issue identified
        could lead to security vulnerabilities or compliance failures if not addressed.
    </p>
    
    <h2>How to Fix</h2>
    <p>
        Review the code at the flagged location and consider the following remediation steps:
    </p>
    <ul>
        <li>Verify if the flagged code truly represents a security issue</li>
        <li>Refactor the code to follow security best practices</li>
        <li>If this is a false positive, add a <code>nosemgrep</code> comment to suppress</li>
        <li>Consult framework-specific documentation for detailed guidance</li>
    </ul>
    
    <div class="links">
        <h2>Additional Resources</h2>
        <a href="https://github.com/cj-juntunen/security-framework-linters" class="link-button">
            View Project Documentation
        </a>
        ${metadata.cwe && metadata.cwe.length > 0 ? `
        <a href="https://cwe.mitre.org/data/definitions/${metadata.cwe[0].replace('CWE-', '')}.html" class="link-button">
            CWE Details
        </a>
        ` : ''}
        <a href="https://semgrep.dev/docs/" class="link-button">
            Semgrep Documentation
        </a>
    </div>
</body>
</html>`;
}

async function restartLanguageServer(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel
): Promise<void> {
    outputChannel.appendLine('Restarting Language Server...');
    
    if (client) {
        await client.stop();
        client = undefined;
    }
    
    await startLanguageServer(context, outputChannel);
    
    vscode.window.showInformationMessage('Semgrep Language Server restarted');
}

export function deactivate(): Thenable<void> | undefined {
    if (!client) {
        return undefined;
    }
    return client.stop();
}
