# Lifecycle Script Command False-Alarm and Sole-Trigger Audit

> **Stage 5g Part 1 & Part 2**: Systematic audit of inline lifecycle script commands
> across 2,000 popular npm packages (last 10 versions) and 1,349 malicious eval pairs.

## 1. Audit Dataset Overview

- **Benign Popular Packages**: 2,000 packages audited from registry metadata
- **Benign Packages with Install Hooks**: 294 packages (14.7%)
- **Benign Script Instances Checked**: 1,992 script commands across last 10 versions
- **Existing Differ Evidence Counts on Benign**: `install_script_network`: 0, `install_script_executes`: 4
- **Malicious Evaluation Pairs Checked**: 1,448 pairs (1102 contain install-time lifecycle hooks; 1331 script instances)

## 2. Regex Alternative Audit Table

| Regex Alternative | Pattern / Intent | Benign Scripts Flagged | Benign Pkgs Flagged | Malicious Pairs Flagged | Malicious Campaigns Flagged | Sole Trigger (Lifecycle Only) [Pairs / Camps] | Sole Trigger (Overall Detector) [Pairs / Camps] |
|---|---|---:|---:|---:|---:|---:|---:|
| `curl` | `\bcurl\b` | 0 | 0 | 10 | 1 | 0 / 0 | 0 / 0 |
| `wget` | `\bwget\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `fetch` | `\bfetch\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `certutil` | `\bcertutil\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `bitsadmin` | `\bbitsadmin\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `iwr` | `\biwr\b\|Invoke-WebRequest` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `powershell_download` | `powershell.*download` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `pipe_to_shell` | `\\|\s*(?:sh\|bash\|zsh\|dash\|powershell\|pwsh\|cmd(?:\.exe)?)\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `sh_c` | `\b(?:bash\|sh\|zsh\|dash)\s+-c\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `powershell_enc` | `\bpowershell(?:\.exe)?\s+(?:-e\|-enc\|-encodedcommand)\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `cmd_c` | `\bcmd(?:\.exe)?\s+/c\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `sudo` | `\bsudo\b` | 0 | 0 | 10 | 1 | 0 / 0 | 0 / 0 |
| `node_e` | `\bnode\s+(?:-e\|--eval)\b` | 4 | 3 | 2 | 1 | 2 / 1 | 0 / 0 |
| `python_c` | `\bpython(?:\d)?\s+-c\b` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |
| `rm_rf` | `rm\s+-rf\b` | 17 | 2 | 10 | 1 | 0 / 0 | 0 / 0 |
| `base64_decode` | `base64\s+(?:-d\|--decode)\|certutil\s+-(?:decode\|f\|decodehex)\|\[System\.Convert\]::FromBase64String\|\[Convert\]::FromBase64String\|atob\(` | 0 | 0 | 0 | 0 | 0 / 0 | 0 / 0 |

## 3. Flagged Benign Commands per Alternative

### Alternative: `curl`

*Zero benign commands flagged.*

### Alternative: `wget`

*Zero benign commands flagged.*

### Alternative: `fetch`

*Zero benign commands flagged.*

### Alternative: `certutil`

*Zero benign commands flagged.*

### Alternative: `bitsadmin`

*Zero benign commands flagged.*

### Alternative: `iwr`

*Zero benign commands flagged.*

### Alternative: `powershell_download`

*Zero benign commands flagged.*

### Alternative: `pipe_to_shell`

*Zero benign commands flagged.*

### Alternative: `sh_c`

*Zero benign commands flagged.*

### Alternative: `powershell_enc`

*Zero benign commands flagged.*

### Alternative: `cmd_c`

*Zero benign commands flagged.*

### Alternative: `sudo`

*Zero benign commands flagged.*

### Alternative: `node_e`

- **Total distinct commands flagged**: 3
- **Distinct packages flagged**: 3
- **Distinct commands listed**:
  - `node -e "const v = parseInt(process.versions.node, 10); if (v >= 20) require('child_process').execSync('vp config', {stdio: 'inherit'});"`
  - `node -e "if(process.env.npm_execpath.indexOf('yarn') === -1) throw new Error('You must use Yarn to install, not NPM')"`
  - `node -e "try{require('better-sqlite3')}catch(e){require('child_process').execSync('npm rebuild better-sqlite3')}"`

### Alternative: `python_c`

*Zero benign commands flagged.*

### Alternative: `rm_rf`

- **Total distinct commands flagged**: 3
- **Distinct packages flagged**: 2
- **Distinct commands listed**:
  - `rm -rf dist && mkdir -p dist && npm run build-cjs && npm run build-dev && npm run build-prod`
  - `rm -rf dist && mkdir -p dist && npm run build-dev && npm run build-prod`
  - `rm -rf lib && tsc`

### Alternative: `base64_decode`

*Zero benign commands flagged.*

## 4. Analysis and Final Decisions (Part 2)

### Decision 1: Narrow `fetch` to network invocations

- **Audit Evidence**: Bare word `fetch` flags 0 benign packages in this dataset, but carries substantial risk of false positives on standard commands like `git fetch` or helper scripts like `fetch-assets.js`.
- **Narrowed Regex**: `\bfetch\s*(?:\(|\s+https?://)` (requires URL parameter or JavaScript function invocation).
- **Malicious Impact**: 0 malicious pairs or campaigns have `fetch` as their sole trigger.
- **Decision**: **Narrowed**. Protects against future git/asset false alarms without weakening any detection.

### Decision 2: Narrow `rm -rf` to dangerous targets

- **Audit Evidence**: Bare `rm -rf` flagged **17 benign scripts across 2 popular packages** (`dist`, `lib`, `build` cleanup before compile). Conversely, all 10 malicious pairs that invoked `rm -rf` targeted the filesystem root: `sudo rm -rf --no-preserve-root /`.
- **Narrowed Regex**: `rm\s+(?:-[a-zA-Z]*\s+)*(?:--no-preserve-root\b|-(?:rf|fr)\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\.\.|\*(?:\s|$|;)|[a-zA-Z]:[\\/]|/[a-zA-Z0-9_]))`
- **Benign Impact**: Eliminates **100% of benign false alarms (17 of 17 scripts)**.
- **Malicious Impact**: Detects all 10 malicious wiping pairs (`@toptal/picasso-*`, `@xene/core`). Sole trigger count is 0 pairs / 0 campaigns.
- **Decision**: **Narrowed** to dangerous targets only.

### Decision 3: Narrow `sudo` to command invocations

- **Audit Evidence**: Flagged 0 benign packages and 10 malicious pairs (all from the picasso wiper campaign).
- **Narrowed Regex**: `\bsudo\s+[a-zA-Z0-9_\-\./]` (requires an explicit command target, avoiding bare-word token matches).
- **Malicious Impact**: 0 malicious pairs or campaigns have `sudo` as sole trigger.
- **Decision**: **Narrowed** to explicit command invocations.

### Decision 4: Retain `node -e`

- **Audit Evidence**: Flagged 4 benign scripts in 3 packages (e.g. environment checks) and 2 malicious pairs in 1 campaign.
- **Malicious Impact**: Sole trigger for 2 pairs / 1 campaign among lifecycle hooks.
- **Decision**: **Retained**. Inline evaluation of arbitrary JavaScript code remains a high-risk vector during installation.

### Summary of Sole-Trigger Rule Verification

No alternative that was narrowed (`fetch`, `rm -rf`, `sudo`) is the sole trigger for 3 or more malicious campaigns (actual sole trigger counts: 0 campaigns for all three).
