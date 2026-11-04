# Optional Alibaba Qwen (Model Studio) setup

Cloud inference is **disabled unless a request-specific approval is given in Conversation**. Merely setting a key does not send a request. Do not paste the key into chat, SQLite, source, or issue reports.

## Windows local configuration

Set protected process/user environment variables (PowerShell example; key input is prompted without echo):

```powershell
$secure = Read-Host 'DashScope API key' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:DASHSCOPE_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
$env:SOVEREIGN_ALIBABA_REGION = '<your actual Model Studio region ID>'
$env:SOVEREIGN_ALIBABA_WORKSPACE_ID = '<workspace ID for that same region>'
$env:SOVEREIGN_ALIBABA_MODEL = '<model ID enabled in that region/workspace>'
# Optional. Otherwise the app constructs the documented workspace-specific URL:
# https://{WorkspaceId}.{Region}.maas.aliyuncs.com/compatible-mode/v1
$env:SOVEREIGN_ALIBABA_BASE_URL = ''
```

For persistent Windows user variables, configure them in Windows Environment Variables or a protected secret manager; restart Streamlit after changes. Do not save a plain-text `.env` file unless it has restrictive ACLs and is excluded from Git. Do not use the Singapore endpoint unless your workspace is actually in Singapore. The hostname must match workspace and region.

The app needs no credential display; it reports only whether a key is configured. Model catalog presence is not proof that the workspace key can invoke that model.

## GitHub Actions

In GitHub repository settings, open **Settings → Secrets and variables → Actions → New repository secret**, name it `ALIBABA_DASHSCOPE_API_KEY`, and paste the key into GitHub's secret field. An authorized workflow that genuinely needs cloud access must explicitly map it to `DASHSCOPE_API_KEY` in its job/step environment. Do not expose it to untrusted fork pull requests or print environment variables. Normal CI uses mocked providers and must not call Alibaba. A repository secret is not available to local Streamlit or OpenCode.

## Billing and permissions

Enable Alibaba/provider-side free-quota-only or spending safeguards where available. The app's token/cost budget is an additional guard, not a billing guarantee. Current UI labels prompt token usage as an estimate and does not claim exact cost when no verified price table is configured. Each cloud operation requires approving the exact displayed payload once. No health-check inference is automatic.
