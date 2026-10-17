/** Windows PowerShell 5.1 and PowerShell 7 both hide input with -AsSecureString. */
export function powershellSecretPrompt(variable: 'AGF_AGENT_TOKEN' | 'AGF_SOURCE_KEY' | 'OPENAI_API_KEY' | 'ANTHROPIC_API_KEY', prompt: string): string {
  const label = prompt.replaceAll("'", "''");
  return `$agfSecret=Read-Host '${label}' -AsSecureString
$agfPtr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($agfSecret)
try { $env:${variable}=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($agfPtr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($agfPtr); Remove-Variable agfSecret,agfPtr -ErrorAction SilentlyContinue }`;
}
