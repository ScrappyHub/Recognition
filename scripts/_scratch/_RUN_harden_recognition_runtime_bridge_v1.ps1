param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "ENSUREDIR_EMPTY" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf+="`n" }; $dir=Split-Path -Parent $Path; if($dir){ EnsureDir $dir }; [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors); if($errors -and @($errors).Count -gt 0){ $e=@($errors)[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message) } }
$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir=Join-Path $RepoRoot "scripts"
$ReceiptPath=Join-Path (Join-Path $RepoRoot "proofs\receipts") "recognition.runtime.bridge.v1.ndjson"
$BridgePath=Join-Path $ScriptsDir "recognition_runtime_bridge_event_v1.ps1"
$SelfPath=Join-Path $ScriptsDir "_selftest_recognition_runtime_bridge_v1.ps1"
foreach($p in @($BridgePath,$SelfPath)){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("MISSING_SCRIPT: " + $p) }; ParseGateFile $p }
$raw=Get-Content -Raw -LiteralPath $BridgePath -Encoding UTF8
$insertAfter = '$NavCommit = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"'
$bridgeReceiptFunc = New-Object System.Collections.Generic.List[string]
[void]$bridgeReceiptFunc.Add('function WriteBridgeReceipt([string]$EventType,[string]$SessionId,[string]$TabId,[string]$Url,[string]$Title,[string]$Utc){')
[void]$bridgeReceiptFunc.Add('  $ReceiptPath = Join-Path (Join-Path $RepoRoot "proofs\receipts") "recognition.runtime.bridge.v1.ndjson"')
[void]$bridgeReceiptFunc.Add('  $dir = Split-Path -Parent $ReceiptPath')
[void]$bridgeReceiptFunc.Add('  if(-not (Test-Path -LiteralPath $dir -PathType Container)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }')
[void]$bridgeReceiptFunc.Add('  $obj = [ordered]@{ schema="recognition.runtime.bridge.receipt.v1"; event_type=$EventType; session_id=$SessionId; tab_id=$TabId; url=$Url; title=$Title; ts_utc=$Utc; source="recognition_runtime_bridge_event_v1" }')
[void]$bridgeReceiptFunc.Add('  $json = $obj | ConvertTo-Json -Compress -Depth 20')
[void]$bridgeReceiptFunc.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$bridgeReceiptFunc.Add('  [System.IO.File]::AppendAllText($ReceiptPath,(($json -replace "`r`n","`n") -replace "`r","`n") + "`n",$enc)')
[void]$bridgeReceiptFunc.Add('  Write-Host ("BRIDGE_RECEIPT_OK: " + $ReceiptPath) -ForegroundColor Green')
[void]$bridgeReceiptFunc.Add('}')
$funcText = [string]::Join("`n",$bridgeReceiptFunc)
if($raw -notmatch "function WriteBridgeReceipt"){ if(-not $raw.Contains($insertAfter)){ Die "PATCH_FAIL:BRIDGE_INSERT_ANCHOR_MISSING" }; $raw=$raw.Replace($insertAfter,($insertAfter+"`n"+$funcText)) }
$raw=$raw.Replace('Write-Host ("RUNTIME_BRIDGE_EVENT_OK: session.open " + $SessionId) -ForegroundColor Green','WriteBridgeReceipt -EventType "session.open" -SessionId $SessionId -TabId "" -Url "" -Title "" -Utc $Utc`n  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: session.open " + $SessionId) -ForegroundColor Green')
$raw=$raw.Replace('Write-Host ("RUNTIME_BRIDGE_EVENT_OK: tab.open " + $TabId) -ForegroundColor Green','WriteBridgeReceipt -EventType "tab.open" -SessionId $SessionId -TabId $TabId -Url $Url -Title $Title -Utc $Utc`n  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: tab.open " + $TabId) -ForegroundColor Green')
$raw=$raw.Replace('Write-Host ("RUNTIME_BRIDGE_EVENT_OK: navigation.commit " + $TabId) -ForegroundColor Green','WriteBridgeReceipt -EventType "navigation.commit" -SessionId $SessionId -TabId $TabId -Url $Url -Title $Title -Utc $Utc`n  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: navigation.commit " + $TabId) -ForegroundColor Green')
WriteUtf8NoBomLf $BridgePath $raw
ParseGateFile $BridgePath
Write-Host ("BRIDGE_RECEIPTS_PATCH_OK: " + $BridgePath) -ForegroundColor Green
if(Test-Path -LiteralPath $ReceiptPath -PathType Leaf){ Remove-Item -LiteralPath $ReceiptPath -Force }
$PSExe=Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$out=& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SelfPath -RepoRoot $RepoRoot 2>&1
$out | Out-Host
$text=($out | Out-String)
if($text -notmatch "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK"){ Die "BRIDGE_SELFTEST_TOKEN_MISSING" }
if(-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf)){ Die ("BRIDGE_RECEIPT_MISSING: " + $ReceiptPath) }
$rt=Get-Content -Raw -LiteralPath $ReceiptPath -Encoding UTF8
foreach($tok in @('"event_type":"session.open"','"event_type":"tab.open"','"event_type":"navigation.commit"')){ if($rt -notmatch [regex]::Escape($tok)){ Die ("BRIDGE_RECEIPT_TOKEN_MISSING: " + $tok) } }
Write-Host ("BRIDGE_RECEIPTS_GREEN: " + $ReceiptPath) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_BRIDGE_HARDENED_V1_OK" -ForegroundColor Green
