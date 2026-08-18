# Recognition Event Chain v2
# Spec: CANONICAL_HANDOFF_V1 sections 12 + 15.
# Every event carries: seq, ts_utc, hash, identity, prev_hash.
# event_hash = SHA256(canonical JSON of the event minus event_hash).
# prev_hash links each event to its predecessor; genesis prev_hash = 64 zeros.
# Verification proves: nothing modified, nothing missing, nothing reordered, nothing forged.
# Requires pwsh 7.2+.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:RCE_SCHEMA = "recognition.event.v2"
$script:RCE_GENESIS = ("0" * 64)

function RCE-Die([string]$m){ throw ("RCE_FAIL: " + $m) }

if($PSVersionTable.PSVersion.Major -lt 7){ RCE-Die "REQUIRES_PWSH7" }

function RCE-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ RCE-Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function RCE-AppendLine([string]$Path,[string]$Line){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $txt = ($Line -replace "`r`n","`n") -replace "`r","`n"
  if(-not $txt.EndsWith("`n")){ $txt += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ RCE-EnsureDir $dir }
  [System.IO.File]::AppendAllText($Path,$txt,$enc)
}

function RCE-NowUtc(){
  return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function RCE-JsonEscape([string]$s){
  if($null -eq $s){ return "" }
  $sb = New-Object System.Text.StringBuilder
  foreach($ch in $s.ToCharArray()){
    $c = [int][char]$ch
    if($c -eq 34){ [void]$sb.Append('\"'); continue }
    if($c -eq 92){ [void]$sb.Append('\\'); continue }
    if($c -eq 8 ){ [void]$sb.Append('\b'); continue }
    if($c -eq 12){ [void]$sb.Append('\f'); continue }
    if($c -eq 10){ [void]$sb.Append('\n'); continue }
    if($c -eq 13){ [void]$sb.Append('\r'); continue }
    if($c -eq 9 ){ [void]$sb.Append('\t'); continue }
    if($c -lt 32){ [void]$sb.AppendFormat('\u{0:x4}',$c); continue }
    [void]$sb.Append([char]$ch)
  }
  return $sb.ToString()
}

function RCE-EmitCanon([object]$v,[System.Text.StringBuilder]$sb){
  if($null -eq $v){ [void]$sb.Append("null"); return }

  if($v -is [bool]){
    [void]$sb.Append($(if($v){"true"}else{"false"})); return
  }

  if($v -is [byte] -or $v -is [sbyte] -or $v -is [int16] -or $v -is [uint16] -or
     $v -is [int] -or $v -is [uint32] -or $v -is [int64] -or $v -is [uint64]){
    [void]$sb.Append([string]$v); return
  }

  if($v -is [double] -or $v -is [single] -or $v -is [decimal]){
    [void]$sb.Append([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,"{0}",$v)); return
  }

  if($v -is [string]){
    [void]$sb.Append('"'); [void]$sb.Append((RCE-JsonEscape $v)); [void]$sb.Append('"'); return
  }

  if($v -is [System.Management.Automation.PSCustomObject]){
    $ht = [ordered]@{}
    foreach($p in $v.PSObject.Properties){ $ht[$p.Name] = $p.Value }
    RCE-EmitCanon $ht $sb; return
  }

  if($v -is [System.Collections.IDictionary]){
    [void]$sb.Append('{')
    $keys = @($v.Keys | ForEach-Object { [string]$_ } | Sort-Object)
    $first = $true
    foreach($k in $keys){
      if(-not $first){ [void]$sb.Append(',') } else { $first = $false }
      [void]$sb.Append('"'); [void]$sb.Append((RCE-JsonEscape $k)); [void]$sb.Append('":')
      RCE-EmitCanon $v[$k] $sb
    }
    [void]$sb.Append('}'); return
  }

  if($v -is [System.Collections.IEnumerable]){
    [void]$sb.Append('[')
    $first = $true
    foreach($it in $v){
      if(-not $first){ [void]$sb.Append(',') } else { $first = $false }
      RCE-EmitCanon $it $sb
    }
    [void]$sb.Append(']'); return
  }

  [void]$sb.Append('"'); [void]$sb.Append((RCE-JsonEscape ([string]$v))); [void]$sb.Append('"')
}

function RCE-CanonJson([object]$obj){
  $sb = New-Object System.Text.StringBuilder
  RCE-EmitCanon $obj $sb
  return $sb.ToString()
}

# Faithful JSON parser. ConvertFrom-Json silently converts ISO-8601 strings to
# DateTime objects, which destroys canonical round-tripping (and therefore hash
# verification). System.Text.Json never does that.
function RCE-JsonElemToObj([System.Text.Json.JsonElement]$el){
  $kind = $el.ValueKind
  if($kind -eq [System.Text.Json.JsonValueKind]::Object){
    $d = [ordered]@{}
    foreach($p in $el.EnumerateObject()){ $d[$p.Name] = RCE-JsonElemToObj $p.Value }
    return $d
  }
  if($kind -eq [System.Text.Json.JsonValueKind]::Array){
    $l = New-Object System.Collections.Generic.List[object]
    foreach($it in $el.EnumerateArray()){ [void]$l.Add((RCE-JsonElemToObj $it)) }
    return ,$l
  }
  if($kind -eq [System.Text.Json.JsonValueKind]::String){ return $el.GetString() }
  if($kind -eq [System.Text.Json.JsonValueKind]::Number){
    $tmp = [long]0
    if($el.TryGetInt64([ref]$tmp)){ return $tmp }
    return $el.GetDecimal()
  }
  if($kind -eq [System.Text.Json.JsonValueKind]::True){ return $true }
  if($kind -eq [System.Text.Json.JsonValueKind]::False){ return $false }
  if($kind -eq [System.Text.Json.JsonValueKind]::Null){ return $null }
  RCE-Die ("PARSE_UNSUPPORTED_KIND: " + [string]$kind)
}

function RCE-ParseJson([string]$Text){
  $doc = [System.Text.Json.JsonDocument]::Parse($Text)
  try {
    return RCE-JsonElemToObj ($doc.RootElement.Clone())
  } finally {
    $doc.Dispose()
  }
}

function RCE-Sha256Hex([string]$Text){
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
  $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

function RCE-GenesisHash(){ return $script:RCE_GENESIS }

function RCE-ComputeEventHash([System.Collections.IDictionary]$EventNoHash){
  return RCE-Sha256Hex (RCE-CanonJson $EventNoHash)
}

function RCE-BuildEvent(
  [int]$Seq,
  [string]$TsUtc,
  [string]$Type,
  [object]$TabId,
  [object]$Data,
  [System.Collections.IDictionary]$Identity,
  [string]$PrevHash
){
  if($Seq -lt 1){ RCE-Die "EVENT_BAD_SEQ" }
  if([string]::IsNullOrWhiteSpace($Type)){ RCE-Die "EVENT_EMPTY_TYPE" }
  if($PrevHash -notmatch '^[0-9a-f]{64}$'){ RCE-Die "EVENT_BAD_PREV_HASH" }
  if($null -eq $Identity -or -not $Identity.Contains("session_id")){ RCE-Die "EVENT_IDENTITY_SESSION_MISSING" }

  $evt = [ordered]@{
    schema    = $script:RCE_SCHEMA
    event_id  = ("evt-" + $Seq.ToString("d6"))
    seq       = $Seq
    ts_utc    = $TsUtc
    type      = $Type
    tab_id    = $TabId
    data      = $Data
    identity  = $Identity
    prev_hash = $PrevHash
  }
  $evt["event_hash"] = RCE-ComputeEventHash $evt
  return $evt
}

function RCE-ReadChainLines([string]$Path){
  # NOTE: `,` prevents PowerShell from unrolling single-element arrays into a
  # bare string (which would make $lines[-1] return the last CHARACTER).
  # CONTRACT: always returns a real array via the `,` no-enumerate wrapper
  # (the pipeline strips exactly one level). Callers must assign DIRECTLY —
  # never wrap the call in @(), which would nest the array.
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ return ,@() }
  $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
  if([string]::IsNullOrWhiteSpace($raw)){ return ,@() }
  $arr = @($raw -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
  return ,$arr
}

function RCE-VerifyEventLine([string]$Line){
  $evt = RCE-ParseJson $Line
  if([string]$evt.schema -ne $script:RCE_SCHEMA){ RCE-Die ("VERIFY_BAD_SCHEMA: seq=" + [string]$evt.seq) }
  foreach($f in @("event_id","seq","ts_utc","type","identity","prev_hash","event_hash")){
    if(-not $evt.Contains($f)){ RCE-Die ("VERIFY_FIELD_MISSING: " + $f) }
  }
  $claimed = [string]$evt.event_hash
  $evt.Remove("event_hash")
  $actual = RCE-ComputeEventHash $evt
  if($actual -ne $claimed){
    RCE-Die ("VERIFY_EVENT_HASH_MISMATCH: seq=" + [string]$evt.seq + " expected=" + $claimed + " actual=" + $actual)
  }
  $evt["event_hash"] = $claimed
  return $evt
}

# Full chain verification: proves nothing modified, missing, reordered, or forged.
function RCE-VerifyChain([string]$Path){
  $lines = RCE-ReadChainLines $Path
  if(@($lines).Count -lt 1){ RCE-Die ("VERIFY_CHAIN_EMPTY: " + $Path) }

  $prevHash = RCE-GenesisHash
  $prevSeq = 0
  $prevTs = ""
  $count = 0

  foreach($line in $lines){
    $evt = RCE-VerifyEventLine $line

    $seq = [int]$evt.seq
    if($seq -ne ($prevSeq + 1)){
      RCE-Die ("VERIFY_SEQ_BREAK: prev=" + $prevSeq + " current=" + $seq)
    }

    $ts = [string]$evt.ts_utc
    if($prevTs -and ($ts -lt $prevTs)){
      RCE-Die ("VERIFY_TS_NON_MONOTONIC: prev=" + $prevTs + " current=" + $ts)
    }

    if([string]$evt.prev_hash -ne $prevHash){
      RCE-Die ("VERIFY_PREV_LINK_BROKEN: seq=" + $seq + " expected=" + $prevHash + " claimed=" + [string]$evt.prev_hash)
    }

    $prevHash = [string]$evt.event_hash
    $prevSeq = $seq
    $prevTs = $ts
    $count++
  }

  return [ordered]@{
    event_count = $count
    head_seq    = $prevSeq
    head_hash   = $prevHash
  }
}

# Read chain tail for appending. Validates the last event's own hash so nothing
# can be appended on top of a tampered head.
function RCE-ChainTail([string]$Path){
  $lines = RCE-ReadChainLines $Path
  if(@($lines).Count -eq 0){
    return [ordered]@{ seq = 0; ts_utc = ""; head_hash = (RCE-GenesisHash) }
  }
  $last = RCE-VerifyEventLine $lines[-1]
  return [ordered]@{
    seq = [int]$last.seq
    ts_utc = [string]$last.ts_utc
    head_hash = [string]$last.event_hash
  }
}
