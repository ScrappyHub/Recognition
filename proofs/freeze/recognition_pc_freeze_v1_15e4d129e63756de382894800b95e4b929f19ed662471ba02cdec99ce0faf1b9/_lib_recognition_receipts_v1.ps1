function Get-RecognitionReceiptPath(){
    return (Join-Path (Join-Path $RepoRoot "proofs\receipts") "recognition.packet_constitution.v1.ndjson")
}
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function REC-Die([string]$m){ throw ("REC_FAIL: " + $m) }

function REC-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ REC-Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function REC-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ REC-EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function REC-AppendUtf8NoBomLfLine([string]$Path,[string]$Line){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $txt = ($Line -replace "`r`n","`n") -replace "`r","`n"
  if(-not $txt.EndsWith("`n")){ $txt += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ REC-EnsureDir $dir }
  [System.IO.File]::AppendAllText($Path,$txt,$enc)
}

function REC-NowUtc(){
  return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

function REC-JsonEscape([string]$s){
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
    if($c -lt 32){
      [void]$sb.AppendFormat('\u{0:x4}', $c)
      continue
    }
    [void]$sb.Append([char]$c)
  }
  return $sb.ToString()
}

function REC-IsEnumerable([object]$o){
  if($null -eq $o){ return $false }
  if($o -is [string]){ return $false }
  return ($o -is [System.Collections.IEnumerable])
}

function REC-ToCanonJson([object]$obj){
  $script:REC_JSON_SB = New-Object System.Text.StringBuilder

  function local:Emit([object]$v){
    if($null -eq $v){
      [void]$script:REC_JSON_SB.Append("null")
      return
    }

    if($v -is [bool]){
      if($v){ [void]$script:REC_JSON_SB.Append("true") } else { [void]$script:REC_JSON_SB.Append("false") }
      return
    }

    if($v -is [byte] -or $v -is [sbyte] -or $v -is [int16] -or $v -is [uint16] -or $v -is [int] -or $v -is [uint32] -or $v -is [int64] -or $v -is [uint64]){
      [void]$script:REC_JSON_SB.Append(([string]$v))
      return
    }

    if($v -is [double] -or $v -is [single] -or $v -is [decimal]){
      $num = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $v)
      [void]$script:REC_JSON_SB.Append($num)
      return
    }

    if($v -is [string]){
      [void]$script:REC_JSON_SB.Append('"')
      [void]$script:REC_JSON_SB.Append((REC-JsonEscape $v))
      [void]$script:REC_JSON_SB.Append('"')
      return
    }

    if($v -is [System.Collections.IDictionary]){
      [void]$script:REC_JSON_SB.Append('{')
      $keys = New-Object System.Collections.Generic.List[string]
      foreach($k in $v.Keys){
        if($null -eq $k){ REC-Die "CANONJSON_NULL_KEY" }
        [void]$keys.Add([string]$k)
      }
      $sorted = @($keys | Sort-Object)
      $first = $true
      foreach($k in $sorted){
        if(-not $first){ [void]$script:REC_JSON_SB.Append(',') } else { $first = $false }
        [void]$script:REC_JSON_SB.Append('"')
        [void]$script:REC_JSON_SB.Append((REC-JsonEscape $k))
        [void]$script:REC_JSON_SB.Append('":')
        Emit $v[$k]
      }
      [void]$script:REC_JSON_SB.Append('}')
      return
    }

    if(REC-IsEnumerable $v){
      [void]$script:REC_JSON_SB.Append('[')
      $first = $true
      foreach($it in $v){
        if(-not $first){ [void]$script:REC_JSON_SB.Append(',') } else { $first = $false }
        Emit $it
      }
      [void]$script:REC_JSON_SB.Append(']')
      return
    }

    [void]$script:REC_JSON_SB.Append('"')
    [void]$script:REC_JSON_SB.Append((REC-JsonEscape ([string]$v)))
    [void]$script:REC_JSON_SB.Append('"')
  }

  Emit $obj
  return $script:REC_JSON_SB.ToString()
}

function REC-AppendReceipt([string]$RepoRoot,[hashtable]$Obj){
  $receiptPath = Join-Path $RepoRoot "proofs\receipts\recognition.packet_constitution.v1.ndjson"
  $canon = REC-ToCanonJson $Obj
  REC-AppendUtf8NoBomLfLine $receiptPath $canon
  return $receiptPath
}
