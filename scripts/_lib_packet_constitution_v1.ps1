Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function PC-Die([string]$m){ throw ("PC_FAIL: " + $m) }

function PC-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ PC-Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function PC-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ PC-EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function PC-Sha256HexBytes([byte[]]$Bytes){
  if($null -eq $Bytes){ PC-Die "SHA256_NULL_BYTES" }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($Bytes)
  } finally {
    $sha.Dispose()
  }
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){
    [void]$sb.AppendFormat("{0:x2}", $b)
  }
  return $sb.ToString()
}

function PC-Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ PC-Die ("SHA256_MISSING_FILE: " + $Path) }
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  return (PC-Sha256HexBytes $bytes)
}

function PC-RelPath([string]$BaseDir,[string]$FullPath){
  $base = (Resolve-Path -LiteralPath $BaseDir).Path
  $full = (Resolve-Path -LiteralPath $FullPath).Path

  $trimChars = New-Object 'System.Char[]' 2
  $trimChars[0] = [char]92
  $trimChars[1] = [char]47

  $base = $base.TrimEnd($trimChars)

  if($full.Length -lt ($base.Length + 1)){
    PC-Die ("REL_OUTSIDE_BASE: base=" + $base + " full=" + $full)
  }
  if($full.Substring(0,$base.Length) -ne $base){
    PC-Die ("REL_OUTSIDE_BASE: base=" + $base + " full=" + $full)
  }

  $rel = $full.Substring($base.Length).TrimStart($trimChars)
  return $rel.Replace([char]92,[char]47)
}

function PC-ListFilesRec([string]$Dir){
  if(-not (Test-Path -LiteralPath $Dir -PathType Container)){ PC-Die ("LISTFILES_MISSING_DIR: " + $Dir) }
  return @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force | Sort-Object FullName)
}

function PC-JsonEscape([string]$s){
  if($null -eq $s){ return "" }
  $sb = New-Object System.Text.StringBuilder
  foreach($ch in $s.ToCharArray()){
    $c = [int][char]$ch
    if($c -eq 34){ [void]$sb.Append([char]92); [void]$sb.Append([char]34); continue }
    if($c -eq 92){ [void]$sb.Append([char]92); [void]$sb.Append([char]92); continue }
    if($c -eq 8 ){ [void]$sb.Append([char]92); [void]$sb.Append([char]98); continue }
    if($c -eq 12){ [void]$sb.Append([char]92); [void]$sb.Append([char]102); continue }
    if($c -eq 10){ [void]$sb.Append([char]92); [void]$sb.Append([char]110); continue }
    if($c -eq 13){ [void]$sb.Append([char]92); [void]$sb.Append([char]114); continue }
    if($c -eq 9 ){ [void]$sb.Append([char]92); [void]$sb.Append([char]116); continue }
    if($c -lt 32){
      [void]$sb.AppendFormat("\u{0:x4}", $c)
      continue
    }
    [void]$sb.Append([char]$c)
  }
  return $sb.ToString()
}

function PC-IsEnumerable([object]$o){
  if($null -eq $o){ return $false }
  if($o -is [string]){ return $false }
  return ($o -is [System.Collections.IEnumerable])
}

function PC-ToCanonJson([object]$obj){
  $script:PC_JSON_SB = New-Object System.Text.StringBuilder

  function local:Emit([object]$v){
    if($null -eq $v){
      [void]$script:PC_JSON_SB.Append("null")
      return
    }

    if($v -is [bool]){
      if($v){ [void]$script:PC_JSON_SB.Append("true") } else { [void]$script:PC_JSON_SB.Append("false") }
      return
    }

    if($v -is [byte] -or $v -is [sbyte] -or $v -is [int16] -or $v -is [uint16] -or $v -is [int] -or $v -is [uint32] -or $v -is [int64] -or $v -is [uint64]){
      [void]$script:PC_JSON_SB.Append(([string]$v))
      return
    }

    if($v -is [double] -or $v -is [single] -or $v -is [decimal]){
      $num = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $v)
      [void]$script:PC_JSON_SB.Append($num)
      return
    }

    if($v -is [string]){
      [void]$script:PC_JSON_SB.Append([char]34)
      [void]$script:PC_JSON_SB.Append((PC-JsonEscape $v))
      [void]$script:PC_JSON_SB.Append([char]34)
      return
    }

    if($v -is [System.Collections.IDictionary]){
      [void]$script:PC_JSON_SB.Append([char]123)
      $keys = New-Object System.Collections.Generic.List[string]
      foreach($k in $v.Keys){
        if($null -eq $k){ PC-Die "CANONJSON_NULL_KEY" }
        [void]$keys.Add([string]$k)
      }
      $sorted = @($keys | Sort-Object)
      $first = $true
      foreach($k in $sorted){
        if(-not $first){ [void]$script:PC_JSON_SB.Append([char]44) } else { $first = $false }
        [void]$script:PC_JSON_SB.Append([char]34)
        [void]$script:PC_JSON_SB.Append((PC-JsonEscape $k))
        [void]$script:PC_JSON_SB.Append([char]34)
        [void]$script:PC_JSON_SB.Append([char]58)
        Emit $v[$k]
      }
      [void]$script:PC_JSON_SB.Append([char]125)
      return
    }

    if(PC-IsEnumerable $v){
      [void]$script:PC_JSON_SB.Append([char]91)
      $first = $true
      foreach($it in $v){
        if(-not $first){ [void]$script:PC_JSON_SB.Append([char]44) } else { $first = $false }
        Emit $it
      }
      [void]$script:PC_JSON_SB.Append([char]93)
      return
    }

    [void]$script:PC_JSON_SB.Append([char]34)
    [void]$script:PC_JSON_SB.Append((PC-JsonEscape ([string]$v)))
    [void]$script:PC_JSON_SB.Append([char]34)
  }

  Emit $obj
  return $script:PC_JSON_SB.ToString()
}

function PC-ComputePacketIdFromManifestNoIdCanon([string]$manifestCanonNoId){
  if($null -eq $manifestCanonNoId){ PC-Die "PACKETID_NULL_MANIFEST" }
  $canon = ($manifestCanonNoId -replace "`r`n","`n") -replace "`r","`n"
  if(-not $canon.EndsWith("`n")){
    $canon += "`n"
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $bytes = $enc.GetBytes($canon)
  return (PC-Sha256HexBytes $bytes)
}
