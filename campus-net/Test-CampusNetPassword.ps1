<#
    校园网密码「逐字符体检」工具

    它做的事情：
      1. 用和安装脚本一样的方式读入密码（默认显示 *，按 F2 切换显示明文，支持 Ctrl+V 粘贴）
      2. 逐字符列出 Unicode 编码，标出全角字符、空格、非英文字符
      3. 真实向门户提交一次，把门户的原始回复打出来，并给出结论
      4. 不保存任何东西，纯检查

    用法：双击 test-password.cmd，或
         powershell -ExecutionPolicy Bypass -File Test-CampusNetPassword.ps1
#>

[CmdletBinding()]
param(
    [string]$Account,
    [int]$Carrier = 0,            # 1=校园用户 2=校园电信(@dx) 3=校园联通(@lt)
    [string]$PortalHost = 'lan.bistu.edu.cn',
    [int]$PortalPort = 801,
    [int]$LegacyPort = 80
)

$ErrorActionPreference = 'Stop'
$Script:PortalHost = $PortalHost
$Script:LegacyPort = $LegacyPort
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Get-CharWarnings {
    param($Chars)
    $full = 0; $space = 0; $nonAscii = 0
    foreach ($c in $Chars) {
        $code = [int][char]$c
        if (($code -ge 0xFF01 -and $code -le 0xFF5E) -or $code -eq 0x3000) { $full++ }
        elseif ($code -eq 32) { $space++ }
        elseif ($code -gt 127) { $nonAscii++ }
    }
    $msgs = @()
    if ($full -gt 0) { $msgs += "【全角字符 $full 个】" }
    if ($space -gt 0) { $msgs += "【空格 $space 个】" }
    if ($nonAscii -gt 0) { $msgs += "【非英文字符 $nonAscii 个】" }
    return ($msgs -join '')
}

function Read-PasswordMasked {
    param([string]$Prompt = '请输入校园网密码')

    $canRaw = $false
    try { $canRaw = (-not [Console]::IsInputRedirected) -and ($Host.Name -eq 'ConsoleHost') } catch { $canRaw = $false }

    if (-not $canRaw) {
        $sec = Read-Host $Prompt -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }

    Write-Host ''
    Write-Host $Prompt -ForegroundColor Cyan
    Write-Host '   · 默认显示为 *；按 F2 切换【显示明文 / 重新隐藏】' -ForegroundColor DarkGray
    Write-Host '   · 支持 Ctrl+V 粘贴；Backspace 删一个字符；回车确认；Esc 取消' -ForegroundColor DarkGray
    Write-Host '   · 请先把输入法切到英文（半角），避免打出全角字符' -ForegroundColor DarkGray
    if ([Console]::CapsLock) { Write-Host '   ! 大写锁定（Caps Lock）现在开着' -ForegroundColor Yellow }

    $chars = New-Object 'System.Collections.Generic.List[char]'
    $visible = $false
    $prevWidth = 0

    while ($true) {
        $text = if ($visible) { '[' + (-join $chars) + ']' } else { '*' * $chars.Count }
        $warn = Get-CharWarnings -Chars $chars
        $line = '  > ' + $text + ('  ' + $warn)
        $pad = [Math]::Max(0, $prevWidth - $line.Length)
        [Console]::Write("`r" + $line + (' ' * $pad))
        $prevWidth = $line.Length

        $key = [Console]::ReadKey($true)

        if (($key.Modifiers -band [ConsoleModifiers]::Control) -and $key.Key.ToString() -eq 'V') {
            try {
                $clip = Get-Clipboard -Raw -ErrorAction Stop
                if ($clip) {
                    $first = ($clip -split "`r`n|`n|`r")[0]
                    foreach ($ch in $first.ToCharArray()) { if ([int][char]$ch -ge 32) { $chars.Add($ch) } }
                }
            } catch { }
            continue
        }

        switch ($key.Key.ToString()) {
            'Enter'    { [Console]::WriteLine(); return (-join $chars) }
            'Escape'   { [Console]::WriteLine(); return $null }
            'Backspace'{ if ($chars.Count -gt 0) { $chars.RemoveAt($chars.Count - 1) } }
            'F2'       { $visible = -not $visible }
            'F1'       { $visible = -not $visible }
            default {
                if ($key.KeyChar -and [int]$key.KeyChar -ge 32 -and [int]$key.KeyChar -ne 127) { $chars.Add($key.KeyChar) }
            }
        }
    }
}

function ConvertTo-UrlEncoded {
    param([string]$Value, [System.Text.Encoding]$Encoding)
    if ($null -eq $Encoding) { $Encoding = [System.Text.Encoding]::UTF8 }
    $bytes = $Encoding.GetBytes($Value)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        $isUnreserved = (($b -ge 48 -and $b -le 57) -or ($b -ge 65 -and $b -le 90) -or
                         ($b -ge 97 -and $b -le 122) -or $b -eq 45 -or $b -eq 46 -or $b -eq 95 -or $b -eq 126)
        if ($isUnreserved) { [void]$sb.Append([char]$b) } else { [void]$sb.AppendFormat('%{0:X2}', $b) }
    }
    return $sb.ToString()
}

function Send-Login {
    param([string]$Acct, [string]$EncodedPassword, [string]$Password, [string]$LocalIp, [string]$Mac)
    $epochMs = [int64](([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalMilliseconds)
    $q = 'callback=dr1003&login_method=1&user_account={0}&user_password={1}&wlan_user_ip={2}&wlan_user_ipv6=&wlan_user_mac={3}&wlan_user_vnode_ip=&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v={4}' -f
         (ConvertTo-UrlEncoded -Value (',0,' + $Acct) -Encoding ([System.Text.Encoding]::UTF8)), $EncodedPassword, $LocalIp, $Mac, $epochMs
    $url = 'http://{0}:{1}/eportal/portal/login?{2}' -f $PortalHost, $PortalPort, $q
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'
        $req.Timeout = 12000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $null
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
        $raw = $sr.ReadToEnd()
        $sr.Dispose(); $resp.Close()
        return $raw
    } catch {
        return "请求异常：$($_.Exception.Message)"
    }
}

function Send-LoginLegacy {
    param([string]$Acct, [string]$Password)
    $body = 'DDDDD={0}&upass={1}&R1=0&R2=0&R3=0&R6=0&para=00&0MKKey=123456&buttonClicked=&redirect_url=&err_flag=&username=&password=&user=&cmd=&Login=' -f
            (ConvertTo-UrlEncoded -Value $Acct -Encoding ([System.Text.Encoding]::UTF8)),
            (ConvertTo-UrlEncoded -Value $Password -Encoding ([System.Text.Encoding]::UTF8))
    try {
        $req = [System.Net.HttpWebRequest]::Create('http://' + $Script:PortalHost + ':' + $Script:LegacyPort + '/eportal/?c=ACSetting&a=Login')
        $req.Method = 'POST'
        $req.ContentType = 'application/x-www-form-urlencoded'
        $req.Timeout = 15000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $null
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($body)
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
        $resp = $req.GetResponse()
        $ms = New-Object System.IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        $resp.Close()
        $txt = ([System.Text.Encoding]::GetEncoding(936)).GetString($ms.ToArray())
        $ms.Dispose()
        $mark = [regex]::Match($txt, 'Dr\.COMWebLoginID_\d+\.htm').Value
        $code = [regex]::Match($txt, 'Msg=([^;]+)').Groups[1].Value.Trim()
        return "页面=$mark  Msg=$code"
    } catch { return "请求异常：$($_.Exception.Message)" }
}

# ================= 主流程 =================
Write-Host ''
Write-Host '=== 校园网密码逐字符体检 ===' -ForegroundColor Cyan

# 账号（可以从已有配置里读默认值）
$cfgPath = Join-Path $env:LOCALAPPDATA 'CampusNetAutoLogin\config.json'
$defAccount = ''
$defSuffix = ''
if (Test-Path -LiteralPath $cfgPath) {
    try {
        $cfg = Get-Content -LiteralPath $cfgPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($cfg.account) { $defAccount = [string]$cfg.account }
        if ($cfg.PSObject.Properties.Name.Contains('accountSuffix')) { $defSuffix = [string]$cfg.accountSuffix }
    } catch { }
}

if (-not $Account) {
    if ($defAccount) {
        $a = Read-Host "校园网账号（直接回车 = $defAccount）"
        if ([string]::IsNullOrWhiteSpace($a)) { $Account = $defAccount } else { $Account = $a.Trim() }
    } else {
        $a = Read-Host '校园网账号（学号）'
        while ([string]::IsNullOrWhiteSpace($a)) { $a = Read-Host '账号不能为空，请重新输入学号' }
        $Account = $a.Trim()
    }
}

if ($Carrier -eq 0 -and -not $defSuffix) {
    Write-Host ''
    Write-Host '登录方式： 1) 校园用户   2) 校园电信(@dx)   3) 校园联通(@lt)'
    $sel = Read-Host '输入 1/2/3（直接回车默认 1）'
    if ([string]::IsNullOrWhiteSpace($sel)) { $Carrier = 1 } else { $Carrier = [int]$sel }
} elseif ($Carrier -eq 0) {
    $Carrier = 1
}
switch ($Carrier) {
    1 { $suffix = '' }
    2 { $suffix = '@dx' }
    3 { $suffix = '@lt' }
    default { $suffix = $defSuffix }
}

$pw = Read-PasswordMasked -Prompt '请输入校园网密码'
if ($null -eq $pw) { Write-Host '已取消。'; exit 1 }
if ($pw.Length -eq 0) { Write-Host '密码为空。'; exit 1 }

# --- 逐字符检查 ---
Write-Host ''
Write-Host "账号：$Account$suffix       密码长度：$($pw.Length) 位" -ForegroundColor Cyan
Write-Host '逐字符检查：'
$sb = New-Object System.Text.StringBuilder
$idx = 0
foreach ($ch in $pw.ToCharArray()) {
    $idx++
    $code = [int][char]$ch
    $kind = '半角/正常'
    if ($code -eq 32) { $kind = '空格' }
    elseif (($code -ge 0xFF01 -and $code -le 0xFF5E) -or $code -eq 0x3000) { $kind = '★全角字符（很可能是这里出问题）' }
    elseif ($code -gt 127) { $kind = '非英文字符' }
    $show = $ch
    if ($code -eq 32) { $show = '␣' }
    "   [{0,2}]  {1}  U+{2:X4}   {3}" -f $idx, $show, $code, $kind
    [void]$sb.Append($code.ToString('X4') + ' ')
}
$warn = Get-CharWarnings -Chars $pw.ToCharArray()
if ($warn) { Write-Host "⚠ 警告：$warn" -ForegroundColor Yellow } else { Write-Host '✅ 没有全角字符、空格或非英文字符' -ForegroundColor Green }

# --- 真实提交 ---
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Sort-Object RouteMetric, ifIndex | Select-Object -First 1
$localIp = ''
if ($route) {
    $localIp = @(Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' })[0].IPAddress
}
$mac = '000000000000'
if ($localIp) {
    $addr = Get-NetIPAddress -IPAddress $localIp -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($addr) {
        $ad = Get-NetAdapter -InterfaceIndex $addr.InterfaceIndex -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ad) { $mac = ($ad.MacAddress -replace '[-:]', '').ToUpper() }
    }
}
Write-Host ''
Write-Host "本机校园网 IP：$localIp    网卡 MAC：$mac"

Write-Host ''
Write-Host '正在提交（不改动网络状态，只是发一次认证请求）...' -ForegroundColor Cyan

$encUtf8 = ConvertTo-UrlEncoded -Value $pw -Encoding ([System.Text.Encoding]::UTF8)
$raw1 = Send-Login -Acct $Account -EncodedPassword $encUtf8 -Password $pw -LocalIp $localIp -Mac $mac
Write-Host "① 普通编码  -> $raw1"

$raw2 = $null
if ($raw1 -match '用户名或密码错误|带有特殊字符') {
    $encDouble = $encUtf8 -replace '%', '%25'
    $raw2 = Send-Login -Acct $Account -EncodedPassword $encDouble -Password $pw -LocalIp $localIp -Mac $mac
    Write-Host "② 二次编码  -> $raw2"
}

$raw3 = $null
$hasNonAscii = $false
foreach ($ch in $pw.ToCharArray()) { if ([int][char]$ch -gt 127) { $hasNonAscii = $true; break } }
if ($hasNonAscii) {
    $encGbk = ConvertTo-UrlEncoded -Value $pw -Encoding ([System.Text.Encoding]::GetEncoding(936))
    $raw3 = Send-Login -Acct $Account -EncodedPassword $encGbk -Password $pw -LocalIp $localIp -Mac $mac
    Write-Host "③ GB2312编码 -> $raw3"
}

# 老版接口（80 端口 DrcomServer1.0）：没有特殊字符过滤器，密码带 & < > 时靠它
$raw4 = Send-LoginLegacy -Acct ($Account + $suffix) -Password $pw
Write-Host "④ 老接口(80端口) -> $raw4"

# --- 结论 ---
Write-Host ''
Write-Host '===== 结论 =====' -ForegroundColor Cyan
$all = @($raw1, $raw2, $raw3, $raw4) | Where-Object { $_ }
$success = $all | Where-Object { $_ -match '"result"\s*:\s*"?1"?' -or $_ -match 'Portal协议认证成功' -or $_ -match 'Dr\.COMWebLoginID_3\.htm' }
if ($success) {
    Write-Host '✅ 门户接受了这组账号密码，认证成功。' -ForegroundColor Green
    Write-Host '   说明密码输入方式没问题；如果安装脚本仍失败，把这里的结果发给我。'
} elseif ($all -match '用户名或密码错误') {
    Write-Host '❌ 门户明确回复：用户名或密码错误。' -ForegroundColor Red
    Write-Host '   请求本身被正常受理了（不是编码问题），是这串密码和学校记录不一致。'
    if ($warn) { Write-Host '   重点看上面的警告：全角字符 / 空格 / 非英文字符都会导致密码不对。' -ForegroundColor Yellow }
    Write-Host '   建议：改成用 Ctrl+V 直接粘贴密码，避免手打。'
} elseif ($all -match '带有特殊字符') {
    Write-Host '❌ 门户过滤器拦截了参数（密码里有 & < >）。' -ForegroundColor Red
    Write-Host '   普通编码和二次编码都被拦，需要换别的方式提交，请把上面的结果发给我。'
} else {
    Write-Host '⚠ 没有拿到明确结果，把上面③条原始回复发给我即可。' -ForegroundColor Yellow
}
Write-Host ''
Write-Host "（密码字符码：$($sb.ToString().Trim())）" -ForegroundColor DarkGray
Write-Host ''
exit 0
