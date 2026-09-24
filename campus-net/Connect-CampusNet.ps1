<#
    北京信息科技大学 校园网自动认证脚本（Dr.COM ePortal / 哆点）

    作用：直接向认证服务器提交账号密码，等同于打开浏览器在认证页点“登录”，
          不需要打开浏览器，也不需要等待页面跳转。

    支持有线和无线：
      · 用 Find-NetRoute 问系统“要去认证门户时实际从哪张网卡、哪个 IP 出去”，
        有线（以太网）和校园 Wi-Fi（BISTU 等）都能自动识别，不需要改配置。
      · 无线连接会额外带上 wlan_user_ssid 参数（认证服务器对无线口通常要求这个）。
      · 换网卡、换 IP、插拔网线、切换 Wi-Fi、DHCP 续约都不影响。
      · 连的是手机热点/家里路由等非校园网时，探不到门户会安静跳过，不会刷日志。

    用法：
        powershell -ExecutionPolicy Bypass -File Connect-CampusNet.ps1
        powershell -ExecutionPolicy Bypass -File Connect-CampusNet.ps1 -Force      # 已在线也重新认证
        powershell -ExecutionPolicy Bypass -File Connect-CampusNet.ps1 -Probe      # 只体检网卡和门户连通性，不认证
        powershell -ExecutionPolicy Bypass -File Connect-CampusNet.ps1 -Watch      # 常驻后台，定时检查

    退出码：0 = 已在线或认证成功；1 = 未成功；2 = 账号/密码问题
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$Force,
    [switch]$Interactive,   # 手动双击运行时用：成功 3 秒后自动关窗，失败停住显示原因
    [switch]$MachineScope,  # 密码改用“机器级”DPAPI 解密（供 SYSTEM 开机任务使用）
    [switch]$Probe,
    [switch]$Watch,
    [int]$WatchIntervalMinutes = 10,
    [int]$TimeoutMinutes = 0,
    [int]$IntervalSeconds = 0
)

$ErrorActionPreference = 'Stop'

$script:CnVersion = '1.1.0'

# ---------- 定位配置文件 ----------
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }

if (-not $ConfigPath) {
    $localCfg = Join-Path $scriptDir 'config.json'
    if (Test-Path -LiteralPath $localCfg) {
        $ConfigPath = $localCfg
    } else {
        $ConfigPath = Join-Path $env:LOCALAPPDATA 'CampusNetAutoLogin\config.json'
    }
}
$script:LogFile = Join-Path (Split-Path -Parent $ConfigPath) 'log.txt'
$script:UseMachineScope = [bool]$MachineScope

# ---------- 日志 ----------
function Write-CnLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($Level -eq 'ERROR') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    else { Write-Host $line }
    try {
        $dir = Split-Path -Parent $script:LogFile
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
        $all = @(Get-Content -LiteralPath $script:LogFile -ErrorAction SilentlyContinue)
        if ($all.Count -gt 400) {
            $all | Select-Object -Last 300 | Set-Content -LiteralPath $script:LogFile -Encoding UTF8
        }
    } catch { }
}

# ---------- 读取配置 ----------
function Get-CnConfig {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "找不到配置文件：$Path" }
    $cfg = (Get-Content -LiteralPath $Path -Raw -Encoding UTF8) | ConvertFrom-Json
    foreach ($field in @('portalHost', 'portalPort', 'account', 'passwordEncrypted')) {
        if (-not $cfg.PSObject.Properties.Name.Contains($field)) { throw "配置文件缺少字段：$field" }
    }
    if (-not $cfg.PSObject.Properties.Name.Contains('accountSuffix')) {
        $cfg | Add-Member -NotePropertyName accountSuffix -NotePropertyValue '' -Force
    }
    return $cfg
}

# ---------- 解密密码（DPAPI，只能被本机本用户解密） ----------
function Get-CnPassword {
    param($Cfg)
    if (-not $Cfg.passwordEncrypted) {
        throw '配置里还没有设置密码（或已被清空），请运行 install.cmd 重新输入账号密码。'
    }
    if ($script:UseMachineScope) {
        # 机器级 DPAPI：SYSTEM 也能解密，用于开机（未登录时）任务
        try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }
        $blob = [Convert]::FromBase64String($Cfg.passwordEncrypted)
        $plainBytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $blob, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [System.Text.Encoding]::UTF8.GetString($plainBytes)
    }
    $sec = ConvertTo-SecureString -String $Cfg.passwordEncrypted
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

# ---------- 解析认证门户的 IP ----------
function Get-PortalIPv4 {
    param($Cfg)
    try {
        $ips = @([System.Net.Dns]::GetHostAddresses($Cfg.portalHost) |
                 Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork })
        if ($ips.Count -gt 0) { return $ips[0].IPAddressToString }
    } catch { }
    if ($Cfg.PSObject.Properties.Name.Contains('portalFallbackHosts')) {
        foreach ($h in $Cfg.portalFallbackHosts) {
            if ($h -match '^\d+\.\d+\.\d+\.\d+$') { return $h }
        }
    }
    return $null
}

<#
    候选网卡列表（按“最可能就是校园网出口”的顺序）：
      1. Find-NetRoute 指向门户 IP 时实际使用的网卡 + 源 IP（有线和无线都会正确给出）
      2. 其余带默认网关的物理网卡，按路由/接口跃点排序
      3. 其余有 IPv4 的物理网卡
    虚拟网卡（VMware/Hyper-V/VPN/TAP 等）会被排除。
#>
# 取当前连接的真实 SSID（netsh 报的才是真正的 SSID，连接配置文件名字可能带后缀）
function Get-CurrentWlanSsid {
    try {
        $out = & netsh wlan show interfaces 2>$null
        foreach ($line in @($out)) {
            if ($line -match '^\s*SSID\s*:\s*(.+?)\s*$') { return $Matches[1] }
        }
    } catch { }
    return $null
}

function Get-NetCandidateList {
    param([string]$PortalIp)

    $pairs = New-Object System.Collections.Generic.List[object]

    if ($PortalIp) {
        try {
            $fr = @(Find-NetRoute -RemoteIPAddress $PortalIp -ErrorAction Stop)
            $src = $fr | Where-Object { $_.IPAddress -and $_.IPAddress -ne $PortalIp } | Select-Object -First 1
            if ($src -and $src.InterfaceIndex) {
                $pairs.Add([pscustomobject]@{ IfIndex = [int]$src.InterfaceIndex; IP = [string]$src.IPAddress })
            }
        } catch { }
    }

    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Sort-Object RouteMetric, InterfaceMetric, ifIndex)
    foreach ($r in $routes) { $pairs.Add([pscustomobject]@{ IfIndex = [int]$r.ifIndex; IP = $null }) }

    foreach ($a in @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                     Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' })) {
        $pairs.Add([pscustomobject]@{ IfIndex = [int]$a.InterfaceIndex; IP = [string]$a.IPAddress })
    }

    $result = New-Object System.Collections.Generic.List[object]
    $seen = @{}

    foreach ($p in $pairs) {
        if (-not $p.IfIndex) { continue }
        if ($seen.ContainsKey($p.IfIndex)) { continue }
        $seen[$p.IfIndex] = $true

        $ad = Get-NetAdapter -InterfaceIndex $p.IfIndex -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $ad) { continue }
        if ($ad.Status -ne 'Up') { continue }

        $desc = ''
        if ($ad.InterfaceDescription) { $desc = [string]$ad.InterfaceDescription }
        $name = ''
        if ($ad.Name) { $name = [string]$ad.Name }
        $whole = "$desc $name"
        if ($whole -match 'VMware|Hyper-V|VirtualBox|Loopback|TAP-|Tunneling|VPN|Sangfor|Bluetooth|Npcap|WAN Miniport') { continue }

        $ipAddr = $p.IP
        if (-not $ipAddr) {
            $ipAddr = @(Get-NetIPAddress -InterfaceIndex $p.IfIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.IPAddress -notlike '169.254.*' })[0].IPAddress
        }
        if (-not $ipAddr) { continue }
        if ($ipAddr -like '169.254.*') { continue }

        $mac = '000000000000'
        if ($ad.MacAddress) { $mac = ($ad.MacAddress -replace '[-:]', '').ToUpper() }

        $isWifi = [bool]($whole -match 'Wi-?Fi|Wireless|802\.11|WLAN')
        $ssid = $null
        if ($isWifi) { $ssid = Get-CurrentWlanSsid }
        if (-not $ssid) {
            $profile = Get-NetConnectionProfile -InterfaceIndex $p.IfIndex -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($profile -and $profile.Name) { $ssid = [string]$profile.Name }
        }

        $result.Add([pscustomobject]@{
            IfIndex    = $p.IfIndex
            Alias      = $name
            Desc       = $desc
            IP         = $ipAddr
            Mac        = $mac
            IsWireless = $isWifi
            SSID       = $ssid
        })
    }

    return $result
}

# ---------- 联网检测 ----------
# 两个要点：
#  1) 不要用 generate_204 / msftncsi / captive.apple.com 这类探测地址 —— 学校网关把它们
#     放进了 visit_blacklist（免重定向名单），未认证时也可能返回正常结果。
#  2) 光判断"返回 200 且内容够长"不够：网关拦截未认证流量时可能返回一个 200 的门户页，
#     会被误判成"已经在线"从而跳过认证 —— 表现就是"进了桌面还要自己手动连一次"。
#     所以再加两道校验：内容特征 + 门户页面识别。
function Test-InternetOnline {
    param([int]$TimeoutSec = 8)
    $targets = @(
        [pscustomobject]@{ Url = 'https://www.bing.com';  Code = 200; MinLen = 5000; Match = 'bing' },
        [pscustomobject]@{ Url = 'https://www.qq.com';    Code = 200; MinLen = 1000; Match = 'qq' },
        [pscustomobject]@{ Url = 'https://www.baidu.com'; Code = 200; MinLen = 100;  Match = 'baidu' }
    )
    # 校园网门户 / 认证页特征：出现这些说明其实还没认证（被网关劫持到了门户页）
    $portalMarkers = 'Dr\.COMWebLoginID|eportal|Portal协议|无法获取用户认证|用户名或密码错误|id="login"'
    foreach ($t in $targets) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($t.Url)
            $req.Method = 'GET'
            $req.Timeout = $TimeoutSec * 1000
            $req.ReadWriteTimeout = $TimeoutSec * 1000
            $req.AllowAutoRedirect = $false
            $req.Proxy = $null
            $req.KeepAlive = $false
            $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            $resp = $req.GetResponse()
            $code = [int]$resp.StatusCode
            $body = ''
            try {
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
                $body = $sr.ReadToEnd()
                $sr.Dispose()
            } catch { }
            $resp.Close()
            if ($code -eq $t.Code -and $body.Length -ge $t.MinLen) {
                if ($body -match $portalMarkers) { continue }            # 被劫持到门户页
                if ($t.Match -and $body -notmatch $t.Match) { continue } # 内容不对，疑似劫持页
                return $true
            }
        } catch { }
    }
    return $false
}

# ---------- 快速联网检测（认证成功后判断网关有没有真的放行） ----------
function Test-OnlineQuick {
    param([int]$TimeoutSec = 4)
    try {
        $req = [System.Net.HttpWebRequest]::Create('https://www.baidu.com')
        $req.Method = 'GET'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $null
        $req.KeepAlive = $false
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $sr.ReadToEnd()
        $sr.Dispose(); $resp.Close()
        return ($code -eq 200 -and $body.Length -ge 100)
    } catch { return $false }
}

# ---------- 按指定编码做 URL 百分号编码（逐字节） ----------
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

# ---------- 生成登录参数（正常编码；密码含中文时补一个 GB2312 版本） ----------
function Get-LoginQueryVariants {
    param($Cfg, [string]$Password, $Candidate)

    $account = '{0}{1}' -f $Cfg.account, $Cfg.accountSuffix
    $epochMs = [int64](([DateTime]::UtcNow - [DateTime]'1970-01-01').TotalMilliseconds)
    $acct = ConvertTo-UrlEncoded -Value (',0,' + $account) -Encoding ([System.Text.Encoding]::UTF8)

    $ssidParam = ''
    if ($Candidate -and $Candidate.IsWireless -and $Candidate.SSID) {
        $ssidParam = '&wlan_user_ssid=' + (ConvertTo-UrlEncoded -Value ([string]$Candidate.SSID) -Encoding ([System.Text.Encoding]::UTF8))
    }

    $build = {
        param($encodedPassword)
        'callback=dr1003&login_method=1&user_account={0}&user_password={1}&wlan_user_ip={2}&wlan_user_ipv6=&wlan_user_mac={3}&wlan_user_vnode_ip=&wlan_ac_ip=&wlan_ac_name={4}&jsVersion=4.1.3&terminal_type=1&lang=zh-cn&v={5}' -f
            $acct, $encodedPassword, $Candidate.IP, $Candidate.Mac, $ssidParam, $epochMs
    }

    $variants = New-Object System.Collections.Generic.List[object]

    # 1) 正常编码（UTF-8）
    $pwUtf8 = ConvertTo-UrlEncoded -Value $Password -Encoding ([System.Text.Encoding]::UTF8)
    $variants.Add([pscustomobject]@{ Kind = 'utf8'; Query = (& $build $pwUtf8) })

    # 2) 密码含中文时，再用 GB2312 编码试一次（门户页面是 gb2312）
    $hasNonAscii = $false
    foreach ($ch in $Password.ToCharArray()) { if ([int]$ch -gt 127) { $hasNonAscii = $true; break } }
    if ($hasNonAscii) {
        try {
            $pwGbk = ConvertTo-UrlEncoded -Value $Password -Encoding ([System.Text.Encoding]::GetEncoding(936))
            $variants.Add([pscustomobject]@{ Kind = 'gbk'; Query = (& $build $pwGbk) })
        } catch { }
    }

    return $variants
}

# ---------- 探测门户是否可达（不带账号密码，只发一个空请求） ----------
function Test-PortalReachable {
    param($Cfg, $Candidate, [int]$TimeoutSec = 6)
    $url = 'http://{0}:{1}/eportal/portal/login' -f $Cfg.portalHost, $Cfg.portalPort
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = 'GET'
        $req.Timeout = $TimeoutSec * 1000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $null
        $req.KeepAlive = $false
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $resp.Close()
        return $true
    } catch {
        return $false
    }
}

# ---------- 向认证服务器提交登录 ----------
function Invoke-PortalLogin {
    param($Cfg, [string]$Password, $Candidate, [int]$TimeoutSec = 10)

    $hosts = @($Cfg.portalHost)
    if ($Cfg.PSObject.Properties.Name.Contains('portalFallbackHosts')) {
        foreach ($h in $Cfg.portalFallbackHosts) { if ($h) { $hosts += $h } }
    }

    $variants = @(Get-LoginQueryVariants -Cfg $Cfg -Password $Password -Candidate $Candidate)
    $result = $null
    $reachable = $false

    foreach ($variant in $variants) {
        $raw = ''
        $lastError = ''
        foreach ($h in $hosts) {
            $url = 'http://{0}:{1}/eportal/portal/login?{2}' -f $h, $Cfg.portalPort, $variant.Query
            try {
                $req = [System.Net.HttpWebRequest]::Create($url)
                $req.Method = 'GET'
                $req.Timeout = $TimeoutSec * 1000
                $req.ReadWriteTimeout = $TimeoutSec * 1000
                $req.AllowAutoRedirect = $false
                $req.Proxy = $null
                $req.KeepAlive = $false
                $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                $resp = $req.GetResponse()
                $sr = New-Object System.IO.StreamReader($resp.GetResponseStream(), [System.Text.Encoding]::UTF8)
                $raw = $sr.ReadToEnd()
                $sr.Dispose()
                $resp.Close()
                $reachable = $true
                $lastError = ''
                break
            } catch {
                $lastError = $_.Exception.Message
                $raw = ''
            }
        }

        if (-not $raw) {
            $result = [pscustomobject]@{ Ok = $false; Msg = "无法连接认证服务器：$lastError"; Raw = ''; Kind = $variant.Kind; Reachable = $reachable }
            continue
        }

        $msg = $raw
        $ok = $false
        $jsonMatch = [regex]::Match($raw, '\{.*\}')
        if ($jsonMatch.Success) {
            try {
                $json = $jsonMatch.Value | ConvertFrom-Json
                if ($json.PSObject.Properties.Name.Contains('msg') -and $json.msg) { $msg = $json.msg }
                if ($json.PSObject.Properties.Name.Contains('result') -and ([int]$json.result -eq 1)) { $ok = $true }
            } catch { }
        }
        if (-not $ok -and $msg -match '已在线|已经在线|认证成功') { $ok = $true }

        $result = [pscustomobject]@{ Ok = $ok; Msg = $msg; Raw = $raw; Kind = $variant.Kind; Reachable = $true }
        if ($ok) { return $result }

        # 只有“账号密码错误”或“参数被特殊字符过滤”这两种情况值得换一种编码再试
        if ($msg -notmatch '用户名或密码错误|密码错误|账号或密码|带有特殊字符') { return $result }
    }

    # 新版接口没成：密码里带 & < > 会被过滤器拦，改用老接口（80 端口）再试一次
    $needLegacy = $false
    if ($result -and $result.Msg -match '带有特殊字符') { $needLegacy = $true }
    if (-not $needLegacy) {
        foreach ($ch in $Password.ToCharArray()) { if ('&<>'.IndexOf($ch) -ge 0) { $needLegacy = $true; break } }
    }
    if ($needLegacy) {
        $legacy = Invoke-PortalLoginLegacy -Cfg $Cfg -Password $Password -Candidate $Candidate
        if ($legacy.Ok) { return $legacy }
        if ($legacy.Reachable) { return $legacy }
        if (-not $result -or $result.Msg -match '带有特殊字符') { return $legacy }
    }

    return $result
}

<#
    老版哆点接口（80 端口，DrcomServer1.0）
    登录页自己声明的提交地址就是它：/eportal/?c=ACSetting&a=Login（字段名 DDDDD / upass）
    这个通道没有新版 nginx 那个“特殊字符”过滤器，密码里带 & < > 时只能走它。
    返回页面标记：Dr.COMWebLoginID_3.htm = 登录成功，_2.htm = 失败（带 Msg=xx 错误码）
#>
function Invoke-PortalLoginLegacy {
    param($Cfg, [string]$Password, $Candidate, [int]$TimeoutSec = 12)

    $account = '{0}{1}' -f $Cfg.account, $Cfg.accountSuffix
    $body = 'DDDDD={0}&upass={1}&R1=0&R2=0&R3=0&R6=0&para=00&0MKKey=123456&buttonClicked=&redirect_url=&err_flag=&username=&password=&user=&cmd=&Login=' -f
            (ConvertTo-UrlEncoded -Value $account -Encoding ([System.Text.Encoding]::UTF8)),
            (ConvertTo-UrlEncoded -Value $Password -Encoding ([System.Text.Encoding]::UTF8))

    $legacyPort = 80
    if ($Cfg.PSObject.Properties.Name.Contains('legacyPort') -and [int]$Cfg.legacyPort -gt 0) { $legacyPort = [int]$Cfg.legacyPort }

    $hosts = @($Cfg.portalHost)
    if ($Cfg.PSObject.Properties.Name.Contains('portalFallbackHosts')) {
        foreach ($h in $Cfg.portalFallbackHosts) { if ($h) { $hosts += $h } }
    }

    $codec = $null
    try { $codec = [System.Text.Encoding]::GetEncoding(936) } catch { $codec = [System.Text.Encoding]::UTF8 }

    $lastError = ''
    foreach ($h in $hosts) {
        $url = 'http://{0}:{1}/eportal/?c=ACSetting&a=Login' -f $h, $legacyPort
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = 'POST'
            $req.ContentType = 'application/x-www-form-urlencoded'
            $req.Timeout = $TimeoutSec * 1000
            $req.ReadWriteTimeout = $TimeoutSec * 1000
            $req.AllowAutoRedirect = $false
            $req.Proxy = $null
            $req.KeepAlive = $false
            $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            $payload = [System.Text.Encoding]::ASCII.GetBytes($body)
            $req.ContentLength = $payload.Length
            $stream = $req.GetRequestStream()
            $stream.Write($payload, 0, $payload.Length)
            $stream.Close()
            $resp = $req.GetResponse()
            $ms = New-Object System.IO.MemoryStream
            $resp.GetResponseStream().CopyTo($ms)
            $resp.Close()
            $text = $codec.GetString($ms.ToArray())
            $ms.Dispose()
        } catch {
            $lastError = $_.Exception.Message
            continue
        }

        if ($text -match '带有特殊字符') {
            return [pscustomobject]@{ Ok = $false; Msg = '老接口也被特殊字符过滤器拦截'; Raw = ''; Kind = 'legacy'; Reachable = $true }
        }

        $ok = ($text -match 'Dr\.COMWebLoginID_3\.htm') -or ($text -match 'page\.run\(\s*3\s*\)')
        if ($ok) {
            return [pscustomobject]@{ Ok = $true; Msg = '认证成功（老接口）'; Raw = ''; Kind = 'legacy'; Reachable = $true }
        }
        $code = [regex]::Match($text, 'Msg=([^;]+)').Groups[1].Value.Trim()
        return [pscustomobject]@{ Ok = $false; Msg = "账号或密码错误（老接口 Msg=$code）"; Raw = ''; Kind = 'legacy'; Reachable = $true }
    }

    return [pscustomobject]@{ Ok = $false; Msg = "老接口无法连接：$lastError"; Raw = ''; Kind = 'legacy'; Reachable = $false }
}

# ================= 网卡体检（-Probe） =================
function Invoke-Probe {
    param($Cfg)
    $portalIp = Get-PortalIPv4 -Cfg $Cfg
    Write-Host ''
    Write-Host '=== 认证门户 ===' -ForegroundColor Cyan
    Write-Host ("域名：{0}:{1}" -f $Cfg.portalHost, $Cfg.portalPort)
    Write-Host ("解析 IP：{0}" -f $(if ($portalIp) { $portalIp } else { '解析失败' }))

    $cands = @(Get-NetCandidateList -PortalIp $portalIp)
    Write-Host ''
    Write-Host '=== 候选网卡（按优先级） ===' -ForegroundColor Cyan
    if ($cands.Count -eq 0) {
        Write-Host '（没有找到可用的物理网卡）' -ForegroundColor Yellow
    }
    $i = 0
    foreach ($c in $cands) {
        $i++
        $netKind = '有线'
        if ($c.IsWireless) { $netKind = '无线' }
        $ssidText = ''
        if ($c.IsWireless -and $c.SSID) { $ssidText = "  SSID=$($c.SSID)" }
        $mark = ''
        if ($i -eq 1) { $mark = '   <= 系统去门户时走的就是这张' }
        Write-Host ("[{0}] {1,-8} {2,-16} {3}  MAC={4}{5}{6}" -f $i, $c.Alias, $c.IP, $netKind, $c.Mac, $ssidText, $mark)
    }

    Write-Host ''
    Write-Host '=== 门户连通性（不涉及账号密码） ===' -ForegroundColor Cyan
    if ($cands.Count -gt 0) {
        if (Test-PortalReachable -Cfg $Cfg -Candidate $cands[0] -TimeoutSec 6) {
            Write-Host ('  ' + $cands[0].Alias + ' (' + $cands[0].IP + ') -> 能访问认证门户') -ForegroundColor Green
        } else {
            Write-Host ('  ' + $cands[0].Alias + ' (' + $cands[0].IP + ') -> 连不上认证门户（不在校园网？）') -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host '=== 当前联网状态 ===' -ForegroundColor Cyan
    if (Test-InternetOnline -TimeoutSec 6) {
        Write-Host '  已经能上外网（不需要认证）' -ForegroundColor Green
    } else {
        Write-Host '  目前不能上外网（需要认证）' -ForegroundColor Yellow
    }
    Write-Host ''
}

# ================= 一次完整的“检查 + 认证” =================
function Invoke-ConnectCycle {
    param($Cfg, [int]$TimeoutMin, [int]$IntervalSec, [bool]$ForceRun, [bool]$QuietOnline = $false)

    if (-not $ForceRun) {
        if (Test-InternetOnline -TimeoutSec 5) {
            if (-not $QuietOnline) { Write-CnLog '网络已连通，无需认证。' }
            return 0
        }
    }

    $password = Get-CnPassword -Cfg $Cfg
    $deadline = (Get-Date).AddMinutes($TimeoutMin)
    $attempt = 0
    $lastMsg = ''
    $portalSeen = $false
    $noNicLogged = $false

    while ($true) {
        $attempt++

        # 每轮都重新找网卡：如果这次跑得太早（网卡 / IP 还没就绪），下一轮会自己恢复。
        # 旧版本在这里直接 return 1 放弃，这是"进了桌面偶尔还得手动连一次"的原因之一。
        $portalIp = Get-PortalIPv4 -Cfg $Cfg
        $candidates = @(Get-NetCandidateList -PortalIp $portalIp)
        if ($candidates.Count -eq 0) {
            $lastMsg = '还没找到可用的物理网卡'
            if (-not $noNicLogged) {
                Write-CnLog '还没找到可用的物理网卡（网线未插或 Wi-Fi 还没连上？），会继续重试。' 'WARN'
                $noNicLogged = $true
            }
            if ((Get-Date) -ge $deadline) { break }
            Start-Sleep -Seconds $IntervalSec
            continue
        }

        $used = $null
        $result = $null

        foreach ($cand in $candidates) {
            $netKind = '有线'
            if ($cand.IsWireless) { $netKind = '无线' }
            $ssidText = ''
            if ($cand.IsWireless -and $cand.SSID) { $ssidText = "（SSID $($cand.SSID)）" }
            if ($attempt -eq 1) {
                Write-CnLog "尝试 $($cand.Alias) $netKind$ssidText：$($cand.IP)"
            }
            $r = Invoke-PortalLogin -Cfg $Cfg -Password $password -Candidate $cand
            if ($r -and $r.Reachable) {
                $result = $r
                $used = $cand
                $portalSeen = $true
                break
            }
            $result = $r
            $used = $cand
        }

        if ($result -and $result.Ok) {
            $netKind = '有线'
            if ($used.IsWireless) { $netKind = '无线' }
            Write-CnLog "认证返回：$($result.Msg)（$netKind $($used.IP)）"
            Write-CnLog '门户已放行，正在等待网络真正连通（无线一般需要几秒）...'

            # 认证成功后网关（尤其无线口）往往还要几秒才真正开闸，这里反复探测，
            # 避免出现“认证成功但检测未通过”这种假警告、也避免重复提交登录。
            $online = $false
            for ($k = 1; $k -le 6; $k++) {
                Start-Sleep -Seconds 2
                if (Test-OnlineQuick -TimeoutSec 4) { $online = $true; break }
            }
            if (-not $online) { $online = Test-InternetOnline -TimeoutSec 6 }

            if ($online) {
                Write-CnLog '校园网已连通，认证完成。'
                return 0
            }
            $lastMsg = '认证已提交，但联网检测未通过'
            Write-CnLog $lastMsg 'WARN'
        }
        elseif ($portalSeen) {
            $lastMsg = $result.Msg
            Write-CnLog "认证失败：$($result.Msg)" 'WARN'
            if ($result.Msg -match '带有特殊字符') {
                Write-CnLog '密码里含有门户拦截的字符（& < >），新版接口和老版接口都没通过，请检查密码内容。' 'ERROR'
                return 2
            }
            if ($result.Msg -match '用户名或密码错误|密码错误|账号或密码|用户不存在') {
                Write-CnLog '账号或密码不正确，停止重试。请重新运行安装脚本填写正确的账号密码。' 'ERROR'
                return 2
            }
        }
        else {
            $lastMsg = '连不上认证服务器'
            if ($attempt -eq 1) {
                Write-CnLog '当前看起来不在校园网范围内（连不上认证服务器），本次跳过。' 'WARN'
            }
            # 给"网络刚起来、门户还没就绪"留几次机会；仍然连不上就提前结束本轮，
            # 交给守护进程稍后重试（避免不在校园网时把整轮超时白跑满、刷日志）
            if ($attempt -ge 3) {
                Write-CnLog '连不上认证服务器，本轮提前结束，稍后自动重试。'
                return 1
            }
        }

        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds $IntervalSec
    }

    if (-not $portalSeen) {
        Write-CnLog "在 $TimeoutMin 分钟内都没有探到认证服务器（可能不在校园网），结束本次。"
        return 1
    }
    Write-CnLog "在 $TimeoutMin 分钟内未能完成认证（最后信息：$lastMsg）。" 'ERROR'
    return 1
}

# ---------- 同一时间只允许一个实例真正干活 ----------
function Invoke-WithLock {
    param([scriptblock]$Action, [int]$WaitSeconds = 45)
    $created = $false
    $mtx = $null
    $got = $false
    $t0 = Get-Date
    try {
        $mtx = New-Object System.Threading.Mutex($false, 'Local\CampusNetAutoLogin', [ref]$created)
        # 旧版本是 WaitOne(0) 瞬时跳过且只写控制台，日志里查不到，出问题没法定位。
        # 现在最多等 WaitSeconds 秒（并发触发时不会白跑一次），并记进日志。
        $got = $mtx.WaitOne([Math]::Max(0, $WaitSeconds) * 1000)
        if (-not $got) {
            Write-CnLog "另一个实例运行超过 $WaitSeconds 秒仍未结束，本次跳过。" 'WARN'
            return 0
        }
        $waited = ((Get-Date) - $t0).TotalSeconds
        if ($waited -gt 1) { Write-CnLog ('等待前一个实例结束用了 {0} 秒。' -f [int]$waited) }
        return (& $Action)
    } finally {
        if ($mtx) {
            if ($got) { try { $mtx.ReleaseMutex() } catch { } }
            try { $mtx.Dispose() } catch { }
        }
    }
}

# ================= 主流程 =================
$exitCode = 0
try {
    $cfg = Get-CnConfig -Path $ConfigPath

    if ($TimeoutMinutes -le 0) {
        if ($cfg.PSObject.Properties.Name.Contains('timeoutMinutes') -and [int]$cfg.timeoutMinutes -gt 0) { $TimeoutMinutes = [int]$cfg.timeoutMinutes } else { $TimeoutMinutes = 10 }
    }
    if ($IntervalSeconds -le 0) {
        if ($cfg.PSObject.Properties.Name.Contains('intervalSeconds') -and [int]$cfg.intervalSeconds -gt 0) { $IntervalSeconds = [int]$cfg.intervalSeconds } else { $IntervalSeconds = 10 }
    }

    if ($Probe) {
        Invoke-Probe -Cfg $cfg
        $exitCode = 0
    }
    elseif ($Watch) {
        # 守护进程单例：计划任务和启动文件夹可能同时拉起，只允许一个真正常驻。
        # 有了它，计划任务也能安全地用 -Watch 启动：守护进程活着就退出，
        # 被杀掉 / 崩溃了就自动补上（自愈），不必再依赖启动文件夹。
        $watchCreated = $false
        $watchMtx = $null
        $watchGot = $false
        try {
            $watchMtx = New-Object System.Threading.Mutex($false, 'Local\CampusNetAutoLoginWatcher', [ref]$watchCreated)
            $watchGot = $watchMtx.WaitOne(0)
        } catch { }
        if (-not $watchGot) {
            Write-CnLog '已有守护进程在运行，本次不再重复启动。'
            exit 0
        }

        # 守护模式：监听网络变化事件（插网线 / 连 Wi-Fi / 睡眠唤醒 / DHCP 变化），
        # 一变就马上检查；另外每 60 秒用极轻的请求快查一次。
        Write-CnLog ("守护模式启动（v{0}）：监听网络变化，并每 60 秒轻量检查一次。" -f $script:CnVersion)

        $signal = New-Object System.Threading.ManualResetEvent($false)
        try {
            if (-not ('CampusNet.NetWatcher' -as [type])) {
                Add-Type -TypeDefinition @'
using System;
using System.Net.NetworkInformation;
using System.Threading;
namespace CampusNet {
    public sealed class NetWatcher {
        private readonly ManualResetEvent _evt;
        public NetWatcher(ManualResetEvent evt) {
            _evt = evt;
            NetworkChange.NetworkAddressChanged += OnChange;
            NetworkChange.NetworkAvailabilityChanged += OnChange;
        }
        private void OnChange(object sender, EventArgs e) { try { _evt.Set(); } catch { } }
    }
}
'@
            }
            $null = New-Object CampusNet.NetWatcher($signal)
        } catch {
            Write-CnLog "网络变化监听没装上，改用 60 秒轮询：$($_.Exception.Message)" 'WARN'
        }

        while ($true) {
            try {
                if ($signal.WaitOne(60000)) {
                    [void]$signal.Reset()
                    Start-Sleep -Seconds 3   # 给 DHCP / 无线关联留点时间
                }
            } catch { Start-Sleep -Seconds 60 }

            if (Test-OnlineQuick -TimeoutSec 4) { continue }   # 能上网就不动

            try {
                $null = Invoke-WithLock { Invoke-ConnectCycle -Cfg $cfg -TimeoutMin $TimeoutMinutes -IntervalSec $IntervalSeconds -ForceRun $false -QuietOnline $true }
            } catch {
                Write-CnLog "守护模式本轮异常：$($_.Exception.Message)" 'WARN'
            }
        }
    }
    else {
        $exitCode = Invoke-WithLock { Invoke-ConnectCycle -Cfg $cfg -TimeoutMin $TimeoutMinutes -IntervalSec $IntervalSeconds -ForceRun ([bool]$Force) }
    }
}
catch {
    Write-CnLog "脚本异常：$($_.Exception.Message)" 'ERROR'
    $exitCode = 1
}

# 手动双击运行时：成功就 3 秒后自动关窗，失败就停住让你看清原因
if ($Interactive -and -not $Watch) {
    if ($exitCode -eq 0) {
        Write-Host ''
        Write-Host '认证成功，窗口将在 3 秒后自动关闭。' -ForegroundColor Green
        Start-Sleep -Seconds 3
    }
    else {
        Write-Host ''
        Write-Host '这次没有认证成功，请把上面的内容截图；按任意键关闭窗口...' -ForegroundColor Yellow
        try { $null = [Console]::ReadKey($true) } catch { Start-Sleep -Seconds 30 }
    }
}

exit $exitCode
