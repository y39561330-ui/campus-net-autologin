<#
    北京信息科技大学 校园网自动登录 —— 安装脚本

    做的事情：
      1. 询问校园网账号、密码
         · 密码默认不显示，按 F2 可以切换“显示明文 / 重新隐藏”
         · 先向门户验证一次，密码错了会让你当场重输（最多 4 次），不会带着错密码装上去
      2. 密码用 Windows DPAPI 加密保存，只有本机本用户能解密
      3. 写入启动项（不用管理员，开机登录就自动认证）
      4. 尝试注册计划任务（会弹一次 UAC，用于断线后每 10 分钟自动重连）
         没授权也没关系，会自动改成后台守护模式，功能一样

    用法：双击同目录下的 install.cmd，或
         powershell -ExecutionPolicy Bypass -File Install-CampusNetAutoLogin.ps1
#>

[CmdletBinding()]
param(
    [string]$Account,
    [int]$Carrier = 0,               # 1=校园用户 2=校园电信(@dx) 3=校园联通(@lt)
    [int]$IntervalMinutes = 10,      # 断线检查间隔
    [int]$TimeoutMinutes = 5,        # 每次开机认证最多尝试多久
    [switch]$SkipValidate,
    [switch]$Boot,        # 直接启用“开机未登录也联网”，不再询问
    [switch]$SkipBoot,    # 不问也不启用
    [switch]$SkipTask
)

$ErrorActionPreference = 'Stop'

$installDir = Join-Path $env:LOCALAPPDATA 'CampusNetAutoLogin'
$configPath = Join-Path $installDir 'config.json'
$taskName   = 'CampusNetAutoLogin'
$portalHost = 'lan.bistu.edu.cn'
$portalPort = 801

Write-Host ''
Write-Host '=== 校园网自动登录 · 安装 (v1.1.0) ===' -ForegroundColor Cyan

function New-Shortcut {
    param([string]$Path, [string]$Target, [string]$Arguments, [string]$WorkDir, [string]$Icon, [string]$Description)
    $ws = New-Object -ComObject WScript.Shell
    $lnk = $ws.CreateShortcut($Path)
    $lnk.TargetPath = $Target
    $lnk.Arguments = $Arguments
    if ($WorkDir) { $lnk.WorkingDirectory = $WorkDir }
    if ($Icon) { $lnk.IconLocation = $Icon }
    if ($Description) { $lnk.Description = $Description }
    $lnk.Save()
}

<#
    密码输入：默认显示 *，按 F2 切换“显示明文 / 重新隐藏”，Backspace 删除，回车确认，Esc 取消。
    返回明文字符串；按 Esc 返回 $null。
#>
# 检查密码里有没有“看着一样但实际不同”的字符（全角、空格、非英文）
# 机器级加密（SYSTEM 也能解密），供开机（未登录）任务使用
function Protect-MachinePassword {
    param([string]$Plain)
    try { Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue } catch { }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    $enc = [System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($enc)
}

# 看看这台机器当前是不是已经有活跃的在线会话（门户首页会带 uid='账号'）
function Get-PortalOnlineAccount {
    param([string]$PortalHost)
    try {
        $req = [System.Net.HttpWebRequest]::Create('http://' + $PortalHost + '/')
        $req.Method = 'GET'
        $req.Timeout = 6000
        $req.AllowAutoRedirect = $false
        $req.Proxy = $null
        $req.KeepAlive = $false
        $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
        $resp = $req.GetResponse()
        $ms = New-Object System.IO.MemoryStream
        $resp.GetResponseStream().CopyTo($ms)
        $resp.Close()
        $txt = ([System.Text.Encoding]::GetEncoding(936)).GetString($ms.ToArray())
        $ms.Dispose()
        $m = [regex]::Match($txt, "uid='([^']*)'")
        if ($m.Success) { return $m.Groups[1].Value }
    } catch { }
    return $null
}

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
    try {
        $canRaw = (-not [Console]::IsInputRedirected) -and ($Host.Name -eq 'ConsoleHost')
    } catch { $canRaw = $false }

    if (-not $canRaw) {
        # 没有真实控制台时退回系统自带隐藏输入
        $sec = Read-Host $Prompt -AsSecureString
        $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
    }

    Write-Host ''
    Write-Host $Prompt -ForegroundColor Cyan
    Write-Host '   · 默认显示为 *，按 F2 切换【显示明文 / 重新隐藏】' -ForegroundColor DarkGray
    Write-Host '   · 支持 Ctrl+V 粘贴；Backspace 删一个字符；回车确认；Esc 取消' -ForegroundColor DarkGray
    Write-Host '   · 请先把输入法切到英文（半角），全角字符会导致密码不对' -ForegroundColor DarkGray
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

# ---------- 复制运行脚本 ----------
$sourceScript = Join-Path $PSScriptRoot 'Connect-CampusNet.ps1'
if (-not (Test-Path -LiteralPath $sourceScript)) {
    Write-Host '找不到 Connect-CampusNet.ps1，请把它和本脚本放在同一个文件夹里。' -ForegroundColor Red
    exit 1
}
if (-not (Test-Path -LiteralPath $installDir)) { New-Item -ItemType Directory -Force -Path $installDir | Out-Null }
$targetScript = Join-Path $installDir 'Connect-CampusNet.ps1'
Copy-Item -LiteralPath $sourceScript -Destination $targetScript -Force
Write-Host "运行脚本：$targetScript"

# 无窗口启动器（wscript 调用，彻底不闪控制台窗口）
$sourceVbs = Join-Path $PSScriptRoot 'RunHidden.vbs'
$targetVbs  = Join-Path $installDir 'RunHidden.vbs'
if (Test-Path -LiteralPath $sourceVbs) {
    Copy-Item -LiteralPath $sourceVbs -Destination $targetVbs -Force
} else {
    Write-Host '  （没找到 RunHidden.vbs，将退回直接调用 powershell，任务运行时可能会闪现窗口）' -ForegroundColor Yellow
    $targetVbs = $null
}

# ---------- 门户地址 ----------
$fallbackHosts = @()
try {
    $resolved = @(Resolve-DnsName -Name $portalHost -Type A -ErrorAction Stop |
                  Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress | Select-Object -Unique)
    $fallbackHosts = @($resolved)
    if ($fallbackHosts.Count -gt 0) { Write-Host "认证门户：$portalHost（备用 IP：$($fallbackHosts -join ', ')）" }
} catch { Write-Host "认证门户：$portalHost" }

# ---------- 账号 ----------
$existing = $null
if (Test-Path -LiteralPath $configPath) {
    try { $existing = (Get-Content -LiteralPath $configPath -Raw -Encoding UTF8) | ConvertFrom-Json } catch { }
}

if (-not $Account) {
    $defaultAccount = ''
    if ($existing -and $existing.account) { $defaultAccount = [string]$existing.account }
    $prompt = '请输入校园网账号'
    if ($defaultAccount) { $prompt += "（直接回车沿用 $defaultAccount）" }
    $inputAccount = Read-Host $prompt
    if ([string]::IsNullOrWhiteSpace($inputAccount)) { $inputAccount = $defaultAccount }
    $Account = $inputAccount.Trim()
}
if (-not $Account) { Write-Host '账号不能为空。' -ForegroundColor Red; exit 1 }
Write-Host "账号：$Account"

# ---------- 登录方式（运营商） ----------
if ($Carrier -eq 0) {
    Write-Host ''
    Write-Host '请选择登录方式：'
    Write-Host '  1) 校园用户（大多数同学选这个，账号后面不加后缀）'
    Write-Host '  2) 校园电信（账号后加 @dx）'
    Write-Host '  3) 校园联通（账号后加 @lt）'
    $sel = Read-Host '输入 1/2/3（直接回车默认 1）'
    if ([string]::IsNullOrWhiteSpace($sel)) { $Carrier = 1 } else { $Carrier = [int]$sel }
}
switch ($Carrier) {
    2 { $suffix = '@dx'; $carrierName = '校园电信' }
    3 { $suffix = '@lt'; $carrierName = '校园联通' }
    default { $suffix = ''; $carrierName = '校园用户' }
}
Write-Host "登录方式：$carrierName（提交的账号：$Account$suffix）"

# ---------- 密码：输入 + 当场验证 + 错了重输 ----------
$credOk = $null
$maxAttempts = 4

# 先看看这台机器是不是已经有在线会话（影响“验证通过”的可信度）
$onlineBefore = Get-PortalOnlineAccount -PortalHost $portalHost
if ($onlineBefore) { Write-Host "提示：检测到本机当前已经有在线会话（账号 $onlineBefore）。" -ForegroundColor DarkGray }

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    if ($attempt -gt 1) { Write-Host '' ; Write-Host "第 $attempt 次输入密码：" -ForegroundColor Cyan }

    $plain = Read-PasswordMasked -Prompt '请输入校园网密码'
    if ($null -eq $plain) { Write-Host '已取消安装。' -ForegroundColor Yellow; exit 1 }
    if ($plain.Length -eq 0) { Write-Host '密码为空，请重新输入。' -ForegroundColor Yellow; continue }

    Write-Host ("   密码长度 {0} 位，已加密保存。" -f $plain.Length) -ForegroundColor DarkGray
    $pwWarn = Get-CharWarnings -Chars $plain.ToCharArray()
    if ($pwWarn) { Write-Host "   警告：$pwWarn  —— 全角字符和空格经常就是验证失败的原因" -ForegroundColor Yellow }

    $secure = ConvertTo-SecureString $plain -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString -SecureString $secure
    # $plain 先留着，后面如果要装“开机任务”还需要它；安装结束前会清空

    $config = [ordered]@{
        portalHost          = $portalHost
        portalFallbackHosts = $fallbackHosts
        portalPort          = $portalPort
        account             = $Account
        accountSuffix       = $suffix
        carrierName         = $carrierName
        passwordEncrypted   = $encrypted
        intervalSeconds     = 10
        timeoutMinutes      = $TimeoutMinutes
        installedAt         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
    [System.IO.File]::WriteAllText($configPath, ($config | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))

    if ($SkipValidate) { break }

    Write-Host '正在向校园网关验证这组账号密码...' -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $targetScript -ConfigPath $configPath -Force -TimeoutMinutes 1 -IntervalSeconds 4
    $code = $LASTEXITCODE

    if ($code -eq 0) {
        $credOk = $true
        Write-Host '验证通过：认证成功。' -ForegroundColor Green
        if ($onlineBefore) {
            Write-Host '   但注意：刚检测到本机已经有在线会话，门户对“已在线 IP”有时会直接返回成功，' -ForegroundColor DarkGray
            Write-Host '   所以这个结果只能作为参考。想严格确认密码，可以先到 https://lan.bistu.edu.cn 点“注销”，' -ForegroundColor DarkGray
            Write-Host '   再运行一次 install.cmd 验证（那时才是真正走一遍登录流程）。' -ForegroundColor DarkGray
        } else {
            Write-Host '   刚才是从“未登录”状态真正登录成功的，说明账号密码确实正确。' -ForegroundColor Green
        }
        break
    }
    if ($code -eq 2) {
        $credOk = $false
        Write-Host '验证失败：门户返回「用户名或密码错误」。' -ForegroundColor Red
        Write-Host '   排查顺序：① 按 F2 显示一下刚才输入的密码有没有打错；② 大写锁定是否开着；③ 登录方式（校园用户/电信/联通）是否选错。' -ForegroundColor DarkGray
        if ($attempt -ge $maxAttempts) { break }
        $again = Read-Host '重新输入密码？(直接回车 = 重新输入；输入 n = 不再重试)'
        if ($again -match '^\s*n') { break }
        continue
    }

    $credOk = $null
    Write-Host '无法确认结果（门户没有返回明确成败），可能是网络刚断开或门户暂时不通，继续安装。' -ForegroundColor Yellow
    break
}

if ($credOk -eq $false) {
    Write-Host ''
    $go = Read-Host '密码仍未通过验证，还要继续安装吗？（开机后同样会认证失败）(y/N)'
    if ($go -notmatch '^\s*y') {
        Write-Host '已取消安装，没有写入启动项。修正密码后重新运行 install.cmd 即可。' -ForegroundColor Yellow
        exit 2
    }
}

# ---------- 启动项：不需要管理员，开机登录就能跑 ----------
$startupDir = [Environment]::GetFolderPath('Startup')
$startupLnk = Join-Path $startupDir '校园网自动登录.lnk'
if ($targetVbs) {
    # 守护模式：监听网络变化（插网线/连 Wi-Fi/睡眠唤醒）立即认证，并每 60 秒轻量检查
    $runArgs = '//B //Nologo "{0}" -Watch -TimeoutMinutes 2 -IntervalSeconds 5' -f $targetVbs
    New-Shortcut -Path $startupLnk -Target 'wscript.exe' -Arguments $runArgs -WorkDir $installDir -Icon 'shell32.dll,17' -Description '校园网自动登录（后台守护·无窗口）'
} else {
    $runArgs = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -TimeoutMinutes {1}' -f $targetScript, $TimeoutMinutes
    New-Shortcut -Path $startupLnk -Target 'powershell.exe' -Arguments $runArgs -WorkDir $installDir -Icon 'shell32.dll,17' -Description '登录 Windows 后自动认证校园网'
}
Write-Host ''
Write-Host "已加入启动项：$startupLnk" -ForegroundColor Green

# ---------- 计划任务：断线自动重连（需要一次 UAC） ----------
# ---------- 可选：开机（未登录 Windows 时）也能联网 ----------
$bootScript = $null
$bootConfig = $null
$wantBoot = $false
if ($Boot) { $wantBoot = $true }
elseif (-not $SkipBoot) {
    Write-Host ''
    Write-Host '可选：让“开机后、还没登录 Windows（锁屏界面）”的那段时间也有网。' -ForegroundColor Cyan
    Write-Host '      做法：把你的密码再存一份“机器级加密”的副本，交给 SYSTEM 身份的开机任务使用。' -ForegroundColor DarkGray
    Write-Host '      代价：这台电脑上的其他账户理论上也能解密这份副本（用户级那份不受影响）。' -ForegroundColor DarkGray
    $ans = Read-Host '要启用吗？(Y/n)'
    if ($ans -notmatch '^\s*n') { $wantBoot = $true }
}

if ($wantBoot -and $plain) {
    try {
        $progDir = Join-Path $env:ProgramData 'CampusNetAutoLogin'
        if (-not (Test-Path -LiteralPath $progDir)) { New-Item -ItemType Directory -Force -Path $progDir | Out-Null }
        $bootScript = Join-Path $progDir 'Connect-CampusNet.ps1'
        $bootConfig = Join-Path $progDir 'config.json'
        Copy-Item -LiteralPath $targetScript -Destination $bootScript -Force

        $bootCfg = [ordered]@{
            portalHost          = $portalHost
            portalFallbackHosts = $fallbackHosts
            portalPort          = $portalPort
            legacyPort          = 80
            account             = $Account
            accountSuffix       = $suffix
            carrierName         = $carrierName
            passwordEncrypted   = (Protect-MachinePassword -Plain $plain)
            intervalSeconds     = 10
            timeoutMinutes      = 2
            installedAt         = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            scope               = 'machine'
        }
        [System.IO.File]::WriteAllText($bootConfig, ($bootCfg | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "已准备开机任务所需文件：$progDir" -ForegroundColor Green
    } catch {
        Write-Host "准备开机任务失败（改为只装用户级）：$($_.Exception.Message)" -ForegroundColor Yellow
        $bootScript = $null; $bootConfig = $null
    }
}

$helper = Join-Path $PSScriptRoot 'Register-CampusNetTask.ps1'
$taskOk = $false
if (-not $SkipTask -and (Test-Path -LiteralPath $helper) -and $IntervalMinutes -gt 0) {
    Write-Host ''
    Write-Host '接下来会弹出一次「用户账户控制(UAC)」，用于注册断线自动重连的计划任务。' -ForegroundColor Cyan
    Write-Host '不想授权可以直接点“否”，脚本会自动改用后台守护方式，功能一样。'
    $bootArgs = ''
    if ($bootScript -and $bootConfig) {
        $bootArgs = ' -BootScriptPath "{0}" -BootConfigPath "{1}" -BootIntervalMinutes {2}' -f $bootScript, $bootConfig, $IntervalMinutes
    }
    if ($targetVbs) {
        $psArgs = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ScriptPath "{1}" -LauncherPath "{2}" -WatcherMode -IntervalMinutes {3}{4}' -f $helper, $targetScript, $targetVbs, $IntervalMinutes, $bootArgs
    } else {
        $psArgs = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ScriptPath "{1}" -WatcherMode -IntervalMinutes {2}{3}' -f $helper, $targetScript, $IntervalMinutes, $bootArgs
    }
    try {
        $proc = Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -PassThru -ArgumentList $psArgs
        $taskOk = ($proc.ExitCode -eq 0)
    } catch {
        $taskOk = $false
        Write-Host '（未获得管理员授权）' -ForegroundColor Yellow
    }
}

if ($taskOk) {
    Write-Host "计划任务已注册：开机登录 15 秒后自动认证，并每 $IntervalMinutes 分钟检查一次，断线自动重连。" -ForegroundColor Green
} else {
    if ($targetVbs) {
        $watchArgs = '//B //Nologo "{0}" -Watch -WatchIntervalMinutes {1} -TimeoutMinutes 2' -f $targetVbs, $IntervalMinutes
        New-Shortcut -Path $startupLnk -Target 'wscript.exe' -Arguments $watchArgs -WorkDir $installDir -Icon 'shell32.dll,17' -Description '校园网自动登录（守护模式·无窗口）'
    } else {
        $watchArgs = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Watch -WatchIntervalMinutes {1} -TimeoutMinutes 2' -f $targetScript, $IntervalMinutes
        New-Shortcut -Path $startupLnk -Target 'powershell.exe' -Arguments $watchArgs -WorkDir $installDir -Icon 'shell32.dll,17' -Description '校园网自动登录（守护模式）'
    }
    Write-Host ''
    Write-Host "已改用守护模式：登录后后台常驻，每 $IntervalMinutes 分钟检查一次，断线自动重连。" -ForegroundColor Green
}

# ---------- 桌面快捷方式：手动重连 ----------
$desktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) '连接校园网.lnk'
# -Interactive：认证成功 3 秒后自动关窗；失败则停住显示原因，按任意键关闭
New-Shortcut -Path $desktopLnk -Target 'powershell.exe' `
    -Arguments ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Force -Interactive' -f $targetScript) `
    -WorkDir $installDir -Icon 'shell32.dll,17' -Description '重新认证校园网（成功后自动关窗）'

Write-Host ''
Write-Host '安装完成。' -ForegroundColor Cyan
Write-Host "日志文件：$(Join-Path $installDir 'log.txt')"
Write-Host '密码输错/换密码：重新运行 install.cmd 即可（账号会自动沿用）'
Write-Host '卸载：双击 uninstall.cmd'
Write-Host ''
if ($credOk -eq $false) { exit 2 }
exit 0
