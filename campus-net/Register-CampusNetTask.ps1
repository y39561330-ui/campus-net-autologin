<#
    注册 / 注销 计划任务（需要管理员权限）。
    安装脚本会自动以管理员身份调用它；也可以在管理员 PowerShell 里手动运行。

    说明：默认通过 RunHidden.vbs + wscript.exe 启动，这样**完全不会闪出控制台窗口**。
          如果找不到 RunHidden.vbs，则退回直接调用 powershell.exe（会闪现一下）。

    退出码：0 = 成功；1 = 失败
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [string]$LauncherPath,
    [string]$BootScriptPath,          # 给 SYSTEM 开机任务用的脚本副本（ProgramData）
    [string]$BootConfigPath,          # 机器级加密的配置
    [int]$BootIntervalMinutes = 10,
    [string]$BootTaskName = 'CampusNetAutoLoginBoot',
    [string]$ExtraArguments = '',
    [int]$IntervalMinutes = 10,
    [string]$TaskName = 'CampusNetAutoLogin',
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

$elevated = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $elevated) {
    Write-Host '需要管理员权限才能注册计划任务。' -ForegroundColor Red
    exit 1
}

try {
    if ($Remove) {
        if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        Write-Host "已删除计划任务 $TaskName"
        exit 0
    }

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        Write-Host "找不到脚本：$ScriptPath" -ForegroundColor Red
        exit 1
    }

    # 优先用 wscript + RunHidden.vbs（无窗口）
    $useLauncher = ($LauncherPath -and (Test-Path -LiteralPath $LauncherPath))
    if ($useLauncher) {
        $action = New-ScheduledTaskAction -Execute 'wscript.exe' `
                    -Argument ('//B //Nologo "{0}" {1}' -f $LauncherPath, $ExtraArguments).Trim()
    } else {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
                    -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" {1}' -f $ScriptPath, $ExtraArguments).Trim()
    }

    $tLogon = New-ScheduledTaskTrigger -AtLogOn
    $tLogon.Delay = 'PT5S'   # 登录后 5 秒就开始，脚本自己会重试到网络就绪

    $triggers = @($tLogon)
    if ($IntervalMinutes -gt 0) {
        $tRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
                    -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes) `
                    -RepetitionDuration (New-TimeSpan -Days 3650)
        $triggers += $tRepeat
    }

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

    # 必须以“当前登录用户”的身份运行（密码是用该用户的 DPAPI 加密的，SYSTEM 解不开）
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Settings $settings -Principal $principal -Force -ErrorAction Stop | Out-Null

    $t = Get-ScheduledTask -TaskName $TaskName
    if ($useLauncher) {
        Write-Host "计划任务 $TaskName 注册成功（无窗口启动，触发器 $($t.Triggers.Count) 个）。" -ForegroundColor Green
    } else {
        Write-Host "计划任务 $TaskName 注册成功（直接调用 powershell，可能会闪现窗口）。" -ForegroundColor Yellow
    }

    # ---------- 额外：开机（未登录时）也能联网 —— 以 SYSTEM 身份跑的启动任务 ----------
    if ($BootScriptPath -and (Test-Path -LiteralPath $BootScriptPath)) {
        $bootArg = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}"' -f $BootScriptPath
        if ($BootConfigPath) { $bootArg += (' -ConfigPath "{0}"' -f $BootConfigPath) }
        $bootArg += ' -MachineScope'
        $bootAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $bootArg

        $bootStart = New-ScheduledTaskTrigger -AtStartup
        try { $bootStart.Delay = 'PT10S' } catch { }
        $bootTriggers = @($bootStart)
        if ($BootIntervalMinutes -gt 0) {
            $bootRepeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(4) `
                            -RepetitionInterval (New-TimeSpan -Minutes $BootIntervalMinutes) `
                            -RepetitionDuration (New-TimeSpan -Days 3650)
            $bootTriggers += $bootRepeat
        }

        $bootSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)
        $bootPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $BootTaskName -Action $bootAction -Trigger $bootTriggers `
            -Settings $bootSettings -Principal $bootPrincipal -Force -ErrorAction Stop | Out-Null
        Write-Host "开机任务 $BootTaskName 注册成功（SYSTEM 身份，未登录也会联网）。" -ForegroundColor Green

        # 收紧权限：SYSTEM / 管理员完全控制，普通用户只读
        # （否则普通账户能改掉 SYSTEM 要执行的脚本，等于提权漏洞）
        try {
            $bootDir = Split-Path -Parent $BootScriptPath
            & icacls.exe $bootDir /inheritance:r `
                /grant '*S-1-5-18:(OI)(CI)F' `
                /grant '*S-1-5-32-544:(OI)(CI)F' `
                /grant '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
        } catch { }
    }
    exit 0
}
catch {
    Write-Host "注册计划任务失败：$($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
