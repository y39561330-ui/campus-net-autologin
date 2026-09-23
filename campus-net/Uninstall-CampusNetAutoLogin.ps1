<#
    卸载校园网自动登录：删除启动项、计划任务、桌面快捷方式和已保存的账号密码。

    用法：双击 uninstall.cmd，或
         powershell -ExecutionPolicy Bypass -File Uninstall-CampusNetAutoLogin.ps1
#>

[CmdletBinding()]
param(
    [switch]$KeepConfig,
    [switch]$Elevated   # 内部用：已提权后的第二次调用
)

$ErrorActionPreference = 'Continue'
$installDir = Join-Path $env:LOCALAPPDATA 'CampusNetAutoLogin'
$taskName = 'CampusNetAutoLogin'

# 0) 开机任务（SYSTEM 身份）与 ProgramData 目录：需要管理员
$bootTaskName = 'CampusNetAutoLoginBoot'
$progDir = Join-Path $env:ProgramData 'CampusNetAutoLogin'
$needElevation = $false

if (Get-ScheduledTask -TaskName $bootTaskName -ErrorAction SilentlyContinue) {
    try {
        Unregister-ScheduledTask -TaskName $bootTaskName -Confirm:$false -ErrorAction Stop
        Write-Host "已删除开机任务：$bootTaskName" -ForegroundColor Green
    } catch {
        $needElevation = $true
    }
}

if (-not $KeepConfig -and (Test-Path -LiteralPath $progDir)) {
    try {
        Remove-Item -LiteralPath $progDir -Recurse -Force -ErrorAction Stop
        Write-Host "已删除系统目录：$progDir" -ForegroundColor Green
    } catch {
        $needElevation = $true
    }
}

if ($needElevation -and -not $Elevated) {
    Write-Host ''
    Write-Host '删除开机任务/系统目录需要管理员权限，正在请求（UAC 请点“是”）...' -ForegroundColor Yellow
    try {
        $self = $PSCommandPath
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -Wait -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Elevated' -f $self)
    } catch { Write-Host '未获得管理员授权，开机任务可能残留。' -ForegroundColor Yellow }
    exit 0
}

Write-Host ''
Write-Host '=== 卸载 校园网自动登录 ===' -ForegroundColor Cyan
Write-Host ''

# 1) 计划任务
try {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "已删除计划任务：$taskName" -ForegroundColor Green
    } else {
        Write-Host "计划任务 $taskName 不存在（可能用的是守护模式）。"
    }
} catch {
    Write-Host "删除计划任务失败（可能需要管理员权限）：$($_.Exception.Message)" -ForegroundColor Yellow
}

# 2) 启动项
$startupLnk = Join-Path ([Environment]::GetFolderPath('Startup')) '校园网自动登录.lnk'
if (Test-Path -LiteralPath $startupLnk) {
    Remove-Item -LiteralPath $startupLnk -Force
    Write-Host '已删除启动项：校园网自动登录.lnk' -ForegroundColor Green
}

# 3) 桌面快捷方式
$desktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) '连接校园网.lnk'
if (Test-Path -LiteralPath $desktopLnk) {
    Remove-Item -LiteralPath $desktopLnk -Force
    Write-Host '已删除桌面快捷方式：连接校园网.lnk' -ForegroundColor Green
}

# 4) 配置目录（含加密后的密码）
if (-not $KeepConfig) {
    if (Test-Path -LiteralPath $installDir) {
        $resolved = (Resolve-Path -LiteralPath $installDir).Path
        $expectedPrefix = [IO.Path]::GetFullPath($env:LOCALAPPDATA)
        if ($resolved.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolved -Recurse -Force
            Write-Host "已删除配置目录：$resolved" -ForegroundColor Green
        } else {
            Write-Host "路径校验未通过，未删除：$resolved" -ForegroundColor Yellow
        }
    }
}

# 5) 停掉可能还在运行的守护进程
Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -like '*Connect-CampusNet.ps1*' } |
    ForEach-Object {
        try { Stop-Process -Id $_.ProcessId -Force; Write-Host "已结束守护进程 PID $($_.ProcessId)" } catch { }
    }

Write-Host ''
Write-Host '卸载完成。' -ForegroundColor Green
