<#
    一键修复“浏览器打不开网页（代理服务器可能有问题 / ERR_PROXY_CONNECTION_FAILED）”

    适用症状：
      · 浏览器所有网站都打不开，提示“代理服务器可能有问题”
      · 但微信、QQ 等其他软件上网正常
      · 通常是 Clash / Clash Verge 等代理工具退出时没关掉“系统代理”，
        留下 127.0.0.1:7897 这类已经没人监听的代理地址

    做法：通过微软官方 API（InternetSetOption / INTERNET_OPTION_PER_CONNECTION_OPTION）
          把“局域网连接”设成『直连』，并清掉注册表里的代理残留。

    用法：双击 fix-proxy.cmd，或在 PowerShell 里运行：
         powershell -ExecutionPolicy Bypass -File Fix-Proxy.ps1

    退出码：0 = 已修复；1 = 失败
#>

[CmdletBinding()]
param([switch]$Quiet)

$ErrorActionPreference = 'Stop'

function Say($m, $c) { if (-not $Quiet) { Write-Host -ForegroundColor $c $m } }

Say '' 'White'
Say '=== 网络代理一键修复 ===' 'Cyan'

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class CnProxyFix {
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
    [DllImport("wininet.dll", SetLastError = true)]
    public static extern bool InternetQueryOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, ref int lpdwBufferLength);
}
'@

# ---------- 1) 看看修复前是什么状态 ----------
function Get-ProxyState {
    $buf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8192)
    try {
        $len = 8192
        if ([CnProxyFix]::InternetQueryOption([IntPtr]::Zero, 38, $buf, [ref]$len)) {
            $t = [System.Runtime.InteropServices.Marshal]::ReadInt32($buf, 0)
            $pp = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($buf, 8)
            $srv = ''
            if ($pp -ne [IntPtr]::Zero) { $srv = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($pp) }
            return [pscustomobject]@{ Mode = $t; Server = $srv }
        }
    } finally { [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buf) }
    return [pscustomobject]@{ Mode = -1; Server = '' }
}

$before = Get-ProxyState
$modeName = switch ($before.Mode) { 0 { '跟随配置' } 1 { '直连' } 3 { '使用代理' } default { "未知($($before.Mode))" } }
Say ("修复前：{0}   代理地址：{1}" -f $modeName, $(if ($before.Server) { $before.Server } else { '(无)' })) 'White'

# ---------- 2) 通过官方 API 设为直连 ----------
$optBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(48)
$listBuf = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(32)
$empty = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi('')
try {
    for ($i = 0; $i -lt 48; $i++) { [System.Runtime.InteropServices.Marshal]::WriteByte($optBuf, $i, 0) }
    [System.Runtime.InteropServices.Marshal]::WriteInt32($optBuf, 0, 1)    # INTERNET_PER_CONN_FLAGS
    [System.Runtime.InteropServices.Marshal]::WriteInt32($optBuf, 8, 1)    # PROXY_TYPE_DIRECT
    [System.Runtime.InteropServices.Marshal]::WriteInt32($optBuf, 16, 2)   # INTERNET_PER_CONN_PROXY_SERVER
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($optBuf, 24, $empty)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($optBuf, 32, 3)   # INTERNET_PER_CONN_PROXY_BYPASS
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($optBuf, 40, $empty)

    [System.Runtime.InteropServices.Marshal]::WriteInt32($listBuf, 0, 32)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($listBuf, 8, [IntPtr]::Zero)  # NULL = 默认局域网连接
    [System.Runtime.InteropServices.Marshal]::WriteInt32($listBuf, 16, 3)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($listBuf, 20, 0)
    [System.Runtime.InteropServices.Marshal]::WriteIntPtr($listBuf, 24, $optBuf)

    $ok = [CnProxyFix]::InternetSetOption([IntPtr]::Zero, 75, $listBuf, 32)
    if (-not $ok) { throw "InternetSetOption 失败（Win32Error=$([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())）" }
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($listBuf)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($optBuf)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($empty)
}

# ---------- 3) 顺手清掉注册表里的残留 ----------
try {
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty -Path $k -Name 'ProxyEnable' -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $k -Name 'AutoDetect'   -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $k -Name 'ProxyServer'  -Value '' -Type String -ErrorAction SilentlyContinue
    $ac = (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue).AutoConfigURL
    if ($ac) { Set-ItemProperty -Path $k -Name 'AutoConfigURL' -Value '' -Type String -ErrorAction SilentlyContinue }
    Say '已清理注册表代理残留（ProxyEnable / AutoDetect / ProxyServer）' 'White'
} catch { Say "清理注册表时出错（可忽略）：$($_.Exception.Message)" 'Yellow' }

# ---------- 4) 通知系统立即生效 ----------
[void][CnProxyFix]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)   # SETTINGS_CHANGED
[void][CnProxyFix]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)   # REFRESH
Start-Sleep -Seconds 1

# ---------- 5) 复查 ----------
$after = Get-ProxyState
$modeName2 = switch ($after.Mode) { 0 { '跟随配置' } 1 { '直连' } 3 { '使用代理' } default { "未知($($after.Mode))" } }
Say '' 'White'
Say ("修复后：{0}   代理地址：{1}" -f $modeName2, $(if ($after.Server) { $after.Server } else { '(无)' })) 'White'

if ($after.Mode -eq 1 -or ($after.Mode -eq 0 -and -not $after.Server)) {
    Say '✅ 代理已恢复正常（直连）。现在请完全关闭浏览器再重新打开。' 'Green'
    Say '   （浏览器要重启才会重新读取代理设置）' 'DarkGray'
    exit 0
}
Say '❌ 仍未恢复。可能有安全软件在强制代理设置，请把这条信息发给协助你的人。' 'Red'
exit 1
