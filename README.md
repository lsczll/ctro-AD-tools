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
