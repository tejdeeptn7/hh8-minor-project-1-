# Windows Security Audit (PowerShell)



##### ~Project Description:

The Windows Security Audit project is a PowerShell-based security assessment tool designed to analyze and report the security posture of a Windows system.

It audits critical system configurations using Windows Management Instrumentation (WMI), registry checks, and system commands to identify potential security risks.



The script automatically:



1)Verifies administrator privileges



2)Collects system and OS information



3)Checks antivirus and Windows Defender status



4)Audits firewall configuration



5)Verifies User Account Control (UAC)



6)Reviews password policy



7)Checks Remote Desktop configuration



Lists administrator accounts



Generates a structured audit report (audit\_report.txt) in a dedicated reports directory



This project simulates a real-world Windows security audit, commonly performed by system administrators and security analysts.

##### 

##### ~Tools Used:



PowerShell



Windows Management Instrumentation (WMI) using Get-WmiObject



Windows Registry



Built-in Windows utilities (net accounts)



Windows Security Services



##### ~How to Run the Project:

Prerequisites:



Windows OS



PowerShell (run as Administrator)



Steps:



Clone or download the repository.





Run the "run_audit.bat" script as Administrator:





After successful execution, the audit report will be generated at:



reports/audit_report.txt



File Name: audit_report.txt



Location: ../reports/



Content Includes:



1)OS details



2)Antivirus status



3)Windows Defender service state



4)Firewall status



5)UAC configuration



6)Password policy



7)Remote Desktop status



8)Administrator accounts



9)Audit completion status

##### 

##### ~What I Learned:



Through this project, I learned:



-How to use PowerShell for security auditing



-Practical usage of Get-WmiObject for system and security data



-Reading and validating Windows registry values



-Handling administrator privilege checks



-Understanding real-world Windows security configurations and risks



