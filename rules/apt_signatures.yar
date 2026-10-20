// APT and advanced threat YARA signatures for Specter

rule APT_Lazarus_Loader : apt lazarus {
    meta:
        description = "Lazarus Group loader characteristics"
        severity = "critical"
        mitre_technique = "T1055"
        mitre_group = "G0032"
        reference = "Lazarus Group TTPs"
    strings:
        $s1 = "WS2_32.dll" nocase
        $s2 = "InternetExplorer.Application" nocase
        $s3 = "certutil" nocase
        $hex1 = { 60 89 E5 31 D2 64 8B 52 30 }  // DKOM shellcode prologue
        $hex2 = { 55 8B EC 83 EC ?? 53 56 57 }   // common function prologue with frame setup
        $rc4_sched = { 31 C9 B1 FF 31 C0 [1-4] 88 04 0F 41 }  // RC4 KSA loop
    condition:
        2 of ($s*) and (1 of ($hex*) or $rc4_sched)
}

rule APT_Cobalt_Strike_Beacon : apt c2 cobalt_strike {
    meta:
        description = "Cobalt Strike Beacon staging and config indicators"
        severity = "critical"
        mitre_technique = "T1071.001"
        reference = "CS Malleable C2 profile patterns"
    strings:
        $cfg1 = "%s (admin)" wide
        $cfg2 = "ReflectiveLoader" nocase
        $cfg3 = "beacon.dll" nocase
        $magic1 = { FC 48 83 E4 F0 }         // CS x64 shellcode prologue
        $magic2 = { 23 78 6F 72 }             // CS XOR staging header
        $profile1 = "Content-Type: application/octet-stream" nocase
        $profile2 = "__utma" nocase           // CS jQuery profile cookie
        $profile3 = "If-None-Match:" nocase
        $watermark = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 }
    condition:
        (2 of ($cfg*)) or
        ($magic1 or $magic2) or
        (2 of ($profile*) and ($watermark or 1 of ($cfg*)))
}

rule Emotet_Loader : malware emotet loader {
    meta:
        description = "Emotet loader network and obfuscation patterns"
        severity = "critical"
        mitre_technique = "T1027"
        mitre_group = "G0049"
    strings:
        $network1 = "POST" nocase
        $network2 = "Mozilla/4.0 (compatible; MSIE 7.0;" nocase
        $obf1 = { 8B 45 FC 33 45 F8 89 45 F4 }  // XOR obfuscation loop pattern
        $persistence1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $persistence2 = "svchost.exe" nocase
        $doc1 = "WScript.Shell" nocase
        $doc2 = "Shell.Application" nocase
        $crypto1 = { 35 [4] 05 [4] 35 [4] 05 }  // Emotet string decryption
    condition:
        ($obf1 or $crypto1) and
        (($network1 and $network2) or (1 of ($persistence*)) or (1 of ($doc*)))
}

rule TrickBot_Module : malware trickbot {
    meta:
        description = "TrickBot module characteristics"
        severity = "critical"
        mitre_technique = "T1059.003"
        mitre_group = "G0102"
    strings:
        $s1 = "<moduleconfig>" nocase
        $s2 = "<maxconn>" nocase
        $s3 = "importDll" nocase
        $s4 = "StartW" nocase
        $cfg1 = "autoruns" nocase
        $cfg2 = "injectDll" nocase
        $cfg3 = "networkDll" nocase
        $cfg4 = "systeminfo" nocase
    condition:
        2 of ($s*) or 3 of ($cfg*)
}

rule Metasploit_Shellcode_x86 : shellcode metasploit {
    meta:
        description = "Metasploit x86 staged/stageless shellcode"
        severity = "critical"
        mitre_technique = "T1059"
    strings:
        $staged_bind   = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $staged_reverse = { FC E8 82 00 00 00 60 89 E5 31 C0 64 8B 50 30 }
        $egghunter = { 66 81 CA FF 0F 42 52 6A 02 58 CD 2E 3C 05 5A 74 EF }
        $shikata = { D9 74 24 F4 5F [1-10] EB ?? }  // shikata_ga_nai encoder
        $meterpreter1 = "METERPRETER_TRANSPORT_SSL" nocase
        $meterpreter2 = "metsrv.x64.dll" nocase
    condition:
        any of them
}

rule Formbook_Infostealer : malware infostealer formbook {
    meta:
        description = "FormBook infostealer process hollowing and form grabbing"
        severity = "critical"
        mitre_technique = "T1055"
    strings:
        $hollow1 = "NtUnmapViewOfSection" nocase
        $hollow2 = "ZwUnmapViewOfSection" nocase
        $inject1 = "VirtualAllocEx" nocase
        $inject2 = "WriteProcessMemory" nocase
        $inject3 = "ResumeThread" nocase
        $hook1 = "SetWindowsHookEx" nocase
        $hook2 = "GetForegroundWindow" nocase
        $browser1 = "chrome.exe" nocase
        $browser2 = "firefox.exe" nocase
        $browser3 = "iexplore.exe" nocase
    condition:
        (1 of ($hollow*) and 2 of ($inject*)) and
        (1 of ($hook*) or 1 of ($browser*))
}

rule AsyncRAT_Backdoor : backdoor rat async {
    meta:
        description = "AsyncRAT remote access trojan indicators"
        severity = "critical"
        mitre_technique = "T1071.001"
    strings:
        $s1 = "AsyncRAT" nocase
        $s2 = "Pastebin" nocase
        $s3 = "HWID" nocase
        $dotnet1 = "AsyncClient" wide
        $dotnet2 = "ClientSocket" wide
        $dotnet3 = "RecvThread" wide
        $config1 = "Ports" wide
        $config2 = "Hosts" wide
        $config3 = "Mutex" wide
        $config4 = "InstallDir" wide
        $config5 = "Certificate" wide
    condition:
        ($s1) or
        (2 of ($dotnet*) and 3 of ($config*))
}

rule Fileless_PowerShell_Execution : fileless powershell {
    meta:
        description = "Fileless PowerShell execution via encoded commands"
        severity = "high"
        mitre_technique = "T1059.001"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-e " nocase
        $bypass1 = "-ExecutionPolicy Bypass" nocase
        $bypass2 = "-ExecutionPolicy RemoteSigned" nocase
        $bypass3 = "Set-ExecutionPolicy" nocase
        $hide1 = "-WindowStyle Hidden" nocase
        $hide2 = "-w hidden" nocase
        $nop1 = "-NonInteractive" nocase
        $iex1 = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "WebClient" nocase
    condition:
        (1 of ($enc*) and 1 of ($bypass*)) or
        (1 of ($hide*) and 1 of ($iex*)) or
        (1 of ($iex*) and 1 of ($download*))
}

rule Anti_Analysis_Techniques : evasion anti_debug {
    meta:
        description = "Common anti-analysis and anti-debugging techniques"
        severity = "medium"
        mitre_technique = "T1027"
    strings:
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "NtQueryInformationProcess" nocase
        $dbg4 = "OutputDebugString" nocase
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "VBOX" nocase
        $vm4 = "Hyper-V" nocase
        $sandbox1 = "SbieDll.dll" nocase
        $sandbox2 = "api_log.dll" nocase
        $sandbox3 = "dir_watch.dll" nocase
        $timing1 = "GetTickCount" nocase
        $timing2 = "QueryPerformanceCounter" nocase
        $timing3 = "NtDelayExecution" nocase
    condition:
        2 of ($dbg*) or
        2 of ($vm*) or
        2 of ($sandbox*) or
        (1 of ($dbg*) and 1 of ($timing*))
}

rule Credential_Harvesting : credential mitre_t1003 {
    meta:
        description = "Credential harvesting and LSASS dumping indicators"
        severity = "critical"
        mitre_technique = "T1003"
    strings:
        $lsass1 = "lsass.exe" nocase
        $lsass2 = "lsass" nocase
        $sam1 = "\\SAM" nocase
        $sam2 = "\\SECURITY" nocase
        $sam3 = "\\SYSTEM" nocase
        $sekurlsa = "sekurlsa" nocase
        $mimikatz1 = "mimikatz" nocase
        $mimikatz2 = "WCE" nocase
        $dmp1 = "MiniDumpWriteDump" nocase
        $dmp2 = "NtReadVirtualMemory" nocase
        $dmp3 = "procdump" nocase
    condition:
        ($mimikatz1 or $mimikatz2 or $sekurlsa) or
        (($lsass1 or $lsass2) and ($dmp1 or $dmp2)) or
        (3 of ($sam*) and 1 of ($dmp*))
}
