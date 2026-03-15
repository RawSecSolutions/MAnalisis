/*
suspicious_strings.yar
=======================
Reglas YARA para detección de strings y patrones asociados a familias
de malware comunes: RATs, ransomware, stealers, backdoors.

Estas reglas complementan el motor Aho-Corasick con detecciones
basadas en combinaciones de strings y estructuras de bytes.
*/

// ============================================================
// ACCESO A CREDENCIALES / LSASS DUMP
// ============================================================
rule CredentialTheft {
    meta:
        description = "Posible robo de credenciales (LSASS dump, mimikatz patterns)"
        severity    = "critical"
    strings:
        $m1 = "lsass"           ascii nocase
        $m2 = "sekurlsa"        ascii nocase
        $m3 = "logonpasswords"  ascii nocase
        $m4 = "mimikatz"        ascii nocase
        $m5 = "wce"             ascii fullword
        $m6 = "cachedump"       ascii nocase
        $m7 = "hashdump"        ascii nocase
        $m8 = "NtlmHash"        ascii
        $m9 = "LmHash"          ascii
    condition:
        2 of them
}

// ============================================================
// CONEXIÓN REVERSA / C2
// ============================================================
rule ReverseShell {
    meta:
        description = "Indicadores de reverse shell o C2"
        severity    = "high"
    strings:
        $r1 = "cmd.exe"             ascii nocase
        $r2 = "/bin/sh"             ascii
        $r3 = "/bin/bash"           ascii
        $r4 = "socket"              ascii
        $r5 = "connect"             ascii
        $r6 = "WSAStartup"          ascii
        $r7 = "reverse_shell"       ascii nocase
        $r8 = "meterpreter"         ascii nocase
        $r9 = "PAYLOAD"             ascii
    condition:
        3 of them
}

// ============================================================
// RANSOMWARE
// ============================================================
rule Ransomware_Indicators {
    meta:
        description = "Indicadores de comportamiento de ransomware"
        severity    = "critical"
    strings:
        $e1 = "CryptEncrypt"        ascii
        $e2 = "BCryptEncrypt"       ascii
        $e3 = "AES_set_encrypt_key" ascii
        $n1 = "Your files"          ascii nocase
        $n2 = "encrypted"           ascii nocase
        $n3 = "decrypt"             ascii nocase
        $n4 = "ransom"              ascii nocase
        $n5 = "bitcoin"             ascii nocase
        $n6 = ".locked"             ascii
        $n7 = "READ_ME"             ascii nocase
        $n8 = "HOW_TO_RECOVER"      ascii nocase
    condition:
        1 of ($e*) and 2 of ($n*)
}

// ============================================================
// INYECCIÓN EN PROCESO
// ============================================================
rule ProcessInjection {
    meta:
        description = "Técnicas de inyección en proceso"
        severity    = "high"
    strings:
        $i1 = "VirtualAllocEx"          ascii
        $i2 = "WriteProcessMemory"      ascii
        $i3 = "CreateRemoteThread"      ascii
        $i4 = "NtUnmapViewOfSection"    ascii
        $i5 = "ZwUnmapViewOfSection"    ascii
        $i6 = "NtCreateThreadEx"        ascii
        $i7 = "RtlCreateUserThread"     ascii
        $i8 = "SetWindowsHookEx"        ascii
        $i9 = "QueueUserAPC"            ascii
    condition:
        2 of them
}

// ============================================================
// PERSISTENCIA EN REGISTRO
// ============================================================
rule RegistryPersistence {
    meta:
        description = "Escritura en claves de registro para persistencia"
        severity    = "high"
    strings:
        $k1 = "CurrentVersion\\Run"             ascii nocase wide
        $k2 = "CurrentVersion\\RunOnce"         ascii nocase wide
        $k3 = "Winlogon"                        ascii nocase
        $k4 = "Image File Execution Options"    ascii nocase wide
        $k5 = "AppCertDlls"                     ascii nocase wide
        $k6 = "AppInit_DLLs"                    ascii nocase wide
        $f1 = "RegSetValueEx"                   ascii
        $f2 = "RegCreateKey"                    ascii
    condition:
        1 of ($f*) and 1 of ($k*)
}

// ============================================================
// KEYLOGGER
// ============================================================
rule Keylogger {
    meta:
        description = "Posibles indicadores de keylogger"
        severity    = "high"
    strings:
        $k1 = "GetAsyncKeyState"    ascii
        $k2 = "GetKeyState"         ascii
        $k3 = "SetWindowsHookEx"    ascii
        $k4 = "WH_KEYBOARD"         ascii
        $k5 = "WH_KEYBOARD_LL"      ascii
        $k6 = "keylog"              ascii nocase
    condition:
        2 of them
}

// ============================================================
// EVASIÓN DE ANÁLISIS / ANTI-DEBUG
// ============================================================
rule AntiAnalysis {
    meta:
        description = "Técnicas de evasión de análisis / anti-debug"
        severity    = "medium"
    strings:
        $d1 = "IsDebuggerPresent"               ascii
        $d2 = "CheckRemoteDebuggerPresent"      ascii
        $d3 = "NtQueryInformationProcess"       ascii
        $d4 = "OutputDebugString"               ascii
        $v1 = "vmware"                          ascii nocase
        $v2 = "VirtualBox"                      ascii nocase
        $v3 = "vboxguest"                       ascii nocase
        $v4 = "VBOX"                            ascii nocase
        $s1 = "SbieDll"                         ascii  // Sandboxie
        $s2 = "cuckoomon"                       ascii  // Cuckoo sandbox
    condition:
        2 of them
}

// ============================================================
// DESCARGA Y EJECUCIÓN
// ============================================================
rule DownloadAndExecute {
    meta:
        description = "Descarga y ejecución de payload adicional"
        severity    = "high"
    strings:
        $d1 = "URLDownloadToFile"   ascii
        $d2 = "WinHttpOpen"         ascii
        $d3 = "InternetOpenUrl"     ascii
        $d4 = "HttpSendRequest"     ascii
        $e1 = "ShellExecute"        ascii
        $e2 = "WinExec"             ascii
        $e3 = "CreateProcess"       ascii
        $e4 = "LoadLibrary"         ascii
    condition:
        1 of ($d*) and 1 of ($e*)
}

// ============================================================
// POWERSHELL MALICIOSO
// ============================================================
rule MaliciousPowerShell {
    meta:
        description = "Uso sospechoso de PowerShell (evasión, descarga)"
        severity    = "high"
    strings:
        $p1 = "-EncodedCommand"         ascii nocase wide
        $p2 = "-enc "                   ascii nocase wide
        $p3 = "Invoke-Expression"       ascii nocase wide
        $p4 = "IEX("                    ascii nocase
        $p5 = "DownloadString"          ascii nocase
        $p6 = "DownloadFile"            ascii nocase
        $p7 = "bypass"                  ascii nocase wide
        $p8 = "-NoProfile"              ascii nocase wide
        $p9 = "FromBase64String"        ascii nocase wide
    condition:
        3 of them
}
