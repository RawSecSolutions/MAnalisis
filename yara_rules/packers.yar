/*
packers.yar
===========
Reglas YARA para detección de empaquetadores (packers) en binarios PE.

Uso con Python:
    import yara
    rules = yara.compile(filepath="yara_rules/packers.yar")
    matches = rules.match("sample.exe")
    for m in matches:
        print(m.rule, m.tags)

Uso con CLI:
    yara yara_rules/packers.yar sample.exe

Referencias:
    - https://github.com/Yara-Rules/rules/tree/master/packers
    - https://yara.readthedocs.io/
*/

// ============================================================
// UPX - El packer de código abierto más común en malware básico
// ============================================================
rule UPX_Packer {
    meta:
        description = "Detecta ejecutables empaquetados con UPX"
        author      = "MalwareLab"
        version     = "1.0"
        severity    = "medium"
        reference   = "https://upx.github.io/"
    strings:
        $upx0       = "UPX0"         ascii fullword
        $upx1       = "UPX1"         ascii fullword
        $upx2       = "UPX2"         ascii fullword
        $upx_magic  = { 55 50 58 21 }               // "UPX!"
        $upx_ver    = /UPX \d+\.\d+/  ascii
    condition:
        2 of them
}

// ============================================================
// ASPack - Packer comercial frecuente en malware
// ============================================================
rule ASPack {
    meta:
        description = "Detecta ejecutables empaquetados con ASPack"
        author      = "MalwareLab"
        severity    = "medium"
    strings:
        $s1 = ".aspack"  ascii nocase
        $s2 = ".adata"   ascii nocase
        $ep = { 60 E8 ?? ?? ?? ?? }  // PUSHAD + CALL (entry point típico)
    condition:
        any of ($s*) or $ep
}

// ============================================================
// Themida / WinLicense - Protección avanzada, frecuente en malware premium
// ============================================================
rule Themida_WinLicense {
    meta:
        description = "Detecta protección Themida o WinLicense"
        author      = "MalwareLab"
        severity    = "high"
        note        = "Themida se usa en software legítimo también, verificar contexto"
    strings:
        $s1 = ".themida"    ascii nocase
        $s2 = "WinLicense"  ascii
        $s3 = "Themida"     ascii
        $s4 = { 8B 85 ?? ?? FF FF 03 85 ?? ?? FF FF }  // patrón interno
    condition:
        any of them
}

// ============================================================
// VMProtect - Protección con virtualización de código
// ============================================================
rule VMProtect {
    meta:
        description = "Detecta protección VMProtect"
        author      = "MalwareLab"
        severity    = "high"
    strings:
        $s1 = ".vmp0"       ascii nocase
        $s2 = ".vmp1"       ascii nocase
        $s3 = ".vmp2"       ascii nocase
        $s4 = "VMProtect"   ascii
        $s5 = "vmp_begin"   ascii
        $s6 = "vmp_end"     ascii
    condition:
        any of them
}

// ============================================================
// MPRESS - Packer gratuito, encontrado en malware
// ============================================================
rule MPRESS {
    meta:
        description = "Detecta MPRESS packer"
        author      = "MalwareLab"
        severity    = "medium"
    strings:
        $s1 = ".MPRESS1" ascii
        $s2 = ".MPRESS2" ascii
        $b1 = { 60 68 ?? ?? ?? ?? E8 }  // PUSHAD PUSH <addr> CALL
    condition:
        any of them
}

// ============================================================
// Petite - Packer shareware
// ============================================================
rule Petite {
    meta:
        description = "Detecta Petite packer"
        author      = "MalwareLab"
        severity    = "medium"
    strings:
        $s1 = ".petite" ascii nocase
        $b1 = { B8 ?? ?? ?? ?? 68 }  // MOV EAX, <addr>; PUSH
    condition:
        $s1 or $b1
}

// ============================================================
// NsPack / NsPacK - Packer chino muy usado en malware asiático
// ============================================================
rule NsPack {
    meta:
        description = "Detecta NsPack packer"
        author      = "MalwareLab"
        severity    = "medium"
    strings:
        $s1 = "NsPack"  ascii
        $s2 = ".nsp0"   ascii nocase
        $s3 = ".nsp1"   ascii nocase
        $s4 = ".nsp2"   ascii nocase
    condition:
        any of them
}

// ============================================================
// PEBundle - Packer para combinar múltiples recursos
// ============================================================
rule PEBundle {
    meta:
        description = "Detecta PEBundle packer"
        severity    = "medium"
    strings:
        $s1 = "PEBundle"  ascii
        $s2 = "pebundle"  ascii nocase
        $s3 = "PEBundl"   ascii
    condition:
        any of them
}

// ============================================================
// HEURÍSTICA: Pocas imports + entry point en sección extraña
// (indicador general de packing cuando no se detecta el packer específico)
// ============================================================
rule Generic_Packer_Heuristic {
    meta:
        description = "Heurística: probable packing (pocas imports + API de carga)"
        author      = "MalwareLab"
        severity    = "medium"
        note        = "Verificar manualmente, puede tener falsos positivos"
    strings:
        $getprocaddr = "GetProcAddress"   ascii
        $loadlib_a   = "LoadLibraryA"     ascii
        $loadlib_w   = "LoadLibraryW"     ascii
        $virtualalloc = "VirtualAlloc"    ascii
    condition:
        $getprocaddr and (1 of ($loadlib*)) and $virtualalloc
}
