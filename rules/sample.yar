// ITShield sample YARA rules - educational.
// These rules are intentionally simple and meant for development/testing
// only. A real deployment would consume curated rule packs (e.g. from
// YARA's signature exchange or vendor feeds).

rule ITShield_EICAR_Test_String
{
    meta:
        description = "Detects the canonical EICAR test string in any file"
        author      = "ITShield"
        severity    = "low"
        date        = "2026-11-17"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule ITShell_Suspicious_Shebang_Python
{
    meta:
        description = "Python script with shebang - flagged as suspicious for review"
        author      = "ITShield"
        severity    = "informational"
    strings:
        $py = /#!\/usr\/bin\/(env )?python[0-9]?/ nocase
    condition:
        $py
}

rule ITShield_Suspicious_Powershell_Invoke
{
    meta:
        description = "PowerShell Invoke-Expression pattern (common in obfuscated scripts)"
        author      = "ITShield"
        severity    = "medium"
    strings:
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "IEX(" nocase
        $iex3 = "&(" nocase
    condition:
        any of ($iex*)
}
