rule WannaCry_Generic {
    meta:
        description = "Detects generic WannaCry ransomware signatures"
        author = "Titanium Guard Research"
        date = "2026-02-06"
    
    strings:
        $s1 = "wanacry" nocase
        $s2 = "CryptEncrypt"
        $s3 = "CryptGenKey"
        $s4 = "WanaCrypt0r"
        
    condition:
        any of them
}
