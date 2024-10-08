
rule IoC_Detection {
    meta:
        description = "Detects specific SHA-256 hash"
    strings:
        $hash1 = { e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55 }
    condition:
        $hash1
}
