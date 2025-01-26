rule LOADER_LNX_SH_Generic_MultiArch {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-26"
        description = "Find generic multi architecture botnet loader (shell script)"

    strings:
        // Match on curl or wget commands with or without any flags.
        $s1 = /(curl|wget)\s+(-[a-zA-Z]\s+)*https?:/
        // Typically these scripts try to download malware of various
        // architectures and try to execute them.
        $s2 = /chmod\s+((\+x)|([0-7]{3}))/
        $a1 = "x86"
        $a2 = "mips"
        $a3 = "mips64"
        $a4 = "arm4"
        $a5 = "arm5"
        $a6 = "arm6"
        $a7 = "arm7"
        $a8 = "ppc"
        $a9 = "m68k"
        $a10 = "sh4"
        $a11 = "686"
        $a12 = "386"
        $a13 = "amd64"
        $a14 = "aarch64"
        $a15 = "mpsl"

    condition:
       filesize < 10KB and all of ($s*) and 4 of ($a*)
}
