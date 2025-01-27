rule ELF_Mirai_xor_horse {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-19"
        description = "Finds XOR obfuscated Mirai IOC's"

    strings:
        $sa = "pool.rentcheapcars.sbs" xor
        $sb = "iranistrash.libre" xor
        $sc = "stun.mitake.com.tw" xor
        $sd = "TxID and IP Range/ASN" xor
        $se = "to be blacklisted from this and future botnets from us." xor

    condition:
       uint16(0) == 0x457f and filesize < 120KB and all of ($s*)
}
