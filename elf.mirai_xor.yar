rule elf_mirai_xor_ioc {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-19"
        description = "Finds XOR obfuscated Mirai IOC's"

    strings:
        $sa = "pool.rentcheapcars.sbs" xor(0x31-0x4f)
        $sb = "iranistrash.libre" xor(0x01-0x1a)
        $sc = "api.opennic.org" xor(0x31-0x4f)
        $sd = "stun.mitake.com.tw" xor(0x01-0x0a)

    condition:
       uint16(0) == 0x457f and filesize < 120KB and all of ($s*)
}
