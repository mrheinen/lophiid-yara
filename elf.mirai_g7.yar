rule elf_mirai {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-17"
        description = "Matching unpacked trojan.mirai/gafgyt"

    strings:
        $sa = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS"
        $sb = "USER-AGENT: Google Chrome/60.0.3112.90 Windows"
        $sc = "Windows XP"
        $sd = "HOST: 255.255.255.255:1900"
        $se = "SNQUERY: 127.0.0.1:AAAAAA:xsvr"

    condition:
       uint16(0) == 0x457f and filesize < 120KB and all of ($s*)
}
