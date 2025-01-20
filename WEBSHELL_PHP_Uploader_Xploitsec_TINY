rule WEBSHELL_PHP_Uploader_Xploitsec_TINY {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds PHP file uploader by XploitSecurity"

    strings:
        $php = "<?php"
        $sa = "<h3>XploitSecurity</h3>"
        $sb = "echo\"<b>BERHASIL NGNTD:V</b>"

    condition:
       $php in (0..60) and filesize < 1KB and all of ($s*)
}
