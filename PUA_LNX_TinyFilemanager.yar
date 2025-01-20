rule PUA_LNX_TinyFilemanager {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds TinyFilemanager instances"
        reference = "https://tinyfilemanager.github.io/"

    strings:
        $php_open = "<?php"
        $sa = "define('APP_TITLE', 'Tiny File Manager');"
        $sb = "Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html"
        $sc = "<a href=\"https://tinyfilemanager.github.io/\""
        $sd = "header('X-XSS-Protection:0');"

    condition:
       $php_open at 0 and filesize > 200KB and filesize < 300KB and all of ($s*)
}
