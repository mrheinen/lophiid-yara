rule WEBSHELL_LNX_PHP_Shin {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds PHP Shin web shell"

    strings:
        $php_open = "<?php" ascii
        $sa = "function executeCommand($command)"
        $sb = "$shellOutput = @shell_exec($command);"
        $sc = "..:: Shin Shell- Coded By Shin Code ::.."
        $sd = "/etc/passwd"
        $se = ".htaccess"
        $sf = "curl --version"

    condition:
       $php_open at 0 and filesize < 60KB and all of ($s*)
}
