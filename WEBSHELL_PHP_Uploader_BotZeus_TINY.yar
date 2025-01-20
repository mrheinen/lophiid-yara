rule WEBSHELL_PHP_Uploader_BotZeus_TINY {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds PHP file uploader by BotZeus"
        reference = "https://github.com/ZeusFtrOfc/BotZeus/blob/main/axvuploader.php"

    strings:
        $php = "<?php"
        $sa = "echo 'AXVTECH<br/>"
        $sb = "if(@copy($_FILES['file']['tmp_name']"
        $sc = "echo '# Success Upload';"

    condition:
       $php at 0 and filesize < 1KB and all of ($s*)
}
