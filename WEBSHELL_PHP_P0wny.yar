rule WEBSHELL_PHP_P0wny {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds PHP P0wny web shell UI element"

    strings:
        $html_tag = "<!DOCTYPE html>"
        $sa = "| '_ \\| | | \\ \\ /\\ / / '_ \\| | | |/ / _` / __| '_ \\ / _ \\ | (_)"
        $sb = "<title>p0wny@shell:~#</title>"
        $sc = "<label for=\"shell-cmd\" id=\"shell-prompt\" class=\"shell-prompt\">"

    condition:
       $html_tag at 0 and filesize < 20KB and all of ($s*)
}
