rule PUA_LNX_Earnfm_token {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-20"
        description = "Finds scripts that start earnfm binaries"

    strings:
        $token =
        /EARNFM_TOKEN\s*=\s*["']?[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}["']?/

    condition:
      $token
}
