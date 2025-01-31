rule PUA_LNX_Xmrig_Miner_config {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-31"
        description = "Finds Monero XMRig configs"

    strings:
      $s1 = /"user": "[A-Za-z0-9]{95}"/ // Match on a Monero wallet address.
      $s2 = "\"nicehash\": "
      $s3 = "\"donate-level\":"
      $s4 = "\"tls-fingerprint\""

    condition:
      all of ($s*)
}
