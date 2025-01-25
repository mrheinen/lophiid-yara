rule PUA_LNX_Agent_Packetsdk {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-25"
        description = "Finds a Packetsdk agent which creates network tunnels"

    strings:
      $d1 = "packetsdk.net"
      $d2 = "packetsdk.xyz"
      $d3 = "packetsdk.io"
      $d4 = "104.21.17.114"
      $d5 = "172.67.175.198"
      $d6 = "104.21.86.62"
      $d7 = "172.67.216.85"
      $d8 = "104.21.95.121"
      $d9 = "172.67.144.193"
      $s1 = "Packet SDK"
      $s2 = "creating tcp tunnel"
      $s3 = "St10money_base"

    condition:
      uint16(0) == 0x457f and filesize > 1MB and filesize < 5MB and 1 of ($d*) and all of ($s*)
}
