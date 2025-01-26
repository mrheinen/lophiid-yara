rule PUA_LNX_Agent_Earnfm {
    meta:
        author = "Niels Heinen <niels.heinen<at>gmail.com>"
        date = "2025-01-25"
        description = "Finds an Earnfm agent which creates network tunnels"

    strings:
      $token = "EARNFM_TOKEN"
      $d1 = "Dart_CreateIsolateGroupFromKernel"
      $d2 = "Dart_LoadELF_Memory"
      $s1 = "package:earnfm/models/request.dart"
      $s2 = "package:earnfm/models/response.dart"
      $s3 = "file:///app/example/earnfm_example.dart"
      $s4 = "Connecting to the earnfm network2"
      $s5 = "Connected to the earnfm network. You are currently earning"
      $s6 = "package:earnfm/src/socket_service.dart"
      $s7 = "package:earnfm/models/status.dart"
      $s8 = "CONNECT_FAILED, err:"

    condition:
      uint16(0) == 0x457f and filesize > 5MB and filesize < 10MB and $token and all of ($d*) and 6 of ($s*)
}
