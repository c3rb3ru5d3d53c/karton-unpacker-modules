rule pe{
    strings:
        $mz = {4d 5a}
    condition:
        uint16(0) == 0x5a4d and
        uint32(uint32(0x3c)) == 0x00004550 and
        uint32(@mz[5]+0x3c) == 0x00004550
}