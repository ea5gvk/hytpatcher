# hytpatcher
tool for fixing some issues with gw_hytera_mmdvm and a Hytera Repeater RD985 with Firmware >= 9.xx

This tool is AS IS - but it's not ready yet.
NO SUPPORT at this time !
It was made for using and working, not for the best software design :)

Issues will be fixed with this tool:
1. If the DMRGateway sends the last packet for call termination (VOICE_TERMINATOR_WITH_LC) then the gw_hytera_mmdvm don't fill the packet send to repeater with the correct payload (fill all with 00 instead of payload with VOICE_TERMINATOR_WITH_LC). So we save the payload from the mmdvm-packet and insert this to the hytera-ipsc-packet at the right place.

73 Heiko/DL1BZ
