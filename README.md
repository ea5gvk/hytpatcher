# hytpatcher
A tool for fixing some network protocol (ipsc) issues between gw_hytera_mmdvm and a Hytera Repeater RD985 with Firmware >= 9.xx
We correct some of the UDP packets after sent from gw_hytera_mmdvm with the help of netqueue and scapy for modification and packet processing. No modification of gw_hytera_mmdvm is required (because it's unfortunately closed source).

This tool is AS IS - but it's not ready yet.
NO SUPPORT at this time !
It was made for using and working, not for the best software design :)
This tool was made for running on a Raspberry Pi with debian buster.

Issues after investigation will be fixed with this tool:
1. If the DMRGateway sends the last packet for call termination (VOICE_TERMINATOR_WITH_LC) then the gw_hytera_mmdvm don't fill the IPSC-packet (send to repeater) with the payload (fill all with 00 instead of payload with VOICE_TERMINATOR_WITH_LC). So we save the payload from the mmdvm-packet and insert/recover this to the hytera-ipsc-packet at the right place. If we do not so, the dmr devices don't detect the CALL_END and will be shown some "hanging effect" - the transmission will not clearly closed and the dmr device will not come back to RX in time. (fixed)
2. If we send a unit call 5000 (DMRplus) for asking which reflector is selected, then the answer voice stream come back, the DMRGateway send a VOICE_TERMINATOR_WITH_LC after this transmission, but the gw_hytera_mmdvm do nothing, no ipsc packet will be generated for call termination. (not fixed yet)
3. UDP ipsc packets from gw_hytera_mmdvm to the repeater have a wrong UDP checksum. (fixed)

...will be continue after next investigations...

73 Heiko/DL1BZ
