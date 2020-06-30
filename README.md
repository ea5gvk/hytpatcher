# hytpatcher
A tool for fixing some network protocol (HYTERA_IPSC) issues between [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and a Hytera repeater RD985 with firmware >= 9.xx
We correct some of the UDP packets after sent from [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) with the help of [netqueue](https://pypi.org/project/NetfilterQueue/) and [scapy](https://scapy.net/) for modification and packet processing. No modification of [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) is required and possible (because it's unfortunately closed source).
We are proccessing only UDP packets between [DMRGateway](https://github.com/g4klx/DMRGateway) and [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and between [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and the repeater itself, depend on which ports are defined.

This tool is **AS IS** - but it's not ready yet!
**NO SUPPORT at the time I work on it !**
It was made for using and working, not for the best software design :)
This tool was made for running on a Raspberry Pi with debian buster and Python3.

Issues after investigation will be fixed with this tool:
1. If the [DMRGateway](https://github.com/g4klx/DMRGateway) sends the last packet for call termination (VOICE_TERMINATOR_WITH_LC) then the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) don't fill the similar HYTERA_IPSC-packet (send to repeater) with the payload (fill all with 00 instead of payload with VOICE_TERMINATOR_WITH_LC). So we save the payload from the mmdvm-packet and insert/recover this to the HYTERA_IPSC-packet at the right place. If we do not so, the dmr devices don't detect the CALL_END and will be shown some "hanging effect" - the transmission will not clearly closed and the dmr device will not come back to RX in time. *(fixed)*
2. If we send a unit call 5000 (DMRplus) for asking which reflector is selected, then the answer voice stream come back, the [DMRGateway](https://github.com/g4klx/DMRGateway) send a VOICE_TERMINATOR_WITH_LC after this transmission, but the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) do nothing, no ipsc packet will be generated for call termination. *(not fixed yet)*
3. HYTERA_IPSC packets from [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) to the repeater have a wrong UDP checksum. *(fixed)*
4. VOICE_START_HYTERA packet payload maybe not complete filled too - replace with payload from similar/first mmdvm-packet which starts the transmission *(fixed)*

...will be continue after next investigations, it's a work in progress...

73 Heiko/DL1BZ

sysop DB0OLL/DB0SPB, co-sysop DB0GRZ/DB0NLS, admin and owner DMR-master LausitzLink
