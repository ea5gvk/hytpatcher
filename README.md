# hytpatcher
A free tool for fixing some network protocol (HYTERA_IPSC) issues between [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and a HYTERA(tm) repeater RD985 with firmware >= 9.xx
We correct some of the UDP packets after sent from [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) with the help of [netqueue](https://pypi.org/project/NetfilterQueue/) and [scapy](https://scapy.net/) for modification and packet processing. No modification of [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) is required and possible (because it's unfortunately closed source).
We are proccessing only UDP packets between [DMRGateway](https://github.com/g4klx/DMRGateway) and [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and between [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) and the repeater itself, depend on which ports are defined.

**required:** Raspberry Pi (3B or higher) with debian buster, [gw_hytera_mmdvm V2.1](http://ham-dmr.at/?wpfb_dl=651), [DMRGateway](https://github.com/g4klx/DMRGateway),  
a HYTERA(tm) repeater like RD985 with FW >= 9.x  
You can use [this Image](https://www.a23-wertheim.de/downloads/dmr/dmrgateway-2/file/35-dmrgateway-image-a23-06092018-zip) for Raspberry Pi (made by Peter/DG9FFM, thanks to him for his work) and install the additional and required software you need like python3-dev and so on with the help of debian packet installer apt. The [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) is preinstalled in this image, [DMRGateway](https://github.com/g4klx/DMRGateway) too.

**required add-ons for python3:** scapy, NetfilterQueue, dmr_utils3, easysnmp  

*Can you help if any problems with installation of the add-ons ?*  
No, I can't. Please read the installation instructions of the required add-ons. It all depends on how you installed your Linux and how you use it. The recommended way is to use "pip3 install add_on" for installation or "pip3 install add_on --upgrade" for upgrade an installed add-on, where add_on represent the name as a placeholder of the add-on.  

*recommended:* confident use of Linux and python3, knowledge of how to use DMR and MMDVM specific things in amateur radio digital voice networks, knowledge of how to program a HYTERA(tm) repeater with CPS, basic network knowledge  

*level:* advanced (made for sysops or owner of HYTERA(tm) repeater used in amateur radio digital voice networks only)  

**METHOD:** Reverse engineering by pattern matching, process of elimination and practical tests, code analysis of free and public source code with HYTERA(tm) IPSC and MMDVM support  
**USED TOOLS:** [tcpdump](https://www.tcpdump.org/), [dmrshark](https://github.com/nonoo/dmrshark), [dmr_utils3 for python](https://github.com/n0mjs710/dmr_utils3), [scapy](https://scapy.net/), [python3](https://www.python.org/), [ETSI TS 102 361-1 "DMR Air Interface (AI) protocol"](https://www.etsi.org/deliver/etsi_ts/102300_102399/10236101/01.04.05_60/ts_10236101v010405p.pdf)  
**PROPERTY:** This work represents the author's interpretation of the HYTERA(tm) IPSC protocol and MMDVM protocol. It is intended for purposes in amateur radio digital voice networks and not for commercial gain. It's not guaranteed to work in any cases.

*Any relationships with the manufacturer HYTERA(tm) ?*  
Absolut not, no NDA, no contracts.  

Why we need the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) ?  
The HYTERA(tm) repeater can connect only ONE DMR network at the same time and in hamradio we have a DMR network protocol specification called MMDVM/homebrew protocol.
A commercial repeater like the HYTERA(tm) don't speak MMDVM, only it's own IPSC (IP site connect). So we need a kind of protocol converter between HYTERA_IPSC and MMDVM. That's what the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) do, but with some issues, not much, but...so we try to correct the known issues with this tool.
The [DMRGateway](https://github.com/g4klx/DMRGateway) help us to connect up to 5 DMR networks and one [XLX](https://github.com/LX3JL/xlxd) at the same time.

If you don't using a HYTERA(tm) repeater with the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) this tool can't do anything for you !

This tool is **AS IS** - but it's not ready yet!
**NO SUPPORT at the time I work on it !**
It was made for using and working, not for the best software design :)
This tool was made for running on a Raspberry Pi with debian buster and Python3 and some additional required python-add-ons.

Issues after investigation with my RD985 will be fixed with this tool:
1. If the [DMRGateway](https://github.com/g4klx/DMRGateway) sends the last packet for call termination (VOICE_TERMINATOR_WITH_LC) then the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) don't fill the similar HYTERA_IPSC-packet (send to repeater) with the payload (fill all with 00 instead of payload with VOICE_TERMINATOR_WITH_LC). So we save the payload from the mmdvm-packet and insert/recover this to the HYTERA_IPSC-packet at the right place. If we do not so, the dmr devices don't detect the CALL_END and will be shown some "hanging effect" - the transmission will not clearly closed and the dmr device will not come back to RX in time. *(fixed)*
2. If we send a unit call 5000 (DMRplus) for asking which reflector is selected, then the answer voice stream come back, the [DMRGateway](https://github.com/g4klx/DMRGateway) send a VOICE_TERMINATOR_WITH_LC after this transmission, but the [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) do nothing, no HYTERA_IPSC packet will be generated for call termination. *(not fixed yet)*
3. HYTERA_IPSC packets from [gw_hytera_mmdvm](http://ham-dmr.at/?wpfb_dl=651) to the repeater have a wrong UDP checksum. *(fixed)*
4. VOICE_START_HYTERA packet payload maybe not complete filled too - replace with payload from similar/first mmdvm-packet which starts the transmission *(fixed)*

...will be continue after next investigations, it's a work in progress...

Special thanks to Cort/N0MJS, the developer of [HBlink for Python3](https://github.com/n0mjs710/hblink3) for support me with a lot of information and help with MMDVM protocol specific things and some cool python solutions for my tool !

73 Heiko/DL1BZ  
sysop DB0OLL/DB0SPB, co-sysop DB0GRZ/DB0NLS, admin and owner DMR-master LausitzLink
