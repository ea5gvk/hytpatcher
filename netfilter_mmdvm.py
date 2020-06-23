## Hytera IPSC protocol patch tool by Heiko/DL1BZ
# This tool is build to correct some protocol issues if you using the gw_hytera_mmdvm from Kurt/OE1KBC http://ham-dmr.at/?wpfb_dl=651
# It was made for using a Hytera Repeater RD985 (maybe RD625 too) with Firmware >= 9.xx
# The tool modify only outgoing UDP packets at the voice & data port sent from gw_hytera_mmdvm to the repeater
# we need to use Python3, NOT Python2 !
# only works in addition with gw_hytera_mmdvm - if not, you don't need this tool

## Installation
# sudo apt-get install build-essential python-dev libnetfilter-queue-dev
# sudp pip3 install NetfilterQueue scapy

## some References...
# https://www.digitalocean.com/community/tutorials/how-to-list-and-delete-iptables-firewall-rules
# https://github.com/phaethon/scapy
# https://5d4a.wordpress.com/2011/08/25/having-fun-with-nfqueue-and-scapy/
# https://pypi.python.org/pypi/NetfilterQueue/0.3
# http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html
# http://www.linuxjournal.com/article/7356

# thanks a lot to Cortney/N0MJS for help me to convert some data and important information about MMDVM things
# Hytera IPSC protocol was analyzed with DMRShark https://github.com/nonoo/dmrshark and information from https://github.com/kb1isz/OpenIPSC/blob/master/README.hytera

import netfilterqueue
import socket
import sys
import os
from binascii import b2a_hex as ahex
from binascii import a2b_hex as bhex
from time import time

from scapy.all import *

# static slice/join function for swapping the bytes in ambe payload between MMDVM and Hytera
def byte_swap(pl):
    return b''.join([pl[2:4],pl[0:2], pl[6:8],pl[4:6], pl[10:12],pl[8:10], pl[14:16],pl[12:14], pl[18:20],pl[16:18], pl[22:24],pl[20:22], pl[26:28],pl[24:26], pl[30:32],pl[28:30], pl[34:36],pl[32:34], pl[38:40],pl[36:38], pl[42:44],pl[40:42], pl[46:48],pl[44:46], pl[50:52],pl[48:50], pl[54:56],pl[52:54], pl[58:60],pl[56:58], pl[62:64],pl[60:62], pl[66:68],pl[64:66]])

# reorder the bytes for correct calculating the destination
def swap_DestId(_dst):
    return b''.join([_dst[4:6],_dst[2:4],_dst[0:2]])

# check if group or unit call in Hytera packet
def check_CallType_HYT(_CallByte):
    answer = "group" if (_CallByte == 1) else "unit"
    return(answer)

# check slot number in Hytera packet
def check_Slot_HYT(slotBytes):
    if slotBytes == b'1111':
       slot = 1
    elif slotBytes == b'2222':
       slot = 2
    return(slot)

def check_FrameType_HYT(frameByte):
    if frameByte == 1:
       FrameDescription = "VOICE FRAME"
    elif frameByte == 2:
       FrameDescription = "START OF TRANSMISSION OR SYNC"
    elif frameByte == 3:
       FrameDescription = "END OF TRANSMISSION"
    else:
       FrameDescription = "PART OF VOICE"
    return(FrameDescription)

def check_FrameType_MMDVM(_bits):
    _frame_type = (_bits & 0x30) >> 4
    _dtype_vseq = (_bits & 0xF)
    HBPF_DATA_SYNC = 0x2
    HBPF_SLT_VTERM = 0x2
    if (_frame_type == HBPF_DATA_SYNC) and (_dtype_vseq == HBPF_SLT_VTERM):
       _ft = "MMDVM: END OF TRANSMISSION"
    else:
       _ft = ""
    _slot = 2 if (_bits & 0x80) else 1
    if _bits & 0x40:
       _ct = 'unit'
    elif (_bits & 0x23) == 0x23:
       _ct = 'vcsbk'
    else:
       _ct = 'group'
    return(_ft,_slot,_ct)

def process(pkt):
    # we need to save ambe payload from MMDVM as global var
    global ambe_payload_mmdvm
    # get payload from packet is landed in netqueue
    data = IP(pkt.get_payload())
    # process only UDP packets longer than 80
    if len(data) > 80 :
       # hexdump(data)
       # print("Length:", len(data),"\n\r")
       # extract payload from UDP packet
       mod_data = raw(data)
       # convert to bytearray
       p = bytearray(mod_data)
       # print(p[28:])
       # is the packet a MMDVM DMRD packet ?
       if p[28:32] == b"DMRD" :
       # if p[28] == 68 and p[29] == 77 and p[30] == 82 and p[31] == 68 :
          print("------ packet processing MMDVM ------")
          p1 = bytearray(p[48:82])
          p1 = ahex(p1)
          print(p1,":from DMRGateway(payload)    Seq.Nr:",hex(p[32]),"Byte15-Flags:",format(p[43],'08b'),check_FrameType_MMDVM(p[43]))
          # swap the ambe mmdvm payload HiByte<>LowByte needed for use in Hytera ambe payload
          p2 = byte_swap(p1)
          # save swapped ambe payload in ambe_paylaod_mmdvm for later insert in Hytera ambe payload
          ambe_payload_mmdvm = p2
          print(p2,":modify MMDVM(Byte_swapping) Seq.Nr:",hex(p[32]),"Byte15-Flags:",format(p[43],'08b'))
          # print(ahex(p[48:82]))
          # print(ahex(p[48:82]),":MMDVM Seq.Nr: ",hex(p[32]),"Status: ",format(p[43],'08b'))
       # is it a Hytera packet ?
       elif p[28:32] == b"ZZZZ" or p[28:32] == bytearray.fromhex('ee ee 11 11'):
          print("------ packet processing IPSC HYTERA ------")
          # print(ambe_payload_mmdvm,":saved")
          # get the SrcId from Hytera payload
          SrcId = p[96:99]
          # get the destination Id from Hytera paylaod
          _DestId = bytearray(p[92:95])
          _DestId = ahex(_DestId)
          # change byteorder for correct calculating destination Id
          DestId = swap_DestId(_DestId)
          # print(ahex(p[44:46]))
          # get slot number from Hytera payload
          _slot = bytearray(p[44:46])
          _slot = ahex(_slot)
          Slot = check_Slot_HYT(_slot)
          print(ahex(p[28:32]),":first 4 Bytes from HytGW Seq.Nr:",hex(p[32]),"FrameType:",hex(p[36]),"Frametype:",check_FrameType_HYT(p[36]))
          print(ahex(p[54:88]),":from HytGW unpatched                 SrcId:",int.from_bytes(SrcId, byteorder='little')," T:",int.from_bytes(bhex(DestId), byteorder='big'),"(",check_CallType_HYT(p[90]),") TS:",Slot)
          # delete the UDP checksum and fill with 00 00 as No_CheckSum
          p[26:28] = bytearray.fromhex('00 00')
          if p[28:32] == b"ZZZZ":
          # if p[28] == 90 and p[29] == 90 and p[30] == 90 and p[31] == 90:
             # replace the Offset_0-3 ZZZZ with 00 00 00 00 (not sure - stamped packet as packet from base station/master)
             p[28:32] = bytearray.fromhex('00 00 00 00')
             # check if the Hytera packet is END_OF_TRANSMISSION 0x2222/Offset_18-19 and 0x3/Offset_8
             if p[46:48] == bytearray.fromhex('22 22') and p[36] == 3:
             # if p[46] == 34 and p[47] == 34 and p[36]) == 3:
                print("CALL_END_WITHOUT_PAYLOAD => need MODIFY...processing packet...")
                # p[28:32] = bytearray.fromhex('00 00 00 00')
                # correct some bytes in Hytera payload
                p[48:50] = bytearray.fromhex('11 11')
                p[51:53] = bytearray.fromhex('00 10')
                # insert the MMDVM payload VOICE_TERMINATOR_WITH_LC because the Hytera_GW do it NOT and fill all with 00 !
                p[54:88] = bhex(ambe_payload_mmdvm)
                print(ahex(p[54:88]),":to RD985 replace with MMDVM(swapped) SrcId:",int.from_bytes(SrcId, byteorder='little')," T:",int.from_bytes(bhex(DestId), byteorder='big'),"(",check_CallType_HYT(p[90]),") TS:",Slot)
                print("CALL_END_WITH_Voiceterminator_LC => now OK")
       # write all changes to packet in netqueue
       p = modify_packet(p)
       pkt.set_payload(bytes(p))
    # we accept now the packet in netqueue with all changes and transmit it
    pkt.accept()

def modify_packet(mpkt):
    return mpkt

# if __name__ == "__main__":

# define that we want to use netqueue
nfqueue = netfilterqueue.NetfilterQueue()
# bind the netqueue 1 for processing
nfqueue.bind(1, process)

try:
    # define the iptables rules for process only the packets we need to modify redirected to netqueue number 1
    os.system("iptables -A OUTPUT -p udp -s 192.168.254.9 -d 192.168.254.8 --dport 62006 -j NFQUEUE --queue-num 1")
    os.system("iptables -A OUTPUT -p udp -s 127.0.0.1 -d 127.0.0.1 --dport 62022 -j NFQUEUE --queue-num 1")
    nfqueue.run()
except:
    # stop the netqeueue processing
    nfqueue.unbind()
    # delete the iptables rules if we want to exit from program
    os.system("iptables -F")
    # exit the program
    sys.exit(1)

# iptables -A OUTPUT -p udp -s 192.168.254.9 -d 192.168.254.8 --dport 62006 -j NFQUEUE --queue-num 1
# sudo iptables -A INPUT -d 127.0.0.1/32 -j NFQUEUE --queue-num 1
