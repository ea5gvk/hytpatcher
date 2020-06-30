#!/usr/bin/env python3
#
# Hytera IPSC protocol patch tool by Heiko/DL1BZ for gw_hytera_mmdvm (latest edited version from 2020 for Linux/RaspberryPi with debian buster)
# This tool is build to correct some network protocol issues if you using the gw_hytera_mmdvm from Kurt/OE1KBC http://ham-dmr.at/?wpfb_dl=651
# gw_hytera_mmdvm is a protocol converter for Linux between Hytera IPSC and the MMDVM-/HB-protocol at network level, which we use as base for DMR networks in hamradio
# So we can using a commercial Hytera repeater like RD985 with our DMR master servers in hamradio and in combination with DMRGateway we can connect multiple dmr networks at the same time
#
# It was made for using a Hytera repeater RD985 (maybe RD625 too) with firmware >= 9.xx
# The tool modify only outgoing UDP packets at the voice & data port sent from gw_hytera_mmdvm to the repeater
# We need to use Python3, NOT Python2 !
# Only works in addition/combination with gw_hytera_mmdvm - if you not using gw_hytera_mmdvm, you don't need this tool !

## Installation
# sudo apt-get install build-essential python3-dev libnetfilter-queue-dev
# sudo pip3 install NetfilterQueue scapy dmr_utils3 easysnmp

## some References...
# https://www.digitalocean.com/community/tutorials/how-to-list-and-delete-iptables-firewall-rules
# https://github.com/phaethon/scapy
# https://5d4a.wordpress.com/2011/08/25/having-fun-with-nfqueue-and-scapy/
# https://pypi.python.org/pypi/NetfilterQueue/0.3
# http://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html
# http://www.linuxjournal.com/article/7356
# https://github.com/n0mjs710/hblink3
# https://github.com/n0mjs710/dmr_utils3
# https://github.com/nonoo/dmrshark
# https://github.com/kb1isz/OpenIPSC/blob/master/README.hytera

# thanks a lot to Cortney/N0MJS (developer of Hblink3 and my mentor) for help me to convert some data and important information about MMDVM things
# Hytera IPSC protocol was deeply analyzed with DMRShark https://github.com/nonoo/dmrshark and information from https://github.com/kb1isz/OpenIPSC/blob/master/README.hytera
#
# All is developed only for use a Hytera Repeater in hamradio digital voice DMR networks - NOT for commercial use ! It's free to use without *any* warranty or commitments on my part.
#
# Important ! NO support at this time, status is only *pre-alpha*. It's not a complete piece of software - it's in development as proof-of-concept. That's all is a project I do in my spare time !
# 
# I have nothing to do with the manufacturer Hytera - no partnership, no dealer contracts or other agreements.
# I own a Hytera RD985 by myself and this tool helps me for a better work with this repeater.

import netfilterqueue
import socket
import sys
import os
from binascii import b2a_hex as ahex
from binascii import a2b_hex as bhex
from time import time
from dmr_utils3.utils import int_id
from easysnmp import snmp_get

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
    HBPF_VOICE      = 0x0
    HBPF_VOICE_SYNC = 0x1
    HBPF_DATA_SYNC  = 0x2
    HBPF_SLT_VHEAD  = 0x1
    HBPF_SLT_VTERM  = 0x2
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
    return(_ft,_slot,_ct,_frame_type,_dtype_vseq)

# main function for processing the UDP packet is landed in netqueue defined with rules from iptables
# the packet will be stored in netqueue until we accept it for transmit as a kind of packet store-and-forward
def process(pkt):
    # we need to save ambe payload from MMDVM as global var
    global ambe_payload_mmdvm
    # we need to save the last packet Seq from Hytera IPSC UDP packet for later processing as global var
    global last_seq_HYT
    # get payload from packet is landed in netqueue - the payload is including(!) the IP header - the payload we use starts at p[28:]
    data = IP(pkt.get_payload())
    # process only UDP packets longer than 80, shorter packets will be pass-thru without any modification
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
          print(p1,":from DMRGateway(payload)    Seq.Nr:",hex(p[32]),"Byte15-Flags:",format(p[43],'08b'),check_FrameType_MMDVM(p[43]),"SrcId:",int_id(p[33:36]),"T:",int_id(p[36:39]))
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
             # save the last HYT SeqNr (0x00 to 0xFF) of UDP payload for later use (format uint8)
             last_seq_HYT = p[32]
             # print(hex(last_seq_HYT))
             # replace the Offset_0-3 ZZZZ with 00 00 00 00 (not sure - stamped packet as packet from base station/master)
             p[28:32] = bytearray.fromhex('00 00 00 00')
             # check if the Hytera packet is START_OF_TRANSMISSION SeqNr.0x0/Offset_4 and 0x2/Offset_8
             if p[36] == 2 and p[32] == 0:
                print("CALL_START_PAYLOAD possible not correct => need MODIFY...processing packet...")
                # insert the MMDVM payload VOICE_START
                p[54:88] = bhex(ambe_payload_mmdvm)
                print(ahex(p[54:88]),":to RD985 replace with MMDVM(swapped) SrcId:",int.from_bytes(SrcId, byteorder='little')," T:",int.from_bytes(bhex(DestId), byteorder='big'),"(",check_CallType_HYT(p[90]),") TS:",Slot)
                print("CALL_START => now OK")
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

# reserved for do additional things with the packet if required
def modify_packet(_pkt):
     return _pkt

# send UDP packet to RD985 at port 62006 Voice & Data
def UDPsendHYT(_payload_hyt):
    # send to IP address of Hytera repeater and port like given in CPS
    UDPsockHYT.sendto(_payload_hyt, ("192.168.254.8", 62006))

# query the Hytera repeater via SNMP V1 for status values, community is "hytera" here and NOT "public" like default -> define this in CPS !
def statsnmp(_oid):
    # IP address is IP of Hytera repeater
    _snmp_response = snmp_get(_oid, hostname='192.168.254.8', community='hytera', version=1)
    # return is string not int!
    return(_snmp_response.value)

# if __name__ == "__main__":

# Start main program
print("STARTING HYT_IPSC_PATCHER for HYTERA RDXXX repeaters...")
print("(c) by DL1BZ, 2020 -=NOT FOR COMMERCIAL USE=- All rights reserved.")
# values for repeater via SNMP 
print("\nRepeatertyp:",statsnmp('1.3.6.1.4.1.40297.1.2.4.1.0'),"FW:",statsnmp('1.3.6.1.4.1.40297.1.2.4.3.0'),"Call:",statsnmp('1.3.6.1.4.1.40297.1.2.4.6.0'),"TX:",(int(statsnmp('1.3.6.1.4.1.40297.1.2.4.10.0')))/1000000,"MHz","RX:",(int(statsnmp('1.3.6.1.4.1.40297.1.2.4.11.0')))/1000000,"MHz","ID:",int(statsnmp('1.3.6.1.4.1.40297.1.2.4.7.0')))
# initialize socket for sending UDP packets to RD985
UDPsockHYT = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

# define that we want to use netqueue
nfqueue = netfilterqueue.NetfilterQueue()
# bind the netqueue 1 for processing
nfqueue.bind(1, process)

try:
    # define the iptables rules for process only the packets we need to modify redirected to netqueue number 1
    #
    # the gw_hytera_mmdvm send with IP 192.168.254.9 (IP of Pi) and the Hytera repeater RD985 has IP 192.168.254.8
    # we use netqueue for modify packets betweeen the voice & data port 62006 only with direction gw_hytera_mmdvm->Hytera repeater RD985
    print("\nInitializing IPTABLES for using NetQueue...")
    os.system("iptables -A OUTPUT -p udp -s 192.168.254.9 -d 192.168.254.8 --dport 62006 -j NFQUEUE --queue-num 1")
    # DMRGateway and gw_hytera_mmdvm are linked via 127.0.0.1, we need only the direction DMRGateway->gw_hytera_mmdvm with destination port 62022
    os.system("iptables -A OUTPUT -p udp -s 127.0.0.1 -d 127.0.0.1 --dport 62022 -j NFQUEUE --queue-num 1")
    print("running NetQueue for processing and modify UDP packets...")
    nfqueue.run()
except:
    # stop the netqeueue processing
    print("unbind NetQueue...")
    nfqueue.unbind()
    # delete the iptables rules if we want to exit from program
    print("delete IPTABLES rules for using NetQueue...")
    os.system("iptables -F")
    # exit the program
    sys.exit(1)
