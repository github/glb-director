#! /usr/bin/env python
#
# Copyright (c) 2018 GitHub.
#
# This file is part of the `scapy-glb-gue` scapy extension.
#
# scapy-glb-gue is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# scapy-glb-gue is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with scapy-glb-gue.  If not, see <https://www.gnu.org/licenses/>.

# Set log level to benefit from Scapy warnings
import logging
logging.getLogger("scapy").setLevel(1)

from scapy.all import *

class GLBGUEChainedRouting(Packet):
    name = "GLBGUEChainedRouting"
    fields_desc = [
                   ShortField('private_type', 0),
                   ByteField("next_hop", 0),
                   FieldLenField("hop_count", None, count_of='hops', fmt='B'),
                   FieldListField("hops", [], IPField("", "0.0.0.0"), count_from=lambda pkt: pkt.hop_count),
                 ]

class GLBGUE(Packet):
    name = "GLBGUE"
    fields_desc = [BitField("version", 0, 2),
                   BitField("control_msg", 0, 1),
                   BitFieldLenField("hlen", None, 5, length_of='private_data', adjust=lambda pkt, x: (x // 4)),
                   BitField("protocol", 0, 8),
                   BitField("flags", 0, 16),
                   PacketListField("private_data", [], GLBGUEChainedRouting, length_from=lambda p:p.hlen * 4)
                   ]

bind_layers(UDP, GLBGUE, dport=19523)
bind_layers(GLBGUE, IP, protocol=4)
bind_layers(GLBGUE, IPv6, protocol=41)


# print repr(IP(str(IP(dst='192.168.50.10')/UDP(sport=12345, dport=19523)/GLBGUE(private_data=GLBGUEChainedRouting(hops=['8.7.6.5', '1.2.3.4']))/IP(src='192.168.50.123', dst='192.168.50.10')/TCP(sport=123, dport=456))))

if __name__ == "__main__":
   interact(mydict=globals(), mybanner="GLB GUE add-on")
