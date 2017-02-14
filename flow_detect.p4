/*
Copyright 2017-present New York University 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "includes/headers.p4"
#include "includes/parser.p4"
#include "includes/actions.p4"

// This program performs large flow detection using sample and hold.
// When a packet is received, we check if it is already in the flow table.
// If it is, the corresponding flow byte counter is incremented
// If it is not, a sampling counter is incremented.  If the sampling counter
// reaches a programmable threshold, the packet is forwarded to the CPU.
// The CPU then programs the corresponding flow into the table.
 
// Store TCP or UDP port numbers in metadata to create flow 5-tuple
// This table is initialized upon startup
table ports {
    reads {
        ipv4.protocol: exact;
    }
    actions {
        set_tcp_ports;
        set_udp_ports;
    }
}

// Flow 5-tuple lookup.
// This table is written by the CPU when it receives a "sampled" packet.
// The CPU extracts the 5-tuple info from the packet and writes it to this table.
// The action is no op; the table is used only for counting bytes per flow 
// (see counter below)
table flow {
    reads {
        ipv4.srcAddr : exact;
	ipv4.dstAddr : exact;
        ipv4.protocol : exact;
	l4.sport : exact;
        l4.dport : exact;
    }
    actions {
        _nop;
    }
    size: 16384;
}

// Byte counter associated with table above.  Each flow present in the table
// has its own counter, which gets incremented by the number of bytes upon a hit
counter flow_counter {
    type: bytes;
    direct: flow;
}

// Random number generation used for packet sampling
table rand {
    actions {
        gen_rand_number; // default
    }
}

// This table is used to look up the shortest packet that can be sampled
// according to the generated random number.  If the random number is within
// the valid range for sampling, the corresponding min packet length is read out
// of this table.  Otherwise, the length is set to a high number such that no packet is sampled.
// This table is programmed at startup.
table sample_prob {
    reads {
	sampling.rand: range;
    }
    actions {
	get_min_len;
	no_sample;
    }
}

// Packet sampling (send mirrored copy to CPU)
table sample {
    actions {
        sample_pkt; // default
    }
}

// Sequential processing:
// 1- Get port numbers from TCP or UDP
// 2- Check if flow in table
// 3- On miss:
//     4- Get random number
//     5- Lookup minimum packet length corresponding to random number
//     6- if received packet is longer than min length, sample (send to CPU)
control ingress {
    apply(ports);
    apply(flow) {
        miss {
            apply(rand);
            apply(sample_prob);
            if ((sampling.in_range == 1) and
                (standard_metadata.packet_length >= sampling.min_len)) {
                apply(sample);
            }
        }
    }
}

// Send all packets (normal and mirrored)
table send_frame {
    reads {
        standard_metadata.instance_type : exact;
    }
    actions {
        _nop;
    }
    size: 16;
}

control egress {
    apply(send_frame);
}
