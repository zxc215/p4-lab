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

action _nop() {
}

// Write TCP port numbers to metadata
action set_tcp_ports() {
    modify_field(l4.sport, tcp.srcPort);
    modify_field(l4.dport, tcp.dstPort);
}

// Write UDP port numbers to metadata
action set_udp_ports() {
    modify_field(l4.sport, udp.srcPort);
    modify_field(l4.dport, udp.dstPort);
}

action gen_rand_number() {
    gen_rand();
}

primitive_action gen_rand();

#define MAX_RN	10000


// Use pre-programmed table lookup to find minimum packet length
// to be sampled, corresponding to a random number
action get_min_len(min_len) {
    modify_field(sampling.min_len, min_len);
    modify_field(sampling.in_range, 1);
}

// Action to set min sampling length to number larger than the longest packet length
action no_sample() {
    modify_field(sampling.in_range, 0);
}

field_list copy_to_cpu_fields {
    standard_metadata;
}

#define CPU_MIRROR_SESSION_ID                  250

// When sampling threshold is reached, packet is sent to CPU
// and sampling register (count) is cleared
action sample_pkt() {
    clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);
}

