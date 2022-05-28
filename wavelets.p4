#include <core.p4>
#include <v1model.p4>

header ethernet_t {
	bit<48> dst;
	bit<48> src;
	bit<16> etype;
}

header ipv4_t {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> total_len;
	bit<16> id;
	bit<3> flags;
	bit<13> offset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> checksum;
	bit<32> src;
	bit<32> dst;
}

header tcp_t {
	bit<16> src;
	bit<16> dst;
	bit<32> seqno;
	bit<32> ackno;
	bit<4> data_offset;
	bit<4> reserved;
	bit<1> cwr;
	bit<1> ece;
	bit<1> urg;
	bit<1>	ack;
	bit<1>	psh;
	bit<1>	rst;
	bit<1>	syn;
	bit<1> fin;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

struct intrinsic_metadata_t {
	bit<64> ingress_global_tstamp;
	bit<64> current_global_tstamp;
	bit<32> index;
	bit<32> timeinterval;
}

struct metadata {
	intrinsic_metadata_t intrinsic_metadata;
}

struct headers {
	ethernet_t 	ethernet;
	ipv4_t		ipv4;
	tcp_t		tcp;
}

const bit<16> 	ARP_TYPE 	= 0x0806;
const bit<16> 	IPV4_TYPE 	= 0x0800;
const bit<8>	TCP_PROTO	= 0x06;
const bit<32> 	TABLE_SIZE  	= 4096;
const bit<32>	NUM_LEVELS 	= 17;

/*************************************************************************
*********************** R E G I S T E R S  *****************************
*************************************************************************/
register<bit<64>>(TABLE_SIZE * (NUM_LEVELS+1)) sum;
register<bit<32>>(TABLE_SIZE) N;

extern void do_wavelets();

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        state start {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etype) {
			IPV4_TYPE:	parse_ipv4;
			default:	accept;
		}
        }
	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			TCP_PROTO:	parse_tcp;
			default:	accept;
		}
	}
	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
        apply {

        }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        action act_forward(bit<16> port) {
                standard_metadata.egress_spec = port;
        }
	
	action act_tag(bit<32> index, bit<32> timeinterval) {
		meta.intrinsic_metadata.index = index;
		meta.intrinsic_metadata.timeinterval = timeinterval;
	}
	

        table tbl_direction {
                actions = {
                        act_forward;
                }
                key = {
                        standard_metadata.ingress_port : exact;
                }
        }

	table tbl_flows {
		actions = {
			act_tag;
		}
		key = {
			hdr.ipv4.dst : ternary;
			hdr.ipv4.src : ternary;
			hdr.tcp.src : ternary;
			hdr.tcp.dst : ternary;
		}
	}
	
        apply {
		if(hdr.ipv4.isValid()) {
			if(hdr.tcp.isValid()) {
				if(tbl_flows.apply().hit) {
                    			do_wavelets();
				}
			}
			hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
			tbl_direction.apply();
		} else {
			if(hdr.ethernet.etype == ARP_TYPE) {
				tbl_direction.apply();
			} else {
				mark_to_drop();
			}
		}
        }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
        apply {

        }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
        apply {
		update_checksum(
			hdr.ipv4.isValid(),
			{ 
			hdr.ipv4.version,
			hdr.ipv4.ihl,
			hdr.ipv4.diffserv,
			hdr.ipv4.total_len,
			hdr.ipv4.id,
			hdr.ipv4.flags,
			hdr.ipv4.offset,
			hdr.ipv4.ttl,
			hdr.ipv4.protocol,
			hdr.ipv4.src,
			hdr.ipv4.dst
			},
			hdr.ipv4.checksum,
			HashAlgorithm.csum16
		);
        }
}

control DeparserImpl(packet_out packet, in headers hdr) {
        apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.tcp);
        }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
