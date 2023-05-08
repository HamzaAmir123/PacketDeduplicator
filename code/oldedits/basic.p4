/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

#define STAGE_BINS_SIZE 400
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<32>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<32> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }
    
    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    counter(8192, CounterType.packets) sentC;
    counter(8192, CounterType.packets) dupC;
    /* Hash table 32-bits x 12 entries */
    
    bit<32> dedup_idx;
    bit<32> key;
    bit<1> dedup_drop;
    bit<32> key_1;
    bit<32> key_2;
    bit<32> key_3;
    bit<32> key_4;
    
    register<bit<32>>(STAGE_BINS_SIZE) dedup_table_1;
    register<bit<32>>(STAGE_BINS_SIZE) dedup_table_2;
    register<bit<32>>(STAGE_BINS_SIZE) dedup_table_3;
    register<bit<32>>(STAGE_BINS_SIZE) dedup_table_4;
    
    action compute_hashes(){
       //Get register position
	   hash(dedup_idx, HashAlgorithm.crc32, (bit<32>)0, {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.checksum},(bit<32>)STAGE_BINS_SIZE);
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
    	dedup_drop = 0;
        if (hdr.ipv4.isValid()) {
            sentC.count((bit<32>) standard_metadata.ingress_port);
            compute_hashes();
            key = (bit<32>) hdr.tcp.checksum;
            
             /* Dedup Stage 1 */
            dedup_table_1.read(key_1, dedup_idx);
            dedup_table_1.write(dedup_idx, key);
            if (key == key_1) {
            	dedup_drop = 1;
	    }
            else{
               /* Dedup Stage 2 */
            	dedup_table_2.read(key_2, dedup_idx);
            	dedup_table_2.write(dedup_idx, key_1);
            	if (key == key_2){
	    			dedup_drop = 1;
            	}
            	else {
 		    /* Dedup Stage 3 */
            	    dedup_table_3.read(key_3, dedup_idx);
            	    dedup_table_3.write(dedup_idx, key_2);
            	    if (key == key_3){
            	    	dedup_drop = 1;
            	    }
            	    else{
            	    	/* Dedup Stage 4 */
            	    	dedup_table_4.read(key_4, dedup_idx);
            	    	dedup_table_4.write(dedup_idx, key_3);
            	    	if (key == key_4){
	    					dedup_drop = 1;
            	    	}
            	    }
            	}
            }
            
	    if(dedup_drop == 1) {
	    	drop();
	    	dupC.count((bit<32>) standard_metadata.ingress_port);
        } 
        else{standard_metadata.egress_spec = (bit<9>)2; }
           
            
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    counter(8192, CounterType.packets) recvC;
    apply { recvC.count((bit<32>) standard_metadata.egress_port); }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.tcp.checksum },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
