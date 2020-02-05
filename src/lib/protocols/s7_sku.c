#include "ndpi_protocol_ids.h"


#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_S7

#include "ndpi_api.h"

void ndpi_search_s7(struct ndpi_detection_module_struct *ndpi_struct,
                            struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t s7_port = htons(102); // port used by S7 Server

  /* Check connection over TCP */
  NDPI_LOG_DBG(ndpi_struct, "Searching S7 Packet...\n");
  
  if(packet->tcp) {
    /* The start byte of 104 is 0x68
     * The usual port: 2404
     */
    // search trigger: example TODO
    if(packet->payload[0] == 0x03 && 
       packet->payload[1] == 0x00 &&
       packet->payload[4] == 0x02 &&
       packet->payload[5] == 0xF0 &&
       packet->payload[6] == 0x80 &&
       packet->payload[7] == 0x32 &&
       ((packet->tcp->dest == s7_port) || (packet->tcp->source == s7_port)) ){
      NDPI_LOG_INFO(ndpi_struct, "S7 packet is detected!\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_S7, NDPI_PROTOCOL_UNKNOWN);
      return;
    }
  }
  
  NDPI_EXCLUDE_PROTO(ndpi_struct, flow);   
}



void init_s7_dissector(struct ndpi_detection_module_struct *ndpi_struct,
                       u_int32_t *id,
                       NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("S7", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_S7,
				      ndpi_search_s7,
				    //   NDPI_SELECTION_BITMASK_PROTOCOL_UDP_WITH_PAYLOAD,
                      NDPI_SELECTION_BITMASK_PROTOCOL_TCP_WITH_PAYLOAD,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);

  *id += 1;
}