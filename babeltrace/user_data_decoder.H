#pragma once
typedef struct PacketFingerprint {
     uint8_t  feed;
     uint8_t  line; // TODO: do I care about group??
     // NOTE: do I want to fill these two bytes with anything? maybe packet_receive_timestamp - packet_dequeue_t
     uint16_t pad;
     uint32_t sequence_number;
} __attribute__((packed)) PacketFingerprint_t;
// TODO: use SBE for decoding and use it generally for user-data encoding w/
// Xpedite? Alternatively, maybe provide a SBE filter component which does the
// user-data decoding??


// TODO: move this to a babeltrace filter plugin which is product-specific and knows how to decode probe user data
// TODO: alternatively, provide a user data decoder babeltrace method which
// populates appropriate event fields for the given probe type
