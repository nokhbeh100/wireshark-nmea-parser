/*
 * Based on https://gpsd.gitlab.io/gpsd/index.html
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nmea(void);
void proto_reg_handoff_nmea(void);

static int proto_nmea = -1;
static gint ett_nmea = -1;
static gint ett_payload = -1;

static int hf_nmea_identifier = -1;
static int hf_nmea_fragments = -1;
static int hf_nmea_fragno = -1;
static int hf_nmea_seqid = -1;
static int hf_nmea_channel = -1;
static int hf_nmea_payload = -1;
static int hf_nmea_msgtype = -1;

static int hf_nmea_mmsi = -1;

guint8 processed_payload[128];


static dissector_handle_t nmea_handle;

static int process_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    if (tvb_captured_length(tvb) == 0)
        return 0;

    guint c = 0;
    for (guint t = 0; 4*t < tvb_captured_length(tvb); t+=1)
    {
        c = tvb_get_guint8(tvb, 4*t)-48;
        if (c>=48)
            c -= 8;
        processed_payload[3*t] = (c & 0x3F) << 2;

        c = tvb_get_guint8(tvb, 4*t+1)-48;
        if (c>=48)
            c -= 8;
        processed_payload[3*t] |= (c & 0x30) >> 4;
        processed_payload[3*t+1] = (c & 0xF) << 4;
        c = tvb_get_guint8(tvb, 4*t+2)-48;
        if (c>=48)
            c -= 8;
        processed_payload[3*t+1] |= (c & 0x3C) >> 2;
        processed_payload[3*t+2] = (c & 0x3) << 6;
        c = tvb_get_guint8(tvb, 4*t+3)-48;
        if (c>=48)
            c -= 8;
        processed_payload[3*t+2] |= (c & 0x3F);
    }
    tvbuff_t *payload = tvb_new_child_real_data(tvb, processed_payload, tvb_captured_length(tvb)*3/4, tvb_captured_length(tvb)*3/4);
    add_new_data_source(pinfo, payload, "Mapped Data");

    guint start = 0;
    guint msgtype = tvb_get_bits(payload, 0, 6, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_nmea_msgtype, payload, start, 6, ENC_BIG_ENDIAN);
    start += 6;

    switch (msgtype) {
        case 1:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(tree, hf_nmea_mmsi, payload, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        start += 4; // navigation status
        start += 8; // Rate of Turn
        start += 10; // speed over ground
        start += 1; // position accuracy
        start += 28; // long
        start += 27; // lat
        start += 12; // course over ground
        start += 9; // heading
        start += 6; // timestamp



        break;
    }

    return tvb_captured_length(tvb);
}

static int
dissect_nmea(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "NMEA");
  col_set_str(pinfo->cinfo, COL_INFO, "NMEA packet data");

  proto_tree *nmea_tree;
  proto_item *nmea_item;
  nmea_item = proto_tree_add_item(tree, proto_nmea, tvb, 0, -1, ENC_NA);
  nmea_tree = proto_item_add_subtree(nmea_item, ett_nmea);
  int i = 0, j = 0;
  tvbuff_t * comma = tvb_new_real_data(",", 1, 1);

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree_add_item(nmea_tree, hf_nmea_identifier, tvb, i, j-i, ENC_ASCII);
  i = j+1;

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree_add_item(nmea_tree, hf_nmea_fragments, tvb, i, j-i, ENC_ASCII);
  i = j+1;

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree_add_item(nmea_tree, hf_nmea_fragno, tvb, i, j-i, ENC_ASCII);
  i = j+1;

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree_add_item(nmea_tree, hf_nmea_seqid, tvb, i, j-i, ENC_ASCII);
  i = j+1;

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree_add_item(nmea_tree, hf_nmea_channel, tvb, i, j-i, ENC_ASCII);
  i = j+1;

  j = tvb_find_tvb(tvb, comma, i);
  proto_tree *payload_tree;
  proto_item *payload_item;
  payload_item = proto_tree_add_item(nmea_tree, hf_nmea_payload, tvb, i, j-i, ENC_NA);
  payload_tree = proto_item_add_subtree(payload_item, ett_payload);

  process_payload(tvb_new_subset_length(tvb, i, j-i), pinfo, payload_tree, NULL);
  i = j+1;

  return tvb_captured_length(tvb);
}

void
proto_register_nmea(void)
{
  static gint *ett[] = {
    &ett_nmea,
    &ett_payload,
  };

  static hf_register_info hf_nmea[] =
      {
          { &hf_nmea_identifier, { "Identifier", "nmea.id", FT_STRING, STR_ASCII, NULL, 0x0, "Sender Identifier", HFILL} },
          { &hf_nmea_fragments, { "Fragments", "nmea.fragments", FT_STRING, STR_ASCII, NULL, 0x0, "Count of Fragments", HFILL} },
          { &hf_nmea_fragno, { "Fragment No", "nmea.fragno", FT_STRING, STR_ASCII, NULL, 0x0, "Fragment No", HFILL} },
          { &hf_nmea_seqid, { "Seq Id", "nmea.seqid", FT_STRING, STR_ASCII, NULL, 0x0, "Sequence Id", HFILL} },
          { &hf_nmea_channel, { "Channel", "nmea.chn", FT_STRING, STR_ASCII, NULL, 0x0, "Channel", HFILL} },
          { &hf_nmea_payload, { "Payload", "nmea.payload", FT_STRING, STR_ASCII, NULL, 0x0, "Payload", HFILL} },
          { &hf_nmea_msgtype, { "Message Type", "nmea.msgtype", FT_UINT8, BASE_DEC, NULL, 0x0, "Message Type", HFILL} },
          { &hf_nmea_mmsi,    { "MMSI", "nmea.mmsi", FT_UINT32, BASE_DEC, NULL, 0x0, "MMSI", HFILL} },

    };
  proto_nmea = proto_register_protocol("nmea packet data", "nmea", "nmea");
  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_nmea, hf_nmea, array_length(hf_nmea));

  nmea_handle = register_dissector("nmea_udp", dissect_nmea, proto_nmea);
}

void
proto_reg_handoff_nmea(void)
{
  dissector_add_uint_with_preference("udp.port", 5005, nmea_handle);
}

