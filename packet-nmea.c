/*
 * Based on https://gpsd.gitlab.io/gpsd/AIVDM.html
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nmea(void);
void proto_reg_handoff_nmea(void);

static int proto_nmea = -1;
static int proto_ais = -1;

static gint ett_nmea = -1;
static gint ett_ais = -1;

static int hf_nmea_identifier = -1;
static int hf_nmea_fragments = -1;
static int hf_nmea_fragno = -1;
static int hf_nmea_seqid = -1;
static int hf_nmea_channel = -1;
static int hf_nmea_payload = -1;
static int hf_nmea_msgtype = -1;

static int hf_nmea_mmsi = -1;
static int hf_nmea_rot = -1;
static int hf_nmea_sog = -1;
static int hf_nmea_lon = -1;
static int hf_nmea_lat = -1;
static int hf_nmea_cog = -1;



guint8 processed_payload[128];


static dissector_handle_t nmea_handle;
static dissector_handle_t ais_handle;

static void
I3(gchar *buf, gint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%d.%03u", value / 1000, abs(value) % 1000);
}

static void
I4deg(gchar *buf, gint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%.06f", value / 600000.);
}

static void
U1(gchar *buf, guint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%u.%01u", value / 10, value % 10);
}

static int
dissect_ais(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIS");
    col_set_str(pinfo->cinfo, COL_INFO, "AIS packet data");

    proto_tree *ais_tree;
    proto_item *ais_item;
    ais_item = proto_tree_add_item(tree, proto_ais, tvb, 0, -1, ENC_NA);
    ais_tree = proto_item_add_subtree(ais_item, ett_ais);



    guint start = 0;
    guint msgtype = tvb_get_bits(tvb, 0, 6, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(ais_tree, hf_nmea_msgtype, tvb, start, 6, ENC_BIG_ENDIAN);
    start += 6;

    switch (msgtype) {
        case 1: case 2: case 3:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        start += 4; // navigation status
        proto_tree_add_bits_item(ais_tree, hf_nmea_rot, tvb, start, 8, ENC_BIG_ENDIAN);
        start += 8; // Rate of Turn
        proto_tree_add_bits_item(ais_tree, hf_nmea_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_nmea_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_nmea_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_nmea_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        start += 9; // heading
        start += 6; // timestamp

        break;
    }

    return tvb_captured_length(tvb);
}


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

    dissect_ais(payload, pinfo, tree, NULL);

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
  proto_tree_add_item(nmea_tree, hf_nmea_payload, tvb, i, j-i, ENC_NA);

  process_payload(tvb_new_subset_length(tvb, i, j-i), pinfo, tree, NULL);
  i = j+1;

  return tvb_captured_length(tvb);
}

void
proto_register_nmea(void)
{
  static gint *ett[] = {
    &ett_nmea,
  };

  static hf_register_info hf_nmea[] =
      {
          { &hf_nmea_identifier, { "Identifier", "nmea.id", FT_STRING, STR_ASCII, NULL, 0x0, "Sender Identifier", HFILL} },
          { &hf_nmea_fragments, { "Fragments", "nmea.fragments", FT_STRING, STR_ASCII, NULL, 0x0, "Count of Fragments", HFILL} },
          { &hf_nmea_fragno, { "Fragment No", "nmea.fragno", FT_STRING, STR_ASCII, NULL, 0x0, "Fragment No", HFILL} },
          { &hf_nmea_seqid, { "Seq Id", "nmea.seqid", FT_STRING, STR_ASCII, NULL, 0x0, "Sequence Id", HFILL} },
          { &hf_nmea_channel, { "Channel", "nmea.chn", FT_STRING, STR_ASCII, NULL, 0x0, "Channel", HFILL} },
          { &hf_nmea_payload, { "Payload", "nmea.payload", FT_STRING, STR_ASCII, NULL, 0x0, "Payload", HFILL} },
    };
  proto_nmea = proto_register_protocol("nmea packet data", "nmea", "nmea");
  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_nmea, hf_nmea, array_length(hf_nmea));

  nmea_handle = register_dissector("nmea_udp", dissect_nmea, proto_nmea);

  static gint *ettais[] = {
    &ett_ais,
  };

  static hf_register_info hf_ais[] =
      {
          { &hf_nmea_msgtype, { "Message Type", "nmea.msgtype", FT_UINT8, BASE_DEC, NULL, 0x0, "Message Type", HFILL} },
          { &hf_nmea_mmsi,    { "MMSI", "nmea.mmsi", FT_UINT32, BASE_DEC, NULL, 0x0, "MMSI", HFILL} },
          { &hf_nmea_rot,    { "Rate of Turn", "nmea.rot", FT_INT32, BASE_CUSTOM, CF_FUNC(I3), 0x0, "Rate of Turn", HFILL} },
          { &hf_nmea_sog,    { "Speed Over Ground", "nmea.sog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Speed Over Ground", HFILL} },
          { &hf_nmea_lon,    { "Longitude", "nmea.lon", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Longitude", HFILL} },
          { &hf_nmea_lat,    { "Lattitude", "nmea.lat", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Latitude", HFILL} },
          { &hf_nmea_cog,    { "Course Over Ground", "nmea.cog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Course Over Ground", HFILL} },

    };
  proto_ais = proto_register_protocol("AIS packet data", "ais", "ais");
  proto_register_subtree_array(ettais, array_length(ettais));
  proto_register_field_array(proto_ais, hf_ais, array_length(hf_ais));

  ais_handle = register_dissector("ais_nmea", dissect_ais, proto_ais);

}

void
proto_reg_handoff_nmea(void)
{
  dissector_add_uint_with_preference("udp.port", 5005, nmea_handle);
}

