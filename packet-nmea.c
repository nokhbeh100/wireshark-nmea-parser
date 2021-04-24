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
static int hf_nmea_navstat = -1;
static int hf_nmea_rot = -1;
static int hf_nmea_sog = -1;
static int hf_nmea_lon = -1;
static int hf_nmea_lat = -1;
static int hf_nmea_cog = -1;
static int hf_nmea_hdg = -1;

static int hf_nmea_imo = -1;
static int hf_nmea_callsign = -1;
static int hf_nmea_name = -1;
static int hf_nmea_shptyp = -1;
static int hf_nmea_dest = -1;



guint8 processed_payload[128];

gchar sixBits[64] = {
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    ' ', '!', '\"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?'};


static char str[1024];


static dissector_handle_t nmea_handle;
static dissector_handle_t ais_handle;

static const value_string vals_nav_stat[] = {
    { 0, "Under way using engine" },
    { 1, "At anchor" },
    { 2, "Not under command" },
    { 3, "Restricted manoeuverability" },
    { 4, "Constrained by her draught" },
    { 5, "Moored" },
    { 6, "Aground" },
    { 7, "Engaged in Fishing" },
    { 8, "Under way sailing" },
    { 9, "Reserved for future amendment of Navigational Status for HSC" },
    { 10, "Reserved for future amendment of Navigational Status for WIG" },
    { 11, "Reserved for future use" },
    { 12, "Reserved for future use" },
    { 13, "Reserved for future use" },
    { 14, "AIS-SART is active" },
    { 15, "Not defined (default)" },
    { 0, NULL },
};

static const value_string vals_ship_type[] = {
    //{1-19, "Reserved for future use"},
    {20, "Wing in ground (WIG), all ships of this type"},
    {21, "Wing in ground (WIG), Hazardous category A"},
    {22, "Wing in ground (WIG), Hazardous category B"},
    {23, "Wing in ground (WIG), Hazardous category C"},
    {24, "Wing in ground (WIG), Hazardous category D"},
    {25, "Wing in ground (WIG), Reserved for future use"},
    {26, "Wing in ground (WIG), Reserved for future use"},
    {27, "Wing in ground (WIG), Reserved for future use"},
    {28, "Wing in ground (WIG), Reserved for future use"},
    {29, "Wing in ground (WIG), Reserved for future use"},
    {30, "Fishing"},
    {31, "Towing"},
    {32, "Towing: length exceeds 200m or breadth exceeds 25m"},
    {33, "Dredging or underwater ops"},
    {34, "Diving ops"},
    {35, "Military ops"},
    {36, "Sailing"},
    {37, "Pleasure Craft"},
    {38, "Reserved"},
    {39, "Reserved"},
    {40, "High speed craft (HSC), all ships of this type"},
    {41, "High speed craft (HSC), Hazardous category A"},
    {42, "High speed craft (HSC), Hazardous category B"},
    {43, "High speed craft (HSC), Hazardous category C"},
    {44, "High speed craft (HSC), Hazardous category D"},
    {45, "High speed craft (HSC), Reserved for future use"},
    {46, "High speed craft (HSC), Reserved for future use"},
    {47, "High speed craft (HSC), Reserved for future use"},
    {48, "High speed craft (HSC), Reserved for future use"},
    {49, "High speed craft (HSC), No additional information"},
    {50, "Pilot Vessel"},
    {51, "Search and Rescue vessel"},
    {52, "Tug"},
    {53, "Port Tender"},
    {54, "Anti-pollution equipment"},
    {55, "Law Enforcement"},
    {56, "Spare - Local Vessel"},
    {57, "Spare - Local Vessel"},
    {58, "Medical Transport"},
    {59, "Noncombatant ship according to RR Resolution No. 18"},
    {60, "Passenger, all ships of this type"},
    {61, "Passenger, Hazardous category A"},
    {62, "Passenger, Hazardous category B"},
    {63, "Passenger, Hazardous category C"},
    {64, "Passenger, Hazardous category D"},
    {65, "Passenger, Reserved for future use"},
    {66, "Passenger, Reserved for future use"},
    {67, "Passenger, Reserved for future use"},
    {68, "Passenger, Reserved for future use"},
    {69, "Passenger, No additional information"},
    {70, "Cargo, all ships of this type"},
    {71, "Cargo, Hazardous category A"},
    {72, "Cargo, Hazardous category B"},
    {73, "Cargo, Hazardous category C"},
    {74, "Cargo, Hazardous category D"},
    {75, "Cargo, Reserved for future use"},
    {76, "Cargo, Reserved for future use"},
    {77, "Cargo, Reserved for future use"},
    {78, "Cargo, Reserved for future use"},
    {79, "Cargo, No additional information"},
    {80, "Tanker, all ships of this type"},
    {81, "Tanker, Hazardous category A"},
    {82, "Tanker, Hazardous category B"},
    {83, "Tanker, Hazardous category C"},
    {84, "Tanker, Hazardous category D"},
    {85, "Tanker, Reserved for future use"},
    {86, "Tanker, Reserved for future use"},
    {87, "Tanker, Reserved for future use"},
    {88, "Tanker, Reserved for future use"},
    {89, "Tanker, No additional information"},
    {90, "Other Type, all ships of this type"},
    {91, "Other Type, Hazardous category A"},
    {92, "Other Type, Hazardous category B"},
    {93, "Other Type, Hazardous category C"},
    {94, "Other Type, Hazardous category D"},
    {95, "Other Type, Reserved for future use"},
    {96, "Other Type, Reserved for future use"},
    {97, "Other Type, Reserved for future use"},
    {98, "Other Type, Reserved for future use"},
    {99, "Other Type, no additional information"},
    { 0, NULL },
};


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

proto_item *
proto_tree_add_sixbit_string(proto_tree *tree, const int hfindex, tvbuff_t *tvb,
             const guint bit_offset, const gint no_of_bits,
             const guint encoding)
{
    int s = 0;
    for (s = 0; (s < no_of_bits) &&  (bit_offset+s+6) < 8*tvb_captured_length(tvb); s+=6)
    {
        str[s/6] = sixBits[tvb_get_bits(tvb, bit_offset+s, 6, encoding)];
    }
    str[s/6] = 0;
    return proto_tree_add_string(tree, hfindex, tvb, bit_offset/8, (s)/8, str);
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
        proto_tree_add_bits_item(ais_tree, hf_nmea_navstat, tvb, start, 4, ENC_BIG_ENDIAN);
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
        proto_tree_add_bits_item(ais_tree, hf_nmea_hdg, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // heading
        start += 6; // timestamp
        start += 2; // Maneuver Indicator
        start += 3; // Spare
        start += 1; // raim
        start += 19; // radio status
        break;
    case 4:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        proto_tree_add_bits_item(ais_tree, hf_nmea_navstat, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 14; // year
        start += 4; // month
        start += 5; // day
        start += 5; // hour
        start += 6; // minute
        start += 6; // second
        start += 1; // quality
        proto_tree_add_bits_item(ais_tree, hf_nmea_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_nmea_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        start += 4; // EPFS
        start += 10; // spare
        start += 1; // raim
        start += 19;
        break;
     case 5:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        start += 2; // ais version
        proto_tree_add_bits_item(ais_tree, hf_nmea_imo, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // IMO
        proto_tree_add_sixbit_string(ais_tree, hf_nmea_callsign, tvb, start, 42, ENC_BIG_ENDIAN);
        start += 42; // call sign
        proto_tree_add_sixbit_string(ais_tree, hf_nmea_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        proto_tree_add_bits_item(ais_tree, hf_nmea_shptyp, tvb, start, 8, ENC_BIG_ENDIAN);
        start += 8; // ship type
        start += 9; // dimention to bow
        start += 9; // dimention to stern
        start += 6; // dimention to port
        start += 6; // dimention to starboard
        start += 4; // EPFD
        start += 4; // ETA month
        start += 5; // ETA day
        start += 5; // ETA hour
        start += 6; // ETA minute
        start += 8; // Draught
        proto_tree_add_sixbit_string(ais_tree, hf_nmea_dest, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        start += 1; // dte
        start += 1; // spare
        break;
    case 18:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        start += 8; // regional reserve
        proto_tree_add_bits_item(ais_tree, hf_nmea_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_nmea_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_nmea_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_nmea_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        proto_tree_add_bits_item(ais_tree, hf_nmea_hdg, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // heading
        start += 6; // timestamp
        start += 2; // regional reserve
        break;
     case 24:
        start += 2; // repeat indicator
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
        start += 2; // part no
        proto_tree_add_sixbit_string(ais_tree, hf_nmea_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        start += 8; // spare
        start += 18; // vendor id
        start += 4; // unit mode code
        start += 20; // serial number
        proto_tree_add_sixbit_string(ais_tree, hf_nmea_callsign, tvb, start, 42, ENC_BIG_ENDIAN);
        start += 42; // call sign
        start += 9; // dimention to bow
        start += 9; // dimention to stern
        start += 6; // dimention to port
        start += 6; // dimention to starboard
        proto_tree_add_bits_item(ais_tree, hf_nmea_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // MMSI
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
          { &hf_nmea_navstat, { "Navigation Status", "nmea.navstat", FT_UINT32, BASE_DEC, VALS(vals_nav_stat), 0x0, "MMSI", HFILL} },
          { &hf_nmea_rot,     { "Rate of Turn", "nmea.rot", FT_INT32, BASE_CUSTOM, CF_FUNC(I3), 0x0, "Rate of Turn", HFILL} },
          { &hf_nmea_sog,     { "Speed Over Ground", "nmea.sog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Speed Over Ground", HFILL} },
          { &hf_nmea_lon,     { "Longitude", "nmea.lon", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Longitude", HFILL} },
          { &hf_nmea_lat,     { "Lattitude", "nmea.lat", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Latitude", HFILL} },
          { &hf_nmea_cog,     { "Course Over Ground", "nmea.cog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Course Over Ground", HFILL} },
          { &hf_nmea_hdg,     { "True Heading (HDG)", "nmea.hdg", FT_UINT32, BASE_DEC, NULL, 0x0, "True Heading", HFILL} },

          { &hf_nmea_imo,    { "IMO", "nmea.imo", FT_UINT32, BASE_DEC, NULL, 0x0, "IMO", HFILL} },
          { &hf_nmea_callsign, { "Call Sign", "nmea.callsign", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Call Sign", HFILL} },
          { &hf_nmea_name, { "Ship Name", "nmea.shipname", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Ship Name", HFILL} },
          { &hf_nmea_shptyp, { "Ship Type", "nmea.shptyp", FT_UINT32, BASE_DEC, VALS(vals_ship_type), 0x0, "Ship Type", HFILL} },
          { &hf_nmea_dest, { "Destination", "nmea.dest", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Destination", HFILL} },
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

