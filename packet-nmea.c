/*
 * Based on ITU-R-REC-M.1371-5  and https://gpsd.gitlab.io/gpsd/AIVDM.html
 *
 * binary packages are a whole different story (some maintained by coutries
 * some maintained by internation organizations) so I am skipping them
 * for now.
 *
 */

#include "config.h"
#include <stdio.h>

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/expert.h>


void proto_register_nmea(void);
void proto_reg_handoff_nmea(void);

static expert_field ei_nmea_checksum_bad = EI_INIT;


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
static int hf_nmea_checksum = -1;
static int hf_nmea_checksum_status = -1;



static int hf_ais_msgtype = -1;

static int hf_ais_char = -1;

static int hf_ais_mmsi = -1;
static int hf_ais_repeat = -1;

static int hf_ais_mid = -1;
static int hf_ais_navstat = -1;
static int hf_ais_rot = -1;
static int hf_ais_sog = -1;
static int hf_ais_lon = -1;
static int hf_ais_lat = -1;
static int hf_ais_cog = -1;
static int hf_ais_hdg = -1;
static int hf_ais_raim = -1;

static int hf_ais_year = -1;
static int hf_ais_month = -1;
static int hf_ais_day = -1;
static int hf_ais_hour = -1;
static int hf_ais_minute = -1;
static int hf_ais_second = -1;
static int hf_ais_epfd = -1;

static int hf_ais_eta_month = -1;
static int hf_ais_eta_day = -1;
static int hf_ais_eta_hour = -1;
static int hf_ais_eta_minute = -1;


static int hf_ais_imo = -1;
static int hf_ais_callsign = -1;
static int hf_ais_name = -1;
static int hf_ais_shptyp = -1;
static int hf_ais_dest = -1;


static int hf_ais_dim_bow = -1;
static int hf_ais_dim_stern = -1;
static int hf_ais_dim_port = -1;
static int hf_ais_dim_starboard = -1;

static int hf_ais_sync_state = -1;
static int hf_ais_slot_timeout = -1;
static int hf_ais_submessage = -1;
static int hf_ais_slot_offset = -1;
static int hf_ais_recieved_stations = -1;
static int hf_ais_slot_used = -1;
static int hf_ais_slot_increment = -1;
static int hf_ais_slot_reserved = -1;

static int hf_ais_lon1 = -1;
static int hf_ais_lat1 = -1;
static int hf_ais_sog0 = -1;
static int hf_ais_cog0 = -1;

static int hf_ais_int_msgtype = -1;
static int hf_ais_int_mmsi = -1;
static int hf_ais_int_mid = -1;

static int hf_ais_aid_type = -1;


static int hf_ais_altitude = -1;

static int hf_ais_channel_a = -1;
static int hf_ais_channel_b = -1;

static int hf_ais_dac = -1;
static int hf_ais_fid = -1;
static int hf_ais_ai = -1;


static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    &hf_msg_reassembled_data,
    /* Tag */
    "Message fragments"
};

static reassembly_table msg_reassembly_table;

guint8 processed_payload[128];

gchar sixBits[64] = {
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    ' ', '!', '\"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?'};


static char str[1024];


static dissector_handle_t nmea_handle;
static dissector_handle_t ais_handle;

static const value_string vals_msgtype[] = {
    {1, "Position Report Class A"},
    {2, "Position Report Class A (Assigned schedule)"},
    {3, "Position Report Class A (Response to interrogation)"},
    {4, "Base Station Report"},
    {5, "Static and Voyage Related Data"},
    {6, "Binary Addressed Message"},
    {7, "Binary Acknowledge"},
    {8, "Binary Broadcast Message"},
    {9, "Standard SAR Aircraft Position Report"},
    {10, "UTC and Date Inquiry"},
    {11, "UTC and Date Response"},
    {12, "Addressed Safety Related Message"},
    {13, "Safety Related Acknowledgement"},
    {14, "Safety Related Broadcast Message"},
    {15, "Interrogation"},
    {16, "Assignment Mode Command"},
    {17, "DGNSS Binary Broadcast Message"},
    {18, "Standard Class B CS Position Report"},
    {19, "Extended Class B Equipment Position Report"},
    {20, "Data Link Management"},
    {21, "Aid-to-Navigation Report"},
    {22, "Channel Management"},
    {23, "Group Assignment Command"},
    {24, "Static Data Report"},
    {25, "Single Slot Binary Message,"},
    {26, "Multiple Slot Binary Message With Communications State"},
    {27, "Position Report For Long-Range Applications"},
    {0, NULL},
};

// codes come from https://www.itu.int/en/ITU-R/terrestrial/fmd/Pages/mid.aspx
static const value_string vals_mid[] = {
    {0,	"Not defined"},
    {1,	"International Agreement"},
    {2,	"International Agreement"},
    {3,	"International Agreement"},
    {4,	"International Agreement"},
    {5,	"International Agreement"},
    {6,	"International Agreement"},
    {7,	"International Agreement"},
    {8,	"International Agreement"},
    {9,	"International Agreement"},
    {200,	"Inland"},
    {201,	"Albania (Republic of)"},
    {202,	"Andorra (Principality of)"},
    {203,	"Austria"},
    {204,	"Portugal - Azores"},
    {205,	"Belgium"},
    {206,	"Belarus (Republic of)"},
    {207,	"Bulgaria (Republic of)"},
    {208,	"Vatican City State"},
    {209,	"Cyprus (Republic of)"},
    {210,	"Cyprus (Republic of)"},
    {211,	"Germany (Federal Republic of)"},
    {212,	"Cyprus (Republic of)"},
    {213,	"Georgia"},
    {214,	"Moldova (Republic of)"},
    {215,	"Malta"},
    {216,	"Armenia (Republic of)"},
    {218,	"Germany (Federal Republic of)"},
    {219,	"Denmark"},
    {220,	"Denmark"},
    {224,	"Spain"},
    {225,	"Spain"},
    {226,	"France"},
    {227,	"France"},
    {228,	"France"},
    {229,	"Malta"},
    {230,	"Finland"},
    {231,	"Denmark - Faroe Islands"},
    {232,	"United Kingdom of Great Britain and Northern Ireland"},
    {233,	"United Kingdom of Great Britain and Northern Ireland"},
    {234,	"United Kingdom of Great Britain and Northern Ireland"},
    {235,	"United Kingdom of Great Britain and Northern Ireland"},
    {236,	"United Kingdom of Great Britain and Northern Ireland - Gibraltar"},
    {237,	"Greece"},
    {238,	"Croatia (Republic of)"},
    {239,	"Greece"},
    {240,	"Greece"},
    {241,	"Greece"},
    {242,	"Morocco (Kingdom of)"},
    {243,	"Hungary"},
    {244,	"Netherlands (Kingdom of the)"},
    {245,	"Netherlands (Kingdom of the)"},
    {246,	"Netherlands (Kingdom of the)"},
    {247,	"Italy"},
    {248,	"Malta"},
    {249,	"Malta"},
    {250,	"Ireland"},
    {251,	"Iceland"},
    {252,	"Liechtenstein (Principality of)"},
    {253,	"Luxembourg"},
    {254,	"Monaco (Principality of)"},
    {255,	"Portugal - Madeira"},
    {256,	"Malta"},
    {257,	"Norway"},
    {258,	"Norway"},
    {259,	"Norway"},
    {261,	"Poland (Republic of)"},
    {262,	"Montenegro"},
    {263,	"Portugal"},
    {264,	"Romania"},
    {265,	"Sweden"},
    {266,	"Sweden"},
    {267,	"Slovak Republic"},
    {268,	"San Marino (Republic of)"},
    {269,	"Switzerland (Confederation of)"},
    {270,	"Czech Republic"},
    {271,	"Turkey"},
    {272,	"Ukraine"},
    {273,	"Russian Federation"},
    {274,	"North Macedonia (Republic of)"},
    {275,	"Latvia (Republic of)"},
    {276,	"Estonia (Republic of)"},
    {277,	"Lithuania (Republic of)"},
    {278,	"Slovenia (Republic of)"},
    {279,	"Serbia (Republic of)"},
    {301,	"United Kingdom of Great Britain and Northern Ireland - Anguilla"},
    {303,	"United States of America - Alaska (State of)"},
    {304,	"Antigua and Barbuda"},
    {305,	"Antigua and Barbuda"},
    {306,	"Netherlands (Kingdom of the) - Bonaire, Sint Eustatius and Saba"},
    {306,	"Netherlands (Kingdom of the) - Curaçao"},
    {306,	"Netherlands (Kingdom of the) - Sint Maarten (Dutch part)"},
    {307,	"Netherlands (Kingdom of the) - Aruba"},
    {308,	"Bahamas (Commonwealth of the)"},
    {309,	"Bahamas (Commonwealth of the)"},
    {310,	"United Kingdom of Great Britain and Northern Ireland - Bermuda"},
    {311,	"Bahamas (Commonwealth of the)"},
    {312,	"Belize"},
    {314,	"Barbados"},
    {316,	"Canada"},
    {319,	"United Kingdom of Great Britain and Northern Ireland - Cayman Islands"},
    {321,	"Costa Rica"},
    {323,	"Cuba"},
    {325,	"Dominica (Commonwealth of)"},
    {327,	"Dominican Republic"},
    {329,	"France - Guadeloupe (French Department of)"},
    {330,	"Grenada"},
    {331,	"Denmark - Greenland"},
    {332,	"Guatemala (Republic of)"},
    {334,	"Honduras (Republic of)"},
    {336,	"Haiti (Republic of)"},
    {338,	"United States of America"},
    {339,	"Jamaica"},
    {341,	"Saint Kitts and Nevis (Federation of)"},
    {343,	"Saint Lucia"},
    {345,	"Mexico"},
    {347,	"France - Martinique (French Department of)"},
    {348,	"United Kingdom of Great Britain and Northern Ireland - Montserrat"},
    {350,	"Nicaragua"},
    {351,	"Panama (Republic of)"},
    {352,	"Panama (Republic of)"},
    {353,	"Panama (Republic of)"},
    {354,	"Panama (Republic of)"},
    {355,	"Panama (Republic of)"},
    {356,	"Panama (Republic of)"},
    {357,	"Panama (Republic of)"},
    {358,	"United States of America - Puerto Rico"},
    {359,	"El Salvador (Republic of)"},
    {361,	"France - Saint Pierre and Miquelon (Territorial Collectivity of)"},
    {362,	"Trinidad and Tobago"},
    {364,	"United Kingdom of Great Britain and Northern Ireland - Turks and Caicos Islands"},
    {366,	"United States of America"},
    {367,	"United States of America"},
    {368,	"United States of America"},
    {369,	"United States of America"},
    {370,	"Panama (Republic of)"},
    {371,	"Panama (Republic of)"},
    {372,	"Panama (Republic of)"},
    {373,	"Panama (Republic of)"},
    {374,	"Panama (Republic of)"},
    {375,	"Saint Vincent and the Grenadines"},
    {376,	"Saint Vincent and the Grenadines"},
    {377,	"Saint Vincent and the Grenadines"},
    {378,	"United Kingdom of Great Britain and Northern Ireland - British Virgin Islands"},
    {379,	"United States of America - United States Virgin Islands"},
    {401,	"Afghanistan"},
    {403,	"Saudi Arabia (Kingdom of)"},
    {405,	"Bangladesh (People's Republic of)"},
    {408,	"Bahrain (Kingdom of)"},
    {410,	"Bhutan (Kingdom of)"},
    {412,	"China (People's Republic of)"},
    {413,	"China (People's Republic of)"},
    {414,	"China (People's Republic of)"},
    {416,	"China (People's Republic of) - Taiwan (Province of China)"},
    {417,	"Sri Lanka (Democratic Socialist Republic of)"},
    {419,	"India (Republic of)"},
    {422,	"Iran (Islamic Republic of)"},
    {423,	"Azerbaijan (Republic of)"},
    {425,	"Iraq (Republic of)"},
    {428,	"Israel (State of)"},
    {431,	"Japan"},
    {432,	"Japan"},
    {434,	"Turkmenistan"},
    {436,	"Kazakhstan (Republic of)"},
    {437,	"Uzbekistan (Republic of)"},
    {438,	"Jordan (Hashemite Kingdom of)"},
    {440,	"Korea (Republic of)"},
    {441,	"Korea (Republic of)"},
    {443,	"State of Palestine (In accordance with Resolution 99 Rev. Dubai, 2018)"},
    {445,	"Democratic People's Republic of Korea"},
    {447,	"Kuwait (State of)"},
    {450,	"Lebanon"},
    {451,	"Kyrgyz Republic"},
    {453,	"China (People's Republic of) - Macao (Special Administrative Region of China)"},
    {455,	"Maldives (Republic of)"},
    {457,	"Mongolia"},
    {459,	"Nepal (Federal Democratic Republic of)"},
    {461,	"Oman (Sultanate of)"},
    {463,	"Pakistan (Islamic Republic of)"},
    {466,	"Qatar (State of)"},
    {468,	"Syrian Arab Republic"},
    {470,	"United Arab Emirates"},
    {471,	"United Arab Emirates"},
    {472,	"Tajikistan (Republic of)"},
    {473,	"Yemen (Republic of)"},
    {475,	"Yemen (Republic of)"},
    {477,	"China (People's Republic of) - Hong Kong (Special Administrative Region of China)"},
    {478,	"Bosnia and Herzegovina"},
    {501,	"France - Adelie Land"},
    {503,	"Australia"},
    {506,	"Myanmar (Union of)"},
    {508,	"Brunei Darussalam"},
    {510,	"Micronesia (Federated States of)"},
    {511,	"Palau (Republic of)"},
    {512,	"New Zealand"},
    {514,	"Cambodia (Kingdom of)"},
    {515,	"Cambodia (Kingdom of)"},
    {516,	"Australia - Christmas Island (Indian Ocean)"},
    {518,	"New Zealand - Cook Islands"},
    {520,	"Fiji (Republic of)"},
    {523,	"Australia - Cocos (Keeling) Islands"},
    {525,	"Indonesia (Republic of)"},
    {529,	"Kiribati (Republic of)"},
    {531,	"Lao People's Democratic Republic"},
    {533,	"Malaysia"},
    {536,	"United States of America - Northern Mariana Islands (Commonwealth of the)"},
    {538,	"Marshall Islands (Republic of the)"},
    {540,	"France - New Caledonia"},
    {542,	"New Zealand - Niue"},
    {544,	"Nauru (Republic of)"},
    {546,	"France - French Polynesia"},
    {548,	"Philippines (Republic of the)"},
    {550,	"Timor-Leste (Democratic Republic of)"},
    {553,	"Papua New Guinea"},
    {555,	"United Kingdom of Great Britain and Northern Ireland - Pitcairn Island"},
    {557,	"Solomon Islands"},
    {559,	"United States of America - American Samoa"},
    {561,	"Samoa (Independent State of)"},
    {563,	"Singapore (Republic of)"},
    {564,	"Singapore (Republic of)"},
    {565,	"Singapore (Republic of)"},
    {566,	"Singapore (Republic of)"},
    {567,	"Thailand"},
    {570,	"Tonga (Kingdom of)"},
    {572,	"Tuvalu"},
    {574,	"Viet Nam (Socialist Republic of)"},
    {576,	"Vanuatu (Republic of)"},
    {577,	"Vanuatu (Republic of)"},
    {578,	"France - Wallis and Futuna Islands"},
    {601,	"South Africa (Republic of)"},
    {603,	"Angola (Republic of)"},
    {605,	"Algeria (People's Democratic Republic of)"},
    {607,	"France - Saint Paul and Amsterdam Islands"},
    {608,	"United Kingdom of Great Britain and Northern Ireland - Ascension Island"},
    {609,	"Burundi (Republic of)"},
    {610,	"Benin (Republic of)"},
    {611,	"Botswana (Republic of)"},
    {612,	"Central African Republic"},
    {613,	"Cameroon (Republic of)"},
    {615,	"Congo (Republic of the)"},
    {616,	"Comoros (Union of the)"},
    {617,	"Cabo Verde (Republic of)"},
    {618,	"France - Crozet Archipelago"},
    {619,	"Côte d'Ivoire (Republic of)"},
    {620,	"Comoros (Union of the)"},
    {621,	"Djibouti (Republic of)"},
    {622,	"Egypt (Arab Republic of)"},
    {624,	"Ethiopia (Federal Democratic Republic of)"},
    {625,	"Eritrea"},
    {626,	"Gabonese Republic"},
    {627,	"Ghana"},
    {629,	"Gambia (Republic of the)"},
    {630,	"Guinea-Bissau (Republic of)"},
    {631,	"Equatorial Guinea (Republic of)"},
    {632,	"Guinea (Republic of)"},
    {633,	"Burkina Faso"},
    {634,	"Kenya (Republic of)"},
    {635,	"France - Kerguelen Islands"},
    {636,	"Liberia (Republic of)"},
    {637,	"Liberia (Republic of)"},
    {638,	"South Sudan (Republic of)"},
    {642,	"Libya (State of)"},
    {644,	"Lesotho (Kingdom of)"},
    {645,	"Mauritius (Republic of)"},
    {647,	"Madagascar (Republic of)"},
    {649,	"Mali (Republic of)"},
    {650,	"Mozambique (Republic of)"},
    {654,	"Mauritania (Islamic Republic of)"},
    {655,	"Malawi"},
    {656,	"Niger (Republic of the)"},
    {657,	"Nigeria (Federal Republic of)"},
    {659,	"Namibia (Republic of)"},
    {660,	"France - Reunion (French Department of)"},
    {661,	"Rwanda (Republic of)"},
    {662,	"Sudan (Republic of the)"},
    {663,	"Senegal (Republic of)"},
    {664,	"Seychelles (Republic of)"},
    {665,	"United Kingdom of Great Britain and Northern Ireland - Saint Helena"},
    {666,	"Somalia (Federal Republic of)"},
    {667,	"Sierra Leone"},
    {668,	"Sao Tome and Principe (Democratic Republic of)"},
    {669,	"Eswatini (Kingdom of)"},
    {670,	"Chad (Republic of)"},
    {671,	"Togolese Republic"},
    {672,	"Tunisia"},
    {674,	"Tanzania (United Republic of)"},
    {675,	"Uganda (Republic of)"},
    {676,	"Democratic Republic of the Congo"},
    {677,	"Tanzania (United Republic of)"},
    {678,	"Zambia (Republic of)"},
    {679,	"Zimbabwe (Republic of)"},
    {701,	"Argentine Republic"},
    {710,	"Brazil (Federative Republic of)"},
    {720,	"Bolivia (Plurinational State of)"},
    {725,	"Chile"},
    {730,	"Colombia (Republic of)"},
    {735,	"Ecuador"},
    {740,	"United Kingdom of Great Britain and Northern Ireland - Falkland Islands (Malvinas)"},
    {745,	"France - Guiana (French Department of)"},
    {750,	"Guyana"},
    {755,	"Paraguay (Republic of)"},
    {760,	"Peru"},
    {765,	"Suriname (Republic of)"},
    {770,	"Uruguay (Eastern Republic of)"},
    {775,	"Venezuela (Bolivarian Republic of)"},
    { 0, NULL },
};

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

static const value_string vals_char[] = {
    {0, "@"},
    {1, "A"},
    {2, "B"},
    {3, "C"},
    {4, "D"},
    {5, "E"},
    {6, "F"},
    {7, "G"},
    {8, "H"},
    {9, "I"},
    {10, "J"},
    {11, "K"},
    {12, "L"},
    {13, "M"},
    {14, "N"},
    {15, "O"},
    {16, "P"},
    {17, "Q"},
    {18, "R"},
    {19, "S"},
    {20, "T"},
    {21, "U"},
    {22, "V"},
    {23, "W"},
    {24, "X"},
    {25, "Y"},
    {26, "Z"},
    {27, "["},
    {28, "\\"},
    {29, "]"},
    {30, "^"},
    {31, "_"},
    {32, " "},
    {33, "!"},
    {34, "\""},
    {35, "#"},
    {36, "$"},
    {37, "%"},
    {38, "&"},
    {39, "\'"},
    {40, "("},
    {41, ")"},
    {42, "*"},
    {43, "+"},
    {44, ","},
    {45, "-"},
    {46, "."},
    {47, "/"},
    {48, "0"},
    {49, "1"},
    {50, "2"},
    {51, "3"},
    {52, "4"},
    {53, "5"},
    {54, "6"},
    {55, "7"},
    {56, "8"},
    {56, "9"},
    {58, ":"},
    {59, ";"},
    {60, "<"},
    {61, "="},
    {62, ">"},
    {63, "?"},
    {0, NULL},
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

static const value_string vals_epfd[] = {
    {0, "Undefined (default)"},
    {1, "GPS"},
    {2, "GLONASS"},
    {3, "Combined GPS/GLONASS"},
    {4, "Loran-C"},
    {5, "Chayka"},
    {6, "Integrated navigation system"},
    {7, "Surveyed"},
    {8, "Galileo"},
    { 0, NULL },
};

static const value_string vals_sync_mode[] = {
    {0, "UTC direct"},
    {1, "UTC indirect"},
    {2, "Base direct"},
    {3, "Base indirect/Mobile as semaphore"},
    { 0, NULL },
};

static const value_string vals_aid_type[] = {
    {0, "Default, Type of Aid to Navigation not specified"},
    {1, "Reference point"},
    {2, "RACON (radar transponder marking a navigation hazard)"},
    {3, "Fixed structure off shore, such as oil platforms, wind farms, rigs. (Note: This code should identify an obstruction that is fitted with an Aid-to-Navigation AIS station.)"},
    {4, "Spare, Reserved for future use."},
    {5, "Light, without sectors"},
    {6, "Light, with sectors"},
    {7, "Leading Light Front"},
    {8, "Leading Light Rear"},
    {9, "Beacon, Cardinal N"},
    {10, "Beacon, Cardinal E"},
    {11, "Beacon, Cardinal S"},
    {12, "Beacon, Cardinal W"},
    {13, "Beacon, Port hand"},
    {14, "Beacon, Starboard hand"},
    {15, "Beacon, Preferred Channel port hand"},
    {16, "Beacon, Preferred Channel starboard hand"},
    {17, "Beacon, Isolated danger"},
    {18, "Beacon, Safe water"},
    {19, "Beacon, Special mark"},
    {20, "Cardinal Mark N"},
    {21, "Cardinal Mark E"},
    {22, "Cardinal Mark S"},
    {23, "Cardinal Mark W"},
    {24, "Port hand Mark"},
    {25, "Starboard hand Mark"},
    {26, "Preferred Channel Port hand"},
    {27, "Preferred Channel Starboard hand"},
    {28, "Isolated danger"},
    {29, "Safe Water"},
    {30, "Special Mark"},
    {31, "Light Vessel / LANBY / Rigs"},
    {0, NULL},
};

// only international messages added
static const value_string vals_ai[] = {
    {(1 << 6) | 0, "Text Telegram"},
    {(1 << 6) | 1, "Application acknowledgement"},
    {(1 << 6) | 2, "Interrogation on specific IFM"},
    {(1 << 6) | 3, "Capability interrogation"},
    {(1 << 6) | 4, "Capability interrogation reply"},
    {(1 << 6) | 5, "Application acknowledgement to an addressed binary message"},
    {(1 << 6) | 11, "Meteorological and Hydrological Data"},
    {(1 << 6) | 12, "Dangerous cargo indication"},
    {(1 << 6) | 13, "Fairway Closed"},
    {(1 << 6) | 14, "Tidal window"},
    {(1 << 6) | 15, "Extended Ship Static and Voyage Related Data"},
    {(1 << 6) | 16, "Number of persons on board"},
    {(1 << 6) | 17, "VTS-Generated/Synthetic targets"},
    {(1 << 6) | 18, "Clearance time to enter port"},
    {(1 << 6) | 19, "Marine Traffic Signal"},
    {(1 << 6) | 20, "Berthing data (addressed)"},
    {(1 << 6) | 21, "Weather observation report from ship"},
    {(1 << 6) | 22, "Area Notice (broadcast)"},
    {(1 << 6) | 23, "Area notice (addressed)"},
    {(1 << 6) | 24, "Extended Ship Static and Voyage Related Data"},
    {(1 << 6) | 25, "Dangerous Cargo indication"},
    {(1 << 6) | 26, "Environmental"},
    {(1 << 6) | 27, "Route Information (broadcast)"},
    {(1 << 6) | 28, "Route info addressed"},
    {(1 << 6) | 29, "Text description (broadcast)"},
    {(1 << 6) | 30, "Text description addressed"},
    {(1 << 6) | 31, "Meteorological and Hydrological Data"},
    {(1 << 6) | 32, "Tidal Window"},
    {(1 << 6) | 40, "Number of Persons on board"},
    {(200 << 6) | 10, "Inland ship static and voyage related data"},
    {(200 << 6) | 21, "ETA at lock/bridge/terminal"},
    {(200 << 6) | 22, "RTA at lock/bridge/terminal"},
    {(200 << 6) | 23, "EMMA Warning Report"},
    {(200 << 6) | 24, "Water Levels"},
    {(200 << 6) | 40, "Signal Strength"},
    {(200 << 6) | 55, "Number of persons on board"},
    {0, NULL},
};

static void
I3(gchar *buf, gint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%.03f", value / 1000.);
}

static void
I4deg(gchar *buf, gint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%.06f", value / 600000.);
}

static void
I1deg(gchar *buf, gint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%.03f", value / 600.);
}

static void
U1(gchar *buf, guint32 value) {
        g_snprintf(buf, ITEM_LABEL_LENGTH, "%.01f", value / 10.);
}

guint16 xor_checksum(tvbuff_t *tvb, guint len)
{
    guint8 chsm = 0;

    tvb_ensure_bytes_exist(tvb, 0, len);  /* len == -1 not allowed */
    for (guint i =0; i<len; i++)
        chsm ^= tvb_get_guint8(tvb, i);
    gint8 out[3];
    sprintf(out, "%02X", chsm);

   return (out[0]<<8) | out[1];
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
        // this is for debugging purposes
        //proto_tree_add_bits_item(tree, hf_ais_char, tvb, bit_offset+s, 6, encoding);
    }
    str[s/6] = 0;
    return proto_tree_add_string(tree, hfindex, tvb, bit_offset/8, (bit_offset+s+7)/8-bit_offset/8, str);
}

static guint getmid(guint mmsi)
{
    switch(mmsi/1000000)
    {
//    111MIDXXX SAR (Search and Rescue) aircraft
//    970MIDXXX AIS SART (Search and Rescue Transmitter)
    case 111: case 970:
        return (mmsi / 1000) % 1000;
        break;
//    972XXXXXX MOB (Man Overboard) device
//    974XXXXXX EPIRB (Emergency Position Indicating Radio Beacon) AIS
    case 972: case 974:
        return 0;
    }
    switch(mmsi/10000000)
    {
    //    00MIDXXXX Coastal stations
    //    98MIDXXXX Auxiliary craft associated with a parent ship
    //    99MIDXXXX Aids to Navigation
    case 0: case 98: case 99:
        return (mmsi/10000) % 1000;
        break;
    }
    switch(mmsi/100000000)
    {
    //    0MIDXXXXX Group of ships; the U.S. Coast Guard, for example, is 03699999
    //    8MIDXXXXX Diver’s radio (not used in the U.S. in 2013)
    case 0: case 8:
        return (mmsi/100000) % 1000;
        break;
    }
//    MIDXXXXXX Ship
    return mmsi / 1000000;

}

static int parse_SOTDMA(tvbuff_t *tvb, proto_tree *ais_tree, int start)
{
    proto_tree_add_bits_item(ais_tree, hf_ais_sync_state, tvb, start, 2, ENC_BIG_ENDIAN);
    start += 2; // sync state
    proto_tree_add_bits_item(ais_tree, hf_ais_slot_timeout, tvb, start, 3, ENC_BIG_ENDIAN);
    int timeslot = tvb_get_bits(tvb, start, 3, ENC_BIG_ENDIAN);
    start += 3; // timeslot
    if (timeslot == 3 || timeslot == 5 || timeslot == 7)
    {
        proto_tree_add_bits_item(ais_tree, hf_ais_recieved_stations, tvb, start, 14, ENC_BIG_ENDIAN);
        start += 14; // recieved stations
    }
    if (timeslot == 2 || timeslot == 4 || timeslot == 6)
    {
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_used, tvb, start, 14, ENC_BIG_ENDIAN);
        start += 14; // slot numbers used for this transmission
    }
    if (timeslot == 1)
    {
        proto_tree_add_bits_item(ais_tree, hf_ais_hour, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // UTC hour
        proto_tree_add_bits_item(ais_tree, hf_ais_minute, tvb, start, 7, ENC_BIG_ENDIAN);
        start += 7; // UTC minute
        start += 2; // not used
    }
    if (timeslot == 0)
    {
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 14, ENC_BIG_ENDIAN);
        start += 14; // slot offset
    }
    return start;
}

static int parse_ITDMA(tvbuff_t *tvb, proto_tree *ais_tree, int start)
{

    proto_tree_add_bits_item(ais_tree, hf_ais_sync_state, tvb, start, 2, ENC_BIG_ENDIAN);
    start += 2; // sync state
    proto_tree_add_bits_item(ais_tree, hf_ais_slot_increment, tvb, start, 13, ENC_BIG_ENDIAN);
    start += 13; // slot increment
    proto_tree_add_bits_item(ais_tree, hf_ais_slot_reserved, tvb, start, 3, ENC_BIG_ENDIAN);
    start += 3; // number of slots to allocate
    start += 1; // keep flag
    return start;
}

static int
dissect_ais(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    gboolean itdma = FALSE;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AIS");
    col_set_str(pinfo->cinfo, COL_INFO, "AIS packet data");

    proto_tree *ais_tree;
    proto_item *ais_item;
    ais_item = proto_tree_add_item(tree, proto_ais, tvb, 0, -1, ENC_NA);
    ais_tree = proto_item_add_subtree(ais_item, ett_ais);



    guint start = 0;
    guint msgtype = tvb_get_bits(tvb, 0, 6, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(ais_tree, hf_ais_msgtype, tvb, start, 6, ENC_BIG_ENDIAN);
    start += 6;
    proto_tree_add_bits_item(ais_tree, hf_ais_repeat, tvb, start, 2, ENC_BIG_ENDIAN);
    start += 2; // repeat indicator
    proto_tree_add_bits_item(ais_tree, hf_ais_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
    guint mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
    proto_tree_add_uint(ais_tree, hf_ais_mid, tvb, start/8, 4, getmid(mmsi));
    start += 30; // MMSI

    switch (msgtype) {
    case 1: case 2: case 3:
        proto_tree_add_bits_item(ais_tree, hf_ais_navstat, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // navigation status
        proto_tree_add_bits_item(ais_tree, hf_ais_rot, tvb, start, 8, ENC_BIG_ENDIAN);
        start += 8; // Rate of Turn
        proto_tree_add_bits_item(ais_tree, hf_ais_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        proto_tree_add_bits_item(ais_tree, hf_ais_hdg, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // heading
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // timestamp
        start += 2; // Maneuver Indicator
        start += 3; // Spare
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        if (msgtype == 1 || msgtype == 2) // SOTDMA
        {
            start = parse_SOTDMA(tvb, ais_tree, start);
        }
        if (msgtype == 3) // ITDMA
        {
            start = parse_ITDMA(tvb, ais_tree, start);
        }
        break;
    case 4:
        proto_tree_add_bits_item(ais_tree, hf_ais_year, tvb, start, 14, ENC_BIG_ENDIAN);
        start += 14; // year
        proto_tree_add_bits_item(ais_tree, hf_ais_month, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // month
        proto_tree_add_bits_item(ais_tree, hf_ais_day, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // day
        proto_tree_add_bits_item(ais_tree, hf_ais_hour, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // hour
        proto_tree_add_bits_item(ais_tree, hf_ais_minute, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // minute
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // second
        start += 1; // quality
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_epfd, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // EPFD
        start += 10; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        start = parse_SOTDMA(tvb, ais_tree, start);
        break;
     case 5:
        start += 2; // ais version
        proto_tree_add_bits_item(ais_tree, hf_ais_imo, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // IMO
        proto_tree_add_sixbit_string(ais_tree, hf_ais_callsign, tvb, start, 42, ENC_BIG_ENDIAN);
        start += 42; // call sign
        proto_tree_add_sixbit_string(ais_tree, hf_ais_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        proto_tree_add_bits_item(ais_tree, hf_ais_shptyp, tvb, start, 8, ENC_BIG_ENDIAN);
        start += 8; // ship type
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_bow, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to bow
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_stern, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to stern
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_port, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to port
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_starboard, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to starboard
        proto_tree_add_bits_item(ais_tree, hf_ais_epfd, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // EPFD
        proto_tree_add_bits_item(ais_tree, hf_ais_eta_month, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // ETA month
        proto_tree_add_bits_item(ais_tree, hf_ais_eta_day, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // ETA day
        proto_tree_add_bits_item(ais_tree, hf_ais_eta_hour, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // ETA hour
        proto_tree_add_bits_item(ais_tree, hf_ais_eta_minute, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // ETA minute
        start += 8; // Draught
        proto_tree_add_sixbit_string(ais_tree, hf_ais_dest, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        start += 1; // dte
        start += 1; // spare
        break;
    case 6:
        start += 2; // seqno
        proto_tree_add_bits_item(ais_tree, hf_ais_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        start += 1; // retransmit flag
        start += 1; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_ai, tvb, start, 16, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(ais_tree, hf_ais_dac, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // DAC
        proto_tree_add_bits_item(ais_tree, hf_ais_fid, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // FID

        break;
    case 8:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_ai, tvb, start, 16, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(ais_tree, hf_ais_dac, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // DAC
        proto_tree_add_bits_item(ais_tree, hf_ais_fid, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // FID
        break;
    case 9:
        proto_tree_add_bits_item(ais_tree, hf_ais_altitude, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12;
        proto_tree_add_bits_item(ais_tree, hf_ais_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // timestamp
        start += 8; // regional reserve
        start += 1; // DTE
        start += 3; // spare
        start += 1; // assigned mode flag
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        itdma = tvb_get_bits(tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // ITDMA flag
        if (itdma)
        {
            start = parse_ITDMA(tvb, ais_tree, start);
        }
        else
        {
            start = parse_SOTDMA(tvb, ais_tree, start);
        }
        break;
    case 10:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_int_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_int_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        start += 2; // spare
        break;
    case 11:
        proto_tree_add_bits_item(ais_tree, hf_ais_year, tvb, start, 14, ENC_BIG_ENDIAN);
        start += 14; // year
        proto_tree_add_bits_item(ais_tree, hf_ais_month, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // month
        proto_tree_add_bits_item(ais_tree, hf_ais_day, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // day
        proto_tree_add_bits_item(ais_tree, hf_ais_hour, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // hour
        proto_tree_add_bits_item(ais_tree, hf_ais_minute, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // minute
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // second
        start += 1; // quality
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_epfd, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // EPFD
        start += 10; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        start = parse_SOTDMA(tvb, ais_tree, start);
        break;
    case 15:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_int_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_int_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        proto_tree_add_bits_item(ais_tree, hf_ais_int_msgtype, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6;
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_int_msgtype, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6;
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_int_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_int_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        proto_tree_add_bits_item(ais_tree, hf_ais_int_msgtype, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6;
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        start += 2; // spare

        break;
    case 17:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_lon1, tvb, start, 18, ENC_BIG_ENDIAN);
        start += 18; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat1, tvb, start, 17, ENC_BIG_ENDIAN);
        start += 17; // lat
        start += 5; // spare
        // rest is DGNSS
        break;
    case 18:
        start += 8; // regional reserve
        proto_tree_add_bits_item(ais_tree, hf_ais_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        proto_tree_add_bits_item(ais_tree, hf_ais_hdg, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // heading
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // timestamp
        start += 2; // regional reserve
        start += 1; // CS unit
        start += 1; // display flag
        start += 1; // DSC flag
        start += 1; // band flag
        start += 1; // msg22 flag
        start += 1; // assigned
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim flag
        itdma = tvb_get_bits(tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // ITDMA flag
        if (itdma)
        {
            start = parse_ITDMA(tvb, ais_tree, start);
        }
        else
        {
            start = parse_SOTDMA(tvb, ais_tree, start);
        }
        break;
     case 19:
        start += 8; // Regional Reserve
        proto_tree_add_bits_item(ais_tree, hf_ais_sog, tvb, start, 10, ENC_BIG_ENDIAN);
        start += 10; // speed over ground
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_cog, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // course over ground
        proto_tree_add_bits_item(ais_tree, hf_ais_hdg, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // heading
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // timestamp
        start += 4; // Regional reserve
        proto_tree_add_sixbit_string(ais_tree, hf_ais_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        proto_tree_add_bits_item(ais_tree, hf_ais_shptyp, tvb, start, 8, ENC_BIG_ENDIAN);
        start += 8; // ship type
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_bow, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to bow
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_stern, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to stern
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_port, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to port
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_starboard, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to starboard
        proto_tree_add_bits_item(ais_tree, hf_ais_epfd, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // EPFD
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        start += 1; // DTE
        start += 1; // assigned mode flag
        start += 4; // spare
        break;
     case 20:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_reserved, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // slots reserved
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_timeout, tvb, start, 3, ENC_BIG_ENDIAN);
        start += 3; // slot timeout
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_increment, tvb, start, 11, ENC_BIG_ENDIAN);
        start += 11; // slot increment
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_reserved, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // slots reserved
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_timeout, tvb, start, 3, ENC_BIG_ENDIAN);
        start += 3; // slot timeout
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_increment, tvb, start, 11, ENC_BIG_ENDIAN);
        start += 11; // slot increment
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_reserved, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // slots reserved
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_timeout, tvb, start, 3, ENC_BIG_ENDIAN);
        start += 3; // slot timeout
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_increment, tvb, start, 11, ENC_BIG_ENDIAN);
        start += 11; // slot increment
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_offset, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // slot offset
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_reserved, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // slots reserved
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_timeout, tvb, start, 3, ENC_BIG_ENDIAN);
        start += 3; // slot timeout
        proto_tree_add_bits_item(ais_tree, hf_ais_slot_increment, tvb, start, 11, ENC_BIG_ENDIAN);
        start += 11; // slot increment
        break;
     case 21:
        proto_tree_add_bits_item(ais_tree, hf_ais_aid_type, tvb, start, 5, ENC_BIG_ENDIAN);
        start += 5; // aid type
        proto_tree_add_sixbit_string(ais_tree, hf_ais_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // name
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_lon, tvb, start, 28, ENC_BIG_ENDIAN);
        start += 28; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat, tvb, start, 27, ENC_BIG_ENDIAN);
        start += 27; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_bow, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to bow
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_stern, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to stern
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_port, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to port
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_starboard, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to starboard
        proto_tree_add_bits_item(ais_tree, hf_ais_epfd, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // EPFD
        proto_tree_add_bits_item(ais_tree, hf_ais_second, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // second
        start += 1; // off indicator
        start += 8; // regional reserve
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        start += 1; // virtual aid flag
        start += 1; // assigned mode flag
        start += 1; // spare
        proto_tree_add_sixbit_string(ais_tree, hf_ais_name, tvb, start, 88, ENC_BIG_ENDIAN);
        start += 88; // name extension
        break;
     case 22:
        start += 2; // spare
        proto_tree_add_bits_item(ais_tree, hf_ais_channel_a, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // channel a
        proto_tree_add_bits_item(ais_tree, hf_ais_channel_b, tvb, start, 12, ENC_BIG_ENDIAN);
        start += 12; // channel b
        start += 4; // txrx mode
        start += 1; // power
        proto_tree_add_bits_item(ais_tree, hf_ais_lon1, tvb, start, 18, ENC_BIG_ENDIAN);
        start += 18; // long NE
        proto_tree_add_bits_item(ais_tree, hf_ais_lat1, tvb, start, 17, ENC_BIG_ENDIAN);
        start += 17; // lat NE
        proto_tree_add_bits_item(ais_tree, hf_ais_lon1, tvb, start, 18, ENC_BIG_ENDIAN);
        start += 18; // long SW
        proto_tree_add_bits_item(ais_tree, hf_ais_lat1, tvb, start, 17, ENC_BIG_ENDIAN);
        start += 17; // lat SW
        proto_tree_add_bits_item(ais_tree, hf_ais_int_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_int_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        proto_tree_add_bits_item(ais_tree, hf_ais_int_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        mmsi = tvb_get_bits(tvb, start, 30, ENC_BIG_ENDIAN);
        proto_tree_add_uint(ais_tree, hf_ais_int_mid, tvb, start/8, 4, getmid(mmsi));
        start += 30; // MMSI
        start += 1; // addressed
        start += 1; // channel a band
        start += 1; // channel b band
        start += 3; // zone site
        start += 23; // spare

        break;
     case 24:
        start += 2; // part no
        proto_tree_add_sixbit_string(ais_tree, hf_ais_name, tvb, start, 120, ENC_BIG_ENDIAN);
        start += 120; // shipname
        start += 8; // spare
        start += 18; // vendor id
        start += 4; // unit mode code
        start += 20; // serial number
        proto_tree_add_sixbit_string(ais_tree, hf_ais_callsign, tvb, start, 42, ENC_BIG_ENDIAN);
        start += 42; // call sign
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_bow, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to bow
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_stern, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // dimention to stern
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_port, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to port
        proto_tree_add_bits_item(ais_tree, hf_ais_dim_starboard, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // dimention to starboard
        proto_tree_add_bits_item(ais_tree, hf_ais_mmsi, tvb, start, 30, ENC_BIG_ENDIAN);
        start += 30; // mother MMSI
        break;
    case 27:
        start += 1; // position accuracy
        proto_tree_add_bits_item(ais_tree, hf_ais_raim, tvb, start, 1, ENC_BIG_ENDIAN);
        start += 1; // raim
        proto_tree_add_bits_item(ais_tree, hf_ais_navstat, tvb, start, 4, ENC_BIG_ENDIAN);
        start += 4; // navigation status
        proto_tree_add_bits_item(ais_tree, hf_ais_lon1, tvb, start, 18, ENC_BIG_ENDIAN);
        start += 18; // long
        proto_tree_add_bits_item(ais_tree, hf_ais_lat1, tvb, start, 17, ENC_BIG_ENDIAN);
        start += 17; // lat
        proto_tree_add_bits_item(ais_tree, hf_ais_sog0, tvb, start, 6, ENC_BIG_ENDIAN);
        start += 6; // speed over ground
        proto_tree_add_bits_item(ais_tree, hf_ais_cog0, tvb, start, 9, ENC_BIG_ENDIAN);
        start += 9; // course over ground
        start += 1; // GNSS
        start += 1; // Spare

        break;

    }

    return tvb_captured_length(tvb);
}


static int process_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    if (tvb_captured_length(tvb) == 0)
        return 0;

    guint c = 0, inpFlag = 0, outFlag = 0, outPointer = -1;
;

    for (guint t = 0; t < tvb_captured_length(tvb); t+=1)
    {
        c = tvb_get_guint8(tvb, t)-48;
        if (c>=48)
            c -= 8;
        inpFlag = 0x20;

        while (inpFlag)
        {
            if (outFlag)
            {
                if (c & inpFlag)
                    processed_payload[outPointer] |= outFlag;
                outFlag >>= 1;
                inpFlag >>= 1;
            }
            else
            {
                // going to next byte
                outPointer++;
                processed_payload[outPointer] = 0;
                outFlag = 0x80;
            }
        }
    }

    tvbuff_t *payload = tvb_new_child_real_data(tvb, processed_payload, outPointer+1, outPointer+1);
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
  int offset_start = 0, offset_end = 0;
  tvbuff_t * comma = tvb_new_real_data(",", 1, 1);

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_identifier, tvb, offset_start, offset_end-offset_start, ENC_ASCII);
  offset_start = offset_end+1;

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_fragments, tvb, offset_start, offset_end-offset_start, ENC_ASCII);
  int fragments = tvb_get_guint8(tvb, offset_start) - '0';
  offset_start = offset_end+1;

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_fragno, tvb, offset_start, offset_end-offset_start, ENC_ASCII);
  int fragmentno = tvb_get_guint8(tvb, offset_start) - '0';
  offset_start = offset_end+1;

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_seqid, tvb, offset_start, offset_end-offset_start, ENC_ASCII);
  int seqid = tvb_get_guint8(tvb, offset_start) - '0';
  offset_start = offset_end+1;

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_channel, tvb, offset_start, offset_end-offset_start, ENC_ASCII);
  offset_start = offset_end+1;

  offset_end = tvb_find_tvb(tvb, comma, offset_start);
  proto_tree_add_item(nmea_tree, hf_nmea_payload, tvb, offset_start, offset_end-offset_start, ENC_NA);

  proto_tree_add_checksum(nmea_tree, tvb, offset_end+3, hf_nmea_checksum, hf_nmea_checksum_status, &ei_nmea_checksum_bad, pinfo,
                          xor_checksum(tvb_new_subset_remaining(tvb, 1), offset_end+1), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

  if (fragments == 1)
  {
      process_payload(tvb_new_subset_length(tvb, offset_start, offset_end-offset_start), pinfo, tree, NULL);
  }
  else
  {
      gboolean save_fragmented = pinfo->fragmented;
      tvbuff_t* new_tvb = NULL;
      fragment_head *frag_msg = NULL;
      pinfo->fragmented = TRUE;
      frag_msg = fragment_add_seq_check(&msg_reassembly_table,
          tvb, offset_start, pinfo,
          seqid, NULL, /* ID for fragments belonging together */
          fragmentno-1, /* fragment sequence number */
          offset_end-offset_start, /* fragment length - to the end */
          !(fragmentno == fragments)); /* More fragments? */

      new_tvb = process_reassembled_data(tvb, offset_start, pinfo,
              "Reassembled Message", frag_msg, &msg_frag_items,
              NULL, nmea_tree);
      if (new_tvb)
      {
          process_payload(new_tvb, pinfo, tree, NULL);
      }
      pinfo->fragmented = save_fragmented;
  }


  offset_start = offset_end+1;

  return tvb_captured_length(tvb);
}

void
proto_register_nmea(void)
{

  reassembly_table_register(&msg_reassembly_table, &addresses_ports_reassembly_table_functions);

  static gint *ett[] = {
    &ett_nmea,
    &ett_msg_fragment,
    &ett_msg_fragments,
  };

  static hf_register_info hf_nmea[] =
      {
          { &hf_nmea_identifier, { "Identifier", "nmea.id", FT_STRING, STR_ASCII, NULL, 0x0, "Sender Identifier", HFILL} },
          { &hf_nmea_fragments, { "Fragments", "nmea.fragments", FT_STRING, STR_ASCII, NULL, 0x0, "Count of Fragments", HFILL} },
          { &hf_nmea_fragno, { "Fragment No", "nmea.fragno", FT_STRING, STR_ASCII, NULL, 0x0, "Fragment No", HFILL} },
          { &hf_nmea_seqid, { "Seq Id", "nmea.seqid", FT_STRING, STR_ASCII, NULL, 0x0, "Sequence Id", HFILL} },
          { &hf_nmea_channel, { "Channel", "nmea.chn", FT_STRING, STR_ASCII, NULL, 0x0, "Channel", HFILL} },
          { &hf_nmea_payload, { "Payload", "nmea.payload", FT_STRING, STR_ASCII, NULL, 0x0, "Payload", HFILL} },

          { &hf_nmea_checksum,{ "Checksum", "lapd.checksum", FT_UINT16, BASE_HEX, NULL, 0x0, "Details at: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvChecksums.html", HFILL }},
          { &hf_nmea_checksum_status,{ "Checksum Status", "lapd.checksum.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},


          {&hf_msg_fragments,    {"Message fragments", "msg.fragments",    FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment,    {"Message fragment", "msg.fragment",    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_overlap,    {"Message fragment overlap", "msg.fragment.overlap",    FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_overlap_conflicts,    {"Message fragment overlapping with conflicting data",    "msg.fragment.overlap.conflicts",    FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_multiple_tails,    {"Message has multiple tail fragments",    "msg.fragment.multiple_tails",    FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_too_long_fragment,    {"Message fragment too long", "msg.fragment.too_long_fragment",    FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_error,    {"Message defragmentation error", "msg.fragment.error",    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_fragment_count,    {"Message fragment count", "msg.fragment.count",    FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_reassembled_in,    {"Reassembled in", "msg.reassembled.in",    FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_reassembled_length,    {"Reassembled length", "msg.reassembled.length",    FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
          {&hf_msg_reassembled_data,    {"Reassembled data", "msg.reassembled.data",    FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL } },
    };
  proto_nmea = proto_register_protocol("nmea packet data", "NMEA", "nmea");
  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_nmea, hf_nmea, array_length(hf_nmea));

  nmea_handle = register_dissector("nmea_udp", dissect_nmea, proto_nmea);

  static gint *ettais[] = {
    &ett_ais,
  };

  static ei_register_info ei[] = {
      { &ei_nmea_checksum_bad, { "nmea.checksum_bad.expert", PI_CHECKSUM, PI_WARN, "Bad FCS", EXPFILL }},
  };

  expert_module_t* expert_nmea;

  expert_nmea = expert_register_protocol(proto_nmea);
  expert_register_field_array(expert_nmea, ei, array_length(ei));


  static hf_register_info hf_ais[] =
      {
          { &hf_ais_char, { "sixbit char", "ais.char", FT_UINT8, BASE_HEX, VALS(vals_char), 0x0, "Char", HFILL} },

          { &hf_ais_msgtype, { "Message Type", "ais.msgtype", FT_UINT8, BASE_DEC, VALS(vals_msgtype), 0x0, "Message Type", HFILL} },
          { &hf_ais_mmsi,    { "MMSI", "ais.mmsi", FT_UINT32, BASE_DEC, NULL, 0x0, "MMSI", HFILL} },
          { &hf_ais_repeat,  { "Repeat Indicator", "ais.repeat", FT_UINT32, BASE_DEC, NULL, 0x0, "Repeat Indicator", HFILL} },
          { &hf_ais_mid,     { "MID", "ais.mid", FT_UINT32, BASE_DEC, VALS(vals_mid), 0x0, "MID", HFILL} },
          { &hf_ais_navstat, { "Navigation Status", "ais.navstat", FT_UINT32, BASE_DEC, VALS(vals_nav_stat), 0x0, "MMSI", HFILL} },
          { &hf_ais_rot,     { "Rate of Turn", "ais.rot", FT_INT32, BASE_CUSTOM, CF_FUNC(I3), 0x0, "Rate of Turn", HFILL} },
          { &hf_ais_sog,     { "Speed Over Ground", "ais.sog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Speed Over Ground", HFILL} },
          { &hf_ais_lon,     { "Longitude", "ais.lon", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Longitude", HFILL} },
          { &hf_ais_lat,     { "Lattitude", "ais.lat", FT_INT32, BASE_CUSTOM, CF_FUNC(I4deg), 0x0, "Latitude", HFILL} },
          { &hf_ais_cog,     { "Course Over Ground", "ais.cog", FT_UINT32, BASE_CUSTOM, CF_FUNC(U1), 0x0, "Course Over Ground", HFILL} },
          { &hf_ais_hdg,     { "True Heading (HDG)", "ais.hdg", FT_UINT32, BASE_DEC, NULL, 0x0, "True Heading", HFILL} },
          { &hf_ais_raim,    { "RAIM Flag", "ais.raim", FT_UINT32, BASE_DEC, NULL, 0x0, "RAIM Flag", HFILL} },

          { &hf_ais_sync_state,        { "Syncronization State", "ais.sync", FT_UINT32, BASE_DEC, VALS(vals_sync_mode), 0x0, "Syncronization State", HFILL} },
          { &hf_ais_slot_timeout,      { "Slot timeout", "ais.slottimeout", FT_UINT32, BASE_DEC, NULL, 0x0, "Slot timeout", HFILL} },
          { &hf_ais_submessage,        { "Sub Message", "ais.submes", FT_UINT32, BASE_DEC, NULL, 0x0, "Sub Message", HFILL} },
          { &hf_ais_slot_offset,       { "Slot Offset", "ais.slotoffset", FT_UINT32, BASE_DEC, NULL, 0x0, "Slot Offset", HFILL} },
          { &hf_ais_recieved_stations, { "Recieved Stations", "ais.recstations", FT_UINT32, BASE_DEC, NULL, 0x0, "Recieved Stations", HFILL} },
          { &hf_ais_slot_used,         { "Slot Used", "ais.slotused", FT_UINT32, BASE_DEC, NULL, 0x0, "Slot Used", HFILL} },
          { &hf_ais_slot_increment,    { "Slot Increment", "ais.slotinc", FT_UINT32, BASE_DEC, NULL, 0x0, "Slot Increment", HFILL} },
          { &hf_ais_slot_reserved,     { "Slots Reserved", "ais.slotres", FT_UINT32, BASE_DEC, NULL, 0x0, "Slots Reserved", HFILL} },


          { &hf_ais_year,    { "Year", "ais.year", FT_UINT32, BASE_DEC, NULL, 0x0, "Year", HFILL} },
          { &hf_ais_month,   { "Month", "ais.month", FT_UINT32, BASE_DEC, NULL, 0x0, "Month", HFILL} },
          { &hf_ais_day,     { "Day", "ais.day", FT_UINT32, BASE_DEC, NULL, 0x0, "Day", HFILL} },
          { &hf_ais_hour,    { "Hour", "ais.hour", FT_UINT32, BASE_DEC, NULL, 0x0, "Hour", HFILL} },
          { &hf_ais_minute,  { "Minute", "ais.minute", FT_UINT32, BASE_DEC, NULL, 0x0, "Minute", HFILL} },
          { &hf_ais_second,  { "Second", "ais.second", FT_UINT32, BASE_DEC, NULL, 0x0, "Second", HFILL} },
          { &hf_ais_epfd,    { "EPFD", "ais.epfd", FT_UINT32, BASE_DEC, VALS(vals_epfd), 0x0, "EPFD", HFILL} },

          { &hf_ais_eta_month,   { "ETA Month", "ais.etamonth", FT_UINT32, BASE_DEC, NULL, 0x0, "ETA Month", HFILL} },
          { &hf_ais_eta_day,     { "ETA Day", "ais.etaday", FT_UINT32, BASE_DEC, NULL, 0x0, "ETA Day", HFILL} },
          { &hf_ais_eta_hour,    { "ETA Hour", "ais.etahour", FT_UINT32, BASE_DEC, NULL, 0x0, "ETA Hour", HFILL} },
          { &hf_ais_eta_minute,  { "ETA Minute", "ais.etaminute", FT_UINT32, BASE_DEC, NULL, 0x0, "ETA Minute", HFILL} },

          { &hf_ais_imo,      { "IMO", "ais.imo", FT_UINT32, BASE_DEC, NULL, 0x0, "IMO", HFILL} },
          { &hf_ais_callsign, { "Call Sign", "ais.callsign", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Call Sign", HFILL} },
          { &hf_ais_name,     { "Name", "ais.name", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Name", HFILL} },
          { &hf_ais_shptyp,   { "Ship Type", "ais.shptyp", FT_UINT32, BASE_DEC, VALS(vals_ship_type), 0x0, "Ship Type", HFILL} },
          { &hf_ais_dest,     { "Destination", "ais.dest", FT_STRINGZ, STR_ASCII, NULL, 0x0, "Destination", HFILL} },

          { &hf_ais_dim_bow,       { "Dimention to Bow", "ais.dimbow", FT_UINT32, BASE_DEC, NULL, 0x0, "Dimention to Bow", HFILL} },
          { &hf_ais_dim_stern,     { "Dimention to Stern", "ais.dimstern", FT_UINT32, BASE_DEC, NULL, 0x0, "Dimention to Stern", HFILL} },
          { &hf_ais_dim_port,      { "Dimention to Port", "ais.dimport", FT_UINT32, BASE_DEC, NULL, 0x0, "Dimention to Port", HFILL} },
          { &hf_ais_dim_starboard, { "Dimention to Starboard", "ais.dimstarboard", FT_UINT32, BASE_DEC, NULL, 0x0, "Dimention to Starboard", HFILL} },

          { &hf_ais_lon1,     { "Longitude", "ais.lon", FT_INT32, BASE_CUSTOM, CF_FUNC(I1deg), 0x0, "Longitude", HFILL} },
          { &hf_ais_lat1,     { "Lattitude", "ais.lat", FT_INT32, BASE_CUSTOM, CF_FUNC(I1deg), 0x0, "Latitude", HFILL} },
          { &hf_ais_sog0,     { "Speed Over Ground", "ais.sog", FT_UINT32, BASE_DEC, NULL, 0x0, "Speed Over Ground", HFILL} },
          { &hf_ais_cog0,     { "Course Over Ground", "ais.cog", FT_UINT32, BASE_DEC, NULL, 0x0, "Course Over Ground", HFILL} },

          { &hf_ais_int_msgtype, { "Interrogation Message Type", "ais.intmsgtype", FT_UINT8, BASE_DEC, VALS(vals_msgtype), 0x0, "Interrogation Message Type", HFILL} },
          { &hf_ais_int_mmsi,    { "Interrogation MMSI", "ais.intmmsi", FT_UINT32, BASE_DEC, NULL, 0x0, "Interrogation MMSI", HFILL} },
          { &hf_ais_int_mid,     { "Interrogation MID", "ais.intmid", FT_UINT32, BASE_DEC, VALS(vals_mid), 0x0, "Interrogation MID", HFILL} },

          { &hf_ais_aid_type,     { "Aid Type", "ais.aidtype", FT_UINT32, BASE_DEC, VALS(vals_aid_type), 0x0, "Aid Type", HFILL} },

          { &hf_ais_altitude,     { "Altitude", "ais.altitude", FT_UINT32, BASE_DEC, NULL, 0x0, "Altitude", HFILL} },

          { &hf_ais_channel_a,     { "channel A", "ais.cha", FT_UINT32, BASE_DEC, NULL, 0x0, "Channel A", HFILL} },
          { &hf_ais_channel_b,     { "channel B", "ais.chb", FT_UINT32, BASE_DEC, NULL, 0x0, "Channel B", HFILL} },

          { &hf_ais_dac,     { "DAC", "ais.dac", FT_UINT32, BASE_DEC, VALS(vals_mid), 0x0, "DAC", HFILL} },
          { &hf_ais_fid,     { "FID", "ais.fid", FT_UINT32, BASE_DEC, NULL, 0x0, "FID", HFILL} },
          { &hf_ais_ai,      { "AI", "ais.ai", FT_UINT16, BASE_HEX, VALS(vals_ai), 0x0, "AI", HFILL} },
  };
  proto_ais = proto_register_protocol("AIS packet data", "AIS", "ais");
  proto_register_subtree_array(ettais, array_length(ettais));
  proto_register_field_array(proto_ais, hf_ais, array_length(hf_ais));

  ais_handle = register_dissector("ais_nmea", dissect_ais, proto_ais);

}

void
proto_reg_handoff_nmea(void)
{
    dissector_add_for_decode_as("udp.port", nmea_handle);
  dissector_add_for_decode_as("udp.port", ais_handle);
}

