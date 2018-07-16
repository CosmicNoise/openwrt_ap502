#ifndef _BEACON_H__
#define _BEACON_H__

#define BEACON_INTERVAL 10240
#define MAC_ADDR_LEN 17 
#define INTERFACE_LEN 32
#define ESSID_LEN 32
#define PASSWD_LEN 63
#define BEACON_ELEMENT_ID 0

#define ELEMENT_BSSID 200
#define ELEMENT_SSID 201
#define ELEMENT_KEY  202

#define FAKEAP "cellwifi-fakeap"
#define FAKEAP_LEN 15

#define CAPTURE_PID_FILE "/var/run/capture.pid"
#define BEACON_PID_FILE "/var/run/beacon.pid"

#define CRYPTO_KEY_LEN 32
#define CRYPTO_KEY "zhongyicaiwdskey"
#define INIT_VECT "1234567890abcdef"

#define WDS_SCRIPT "/usr/bin/wds-son "

#define PCAP_FILTER "subtype beacon and ether src 00:00:00:00:00:00"

struct FrameControl {
	uint8_t version:2;
	uint8_t type:2;
	uint8_t subtype:4;
} __attribute__((packed));

struct element {
	uint8_t elementID;
	uint8_t length;
	uint8_t *data;
} __attribute__((packed));

struct mgt_beacon {
	uint64_t timestamp;
	uint16_t interval;
	uint16_t cap;
} __attribute__((packed));


struct ieee80211_radiotap_header {
	uint8_t        it_version;     /* set to 0 */
	uint8_t        it_pad;
	uint16_t       it_len;         /* entire length */
	uint32_t       it_present;     /* fields present */
} __attribute__((packed));

struct rtapdata {
	uint8_t  flags;
	uint8_t  datarate;
	uint16_t frequency;
	uint16_t  type;
	int8_t  ssi;        
	uint8_t antenna;
	uint16_t rx_flags;
} __attribute__ ((packed));

struct AP_descriptor {
	uint8_t MAC[MAC_ADDR_LEN];
	uint8_t channel;
	uint8_t ssid_len;
	int8_t ssid[ESSID_LEN];
	uint8_t key_len;
	int8_t key[PASSWD_LEN];
	uint8_t interface[INTERFACE_LEN];
};

struct MAC_HEADER {
	uint16_t framecontrol;
	uint16_t duration;
	uint8_t dest[6];
	uint8_t src[6];
	uint8_t bssid[6];
	uint16_t sequence;
	struct mgt_beacon beacon;
} __attribute__((packed));

const uint16_t CHANNEL[11] = {
	0x6C09, 0x7109, 0x7609, 0X7B09,
	0x8009, 0x8509, 0x8A09, 0x8F09,
	0x9409, 0x9909, 0x9E09
};

#endif
