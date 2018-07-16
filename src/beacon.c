#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <openssl/aes.h>
#include <regex.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>

//#define _BSD_SOURCE             /* See feature_test_macros(7) */
#include <endian.h>

#include "beacon.h"
#include "debug.h"
#include "iw.h"

struct ieee80211_radiotap_header rthdr;
struct rtapdata rtp;
struct MAC_HEADER header; 
struct AP_descriptor ap;
int32_t default_level = LOG_WARNING;
static struct nl80211_state nlstate;
int32_t sock = -1;

void usage(void)
{
	printf("\n******************************************\n");
	printf("beacon <arg>\n");
	printf("-i : interface to send beacon frame\n");
	printf("-k : password \n");
	printf("-s : ssid\n");
	printf("-m : mac\n");
	printf("-d : debug level\n");
	printf("-h : show help message\n");
	printf("\n******************************************\n");
}

int32_t isValidMac(const int8_t *mac)
{
	int8_t *reg="^([0-9a-fA-F]{2})(([/\\s:][0-9a-fA-F]{2}){5})$";
	regex_t pat_cmdline;
	regmatch_t matches[17];
	if(regcomp(&pat_cmdline, reg, REG_EXTENDED)){
		debug(LOG_ERR, "regcomp error <%s>\n", strerror(errno));	
		exit(1);
	}
	if(regexec(&pat_cmdline, mac, 17, matches, 0)){
		regfree(&pat_cmdline);	
		return -1;
	}
	regfree(&pat_cmdline);
	return 0;
}

int update_pid_file(void)
{
	char path[] = BEACON_PID_FILE;
	int fd = 0;  

	unlink(path);

	if ( (fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH )) < 0 ) {  //check permissions of generated file
		debug(LOG_ERR, "could not open %s - %s", path, strerror(errno) );
		return -1; 
	}        

	dprintf(fd, "%d\n", getpid());
	close (fd);

	return 0;
}


void parse_arg(int argc, char **argv)
{
	int32_t c;
	memset(&ap, 0, sizeof(ap));
	while (EOF!= (c = getopt(argc, argv, "hi:k:m:s:d:"))) {
		switch(c){
			case 'i':{
				memcpy(ap.interface, optarg, 32);
				debug(LOG_DEBUG, "ap.interface:%s\n", ap.interface);
				break;
			}
			case 'k':{
				ap.key_len = strlen(optarg) > PASSWD_LEN ? PASSWD_LEN : strlen(optarg);
				memcpy(ap.key, optarg, ap.key_len);
				break;
			}
			case 's':{
				ap.ssid_len = strlen(optarg) > ESSID_LEN ? ESSID_LEN : strlen(optarg);
				memcpy(ap.ssid, optarg, ap.ssid_len);
				break;
			}
			case 'm':{
				if(isValidMac(optarg)){
					debug(LOG_ERR, "Invalid MAC\n");
					usage();
					exit(1);

				}
				debug(LOG_DEBUG, "mac:%s\n", optarg);
				memcpy(ap.MAC, optarg, MAC_ADDR_LEN);		 
				break;
			}
			case 'd':{
				default_level = atoi(optarg);
				break;
			}
			case 'h':
			case '?':
			default: {
				usage();
				exit(1);
			}
		}
		
	}

	debug(LOG_DEBUG, "ap.ssid_len:%d\n", ap.ssid_len);
	debug(LOG_DEBUG, "ap.ssid:%s\n", ap.ssid);
	debug(LOG_DEBUG, "ap.key_len:%d\n", ap.key_len);
	debug(LOG_DEBUG, "ap.key:%s\n", ap.key);

	if (!ap.ssid_len || !ap.key_len || !ap.ssid || !ap.key){
		usage();	
		exit(1);	
	}
	
}

void config_init(struct AP_descriptor *ap)
{
	rthdr.it_version = 0;
	rthdr.it_pad = 0;
	rthdr.it_len = htole16(18);
	/*	we use a more general present 	*/
	/*	see http://www.radiotheader.org/ for more introduction */
	rthdr.it_present =	0x2e480000;

	/* IEEE80211_RADIOTheader_F_FCS; */
	/* auto add frame check sequence */
	rtp.flags = 0;

	/* 1.0 Mb/s */
	rtp.datarate = 0x02;

	/* channel frequency , will be fixed by drivers*/
	rtp.frequency = 0x6C09;

	/* 802.11g */
	rtp.type = 0xC000;

	/* -20dbm, will be fixed by drivers */
	rtp.ssi = 0xA0;

	/* has antenna , will be fixed by drivers */
	rtp.antenna = 0x01;

	rtp.rx_flags = 0x0000;

	/* beacon frame */
	header.framecontrol = 0x8000;

	/* duration 0s */
	header.duration = 0x0000;

	/* destination MAC address, broadcast */ 
	memcpy(header.dest, "\xFF\xFF\xFF\xFF\xFF\xFF", 6);

	/* source MAC address, fake MAC address */
	memcpy(header.src, "\x00\x00\x00\x00\x00\x00", 6);

	/* BSSID , fake MAC address */
	memcpy(header.bssid, "\x00\x00\x00\x00\x00\x00", 6);
	
	/* fragments and sequence number: start from 1 */
	header.sequence = 0x0001;

	/* beacon timestamp for BSS : initial value to 0 */
	header.beacon.timestamp = 0LL;

	/* beacon interval : 10TU*/
	header.beacon.interval = htole16(BEACON_INTERVAL / 1024);

	/* beacon capabilities */
	header.beacon.cap = htole16(0x0001);

	//ap->ssid_len = 6;
	//memcpy(ap->ssid, "fakeap", 6);
	//ap->key_len = 10;
	//memcpy(ap->key, "1234567890", 10);
}

uint8_t *cryptoBeacon(const uint8_t *in, uint8_t in_len, uint8_t *out)
{
	uint8_t iv[AES_BLOCK_SIZE * 4] = INIT_VECT;
	uint8_t cipher[AES_BLOCK_SIZE * 16]; 
	uint8_t key[CRYPTO_KEY_LEN] = CRYPTO_KEY;
	int32_t nr_of_bits = 0;
	int32_t nr_of_bytes = 0;
	AES_KEY a_key;
	
	memset(cipher, 0, sizeof(cipher));
	nr_of_bits = 8 * sizeof(key);
	nr_of_bytes = in_len; 
	AES_set_encrypt_key(key, nr_of_bits, &a_key);
	AES_cbc_encrypt(in, cipher, nr_of_bytes, &a_key, iv, AES_ENCRYPT);
	int i = 0;
	memcpy(out, cipher, in_len);
	return out;
}

uint16_t constructBeacon(struct AP_descriptor *ap, uint8_t *data)
{
	/****************************************************************/
	/*					Big endian									*/
	/*	 Frame Control		0×80 0×00								*/
	/*	 Duration	0×00 0×00										*/
	/*	 Destination Address FF:FF:FF:FF:FF:FF						*/
	/*	 Source Address		 00:11:22:33:44:55						*/
	/*	 BSSID				 00:11:22:33:44:55						*/
	/*	 Seq-ID	12-bit Sequence Number + 4-bit Fragment Number		*/
	/*	 Timestamp	BSS timestamp	8-bypes							*/
	/*	 Beacon interval	0×64 0×00  100TU						*/
	/*	 Capability info	0×01 0×00  PCF no poll					*/
	/*	 SSID	Element ID + len + data								*/
	/*	 FCS	auto-calcuate by drivers							*/
	uint16_t offset = 0;	
	uint8_t *pos = data;
	uint8_t cipher[AES_BLOCK_SIZE * 16];

	memcpy(pos, &rthdr, sizeof(struct ieee80211_radiotap_header));
	pos += sizeof(struct ieee80211_radiotap_header);
	memcpy(pos, &rtp, sizeof(struct rtapdata));
	pos += sizeof(struct rtapdata);

	memcpy(pos, &header, sizeof(struct MAC_HEADER));
	pos += sizeof(struct MAC_HEADER);
	/* fake ap ssid */
	*pos = BEACON_ELEMENT_ID;
	pos++;
	*pos = FAKEAP_LEN;
	pos++;
	memcpy(pos, FAKEAP, FAKEAP_LEN);
	pos += FAKEAP_LEN;

	/* bssid */
	*pos = ELEMENT_BSSID;
	pos++;
	*pos = MAC_ADDR_LEN;
	pos++;
	memcpy(pos, ap->MAC, MAC_ADDR_LEN);
	pos += MAC_ADDR_LEN;

	/* ssid */
	//pos++;
	*pos = ELEMENT_SSID;
	pos++;
	*pos = ap->ssid_len;
	pos++;
	memcpy(pos, ap->ssid, ap->ssid_len);
	
	/* vendor */
	pos += ap->ssid_len;
	*pos = ELEMENT_KEY;
	pos++;
//	*pos = ap->key_len;
	*pos = (ap->key_len / 16 + 1) * 16;
	pos++;
	memcpy(pos, cryptoBeacon(ap->key, (ap->key_len / 16 + 1) * 16, cipher), (ap->key_len / 16 + 1) * 16);
	pos += (ap->key_len / 16 + 1) * 16;

	return pos - data;
}


ssize_t transmitBeacon(struct AP_descriptor *ap, int32_t sock,  uint8_t *data, uint16_t length)
{
	ssize_t ret = 0;
	
	hexdump(data, length);

	ret = write(sock, data, length);
	if (ret != length){
		debug(LOG_ERR, "send beacon frame failed:%s\n", strerror(errno));
	}
	return ret;
}

int32_t open_raw_socket(const int8_t *iface)
{
	int32_t sock;
	struct ifreq ifr;
	struct sockaddr_ll ll;

	debug(LOG_DEBUG, "open interface <%s>\n", iface);

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0){
		debug(LOG_ERR, "create raw socket error: %s\n", strerror(errno));
		exit(1);
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
	if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0){
		debug(LOG_ERR, "set socket <SIOCGIFINDEX> error: %s\n", strerror(errno));
		return -1;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_P_ALL);
	if(bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0){
		debug(LOG_ERR, "bind socket <AP_PACKET> error: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	
	struct packet_mreq mr;
	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ll.sll_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if(setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0){
		debug(LOG_ERR, "set socket option <PACKET_MR_PROMISC> error: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

void interface_exit(struct nl80211_state *state)
{
	uint32_t err;
	err = interface_del(state);
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
	}

	nl80211_cleanup(state);
}

int32_t interface_init(struct nl80211_state *state)
{
	int err;

	/* calculate command size including padding */

	err = nl80211_init(state);
	if (err){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
		exit(1);
	}

	err = interface_add(state);
	if (err < 0) {
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
		nl80211_cleanup(state);
		exit(1);
	} 

	err = interface_up(state->ifc);
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
		interface_exit(state);
		exit(1);
	}

	return err;
}


void signal_handler(int32_t sig)
{	
	interface_exit(&nlstate);
	exit(0);
}

#if 0
void signal_pipe(int32_t sig)
{
	interface_exit(&nlstate);
	interface_init(&nlstate);

	if(sock > 0){
		close(sock);
	}

	sock = open_raw_socket(nlstate.ifc);
	if (sock < 0){
		debug(LOG_ERR, "create raw socket[%s] error <%s>\n", nlstate.ifc, strerror(errno));
		return 1;
	}
	
}
#endif

static void signal_init(void)
{
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));	
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
	
#if 0
	/* SIGPIPE */
	sa.sa_handler = signal_pipe;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
#endif
}

int32_t reinit(void)
{
	interface_exit(&nlstate); 
	interface_init(&nlstate);

	if (sock > 0){
		close(sock);
	}
	sock = open_raw_socket(nlstate.ifc);
	if (sock < 0){
		debug(LOG_ERR, "create raw socket[%s] error <%s>\n", nlstate.ifc, strerror(errno));
		return 1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	uint8_t buffer[4096];	
	uint16_t len;
	ssize_t ret;

	if(update_pid_file()){
		debug(LOG_ERR, "write beacon pid to file error\n");
		return -1;
	}

	parse_arg(argc, argv);
	config_init(&ap);
	if (ap.interface){
		nlstate.ifc = ap.interface;
	}
	else {
		nlstate.ifc = "monitor";
	}
	
	signal_init();
	interface_init(&nlstate);

	sock = open_raw_socket(nlstate.ifc);
	if (sock < 0){
		debug(LOG_ERR, "create raw socket[%s] error <%s>\n", nlstate.ifc, strerror(errno));
		return 1;
	}

	while(1) {
		len = constructBeacon(&ap, buffer);
		debug(LOG_DEBUG, "beacon length :%d\n", len);
		ret = transmitBeacon(&ap, sock, buffer, len);	
		if (ret < 0 && (errno == ENXIO || errno == ENETDOWN)){
			if (reinit()) {
				break;
			}
		}
		sleep(1);
	}
	
	interface_exit(&nlstate);

	return 0;
}



