#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <openssl/aes.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include "beacon.h"
#include "debug.h"
#include "iw.h"

int32_t default_level = LOG_WARNING;
int8_t interface[32];

static int32_t got = 0;
static struct nl80211_state nlstate;
pcap_t *handle;            /* Session handle */

uint8_t *decryptoBeacon(const uint8_t *in, uint8_t in_len, uint8_t *out)
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
	AES_set_decrypt_key(key, nr_of_bits, &a_key);
	AES_cbc_encrypt(in, cipher, nr_of_bytes, &a_key, iv, AES_DECRYPT);
	int i = 0;
#if 0
	debug(LOG_DEBUG, "\n");
	for (; i < AES_BLOCK_SIZE * 16; i++){
		debug(LOG_DEBUG, "%02x ", cipher[i]);
	}   
	debug(LOG_DEBUG, "\n");
#endif
	memcpy(out, cipher, in_len);
	return out;
}


void got_packet(u_char *args, const struct pcap_pkthdr *header,	const u_char *packet)
{
	int32_t index;
	const u_char *pos = packet;
	struct MAC_HEADER *hdr;	
	struct AP_descriptor ap; 
	int32_t fakeap_len;
	uint16_t offset;
	struct ieee80211_radiotap_header *rthdr;

	/* struc radiotap length is depend on the device , 
	   so we calculate the offset by radiotap frame format instead
	   of using sizeof(struct MAC_HEADER);  
	*/
	rthdr = (struct ieee80211_radiotap_header *)pos;

	memset(&ap, 0, sizeof(ap));

	if(rthdr->it_version != 0){
		debug(LOG_ERR, "only support version 0\n");
		return ;
	}
	pos += htole16(rthdr->it_len);
	debug(LOG_DEBUG, "radiotap present length : %d\n", htole16(rthdr->it_len));
	hdr = (struct MAC_HEADER *)pos;

	debug(LOG_DEBUG, "dest:%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdr->dest[0],hdr->dest[1],hdr->dest[2],
			hdr->dest[3],hdr->dest[4],hdr->dest[5]);
	debug(LOG_DEBUG, "src:%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdr->src[0],hdr->src[1],hdr->src[2],
			hdr->src[3],hdr->src[4],hdr->src[5]);
	debug(LOG_DEBUG, "bssid:%02x:%02x:%02x:%02x:%02x:%02x\n", 
			hdr->bssid[0],hdr->bssid[1],hdr->bssid[2],
			hdr->bssid[3],hdr->bssid[4],hdr->bssid[5]);
	debug(LOG_DEBUG, "sequence:%x\n", hdr->sequence);

	debug(LOG_DEBUG, "get %d! bytes data:\n",header->len);
	hexdump(pos, header->len);
		
	pos += sizeof(struct MAC_HEADER);
	debug(LOG_DEBUG, "%x\n", *pos);
	if(*pos == 0){
		pos++;
		fakeap_len = *pos;
		pos++;
		if(memcmp(FAKEAP, pos, FAKEAP_LEN)){
			debug(LOG_ERR, "Invalid beacon");
			return;	
		}
	}
	
	pos += fakeap_len;
	if (*pos == 200){
		pos++;
		debug(LOG_DEBUG, "bssid length:%d\n", *pos);
		pos++;
		memcpy(ap.MAC, pos, MAC_ADDR_LEN);
		debug(LOG_DEBUG, "bssid: %s\n", ap.MAC);
		pos += MAC_ADDR_LEN;

	}
	if (*pos == 201){
		pos++;
		debug(LOG_DEBUG, "real ssid length:%d\n", *pos);
		ap.ssid_len = *pos;
		pos++;
		debug(LOG_DEBUG, "real ssid: %s\n", strndup(pos, ap.ssid_len));
		memcpy(ap.ssid, pos, ap.ssid_len);
	}

	pos += ap.ssid_len;
	debug(LOG_DEBUG, "*pos:%d\n", *pos);
	if(*pos == 202){
		pos++;
		debug(LOG_DEBUG, "key length: %d\n", *pos);
		ap.key_len = *pos;
		uint8_t key[AES_BLOCK_SIZE * 16];
		pos++;
		debug(LOG_DEBUG, "key:%s\n", decryptoBeacon(strndup(pos, ap.key_len), ap.key_len, key));
		memcpy(ap.key, key, ap.key_len);
	}
	if (ap.key_len && ap.ssid_len){
		uint8_t cmd[1024] = {0};
		strncpy(cmd, WDS_SCRIPT, 17);
		strncat(cmd, ap.MAC, MAC_ADDR_LEN);
		strncat(cmd, " ", 1);
		strncat(cmd, ap.ssid, ap.ssid_len);
		strncat(cmd, " ", 1);
		strncat(cmd, ap.key, ap.key_len);
		debug(LOG_DEBUG, "cmd:%s\n", cmd);
		got = 1;
		system(cmd);
	}
}

int32_t update_pid_file(void)
{

	int8_t path[] = CAPTURE_PID_FILE;
	int32_t fd = 0; 

	unlink(path);
	/* check permissions of generated file */
	if ( (fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH )) < 0 ) { 
		debug(LOG_DEBUG, "could not open %s - %s", path, strerror(errno) );
		return -1;
	}    

	dprintf(fd, "%d\n", getpid());
	close (fd);

	return 0;
}


void usage(void)
{
	printf("\n***************************************\n");
	printf("capture <arg>\n");
	printf("-i : interface to capture packets\n");
	printf("-d : debug level\n");
	printf("-h : show help message\n");
	printf("\n***************************************\n");
}
void parse_arg(int argc, char **argv)
{
	int32_t c;
	int32_t flag = 0;
	while(EOF != (c = getopt(argc, argv, "hi:d:"))){
		switch (c){
			case 'i':{
				memcpy(interface, optarg, 32);
				flag = 1;
				break;
			}
			case 'd':{
				default_level = atoi(optarg);		 
				break;
			}
			case 'h':
			case '?':
			default:{
				usage();		
				exit(1);
			}
		}
	}
	if(!flag){
		usage();		
		exit(1);
	}
}


void interface_exit(struct nl80211_state *state)
{
	int32_t err ;
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
	debug(LOG_DEBUG, "capture signale:%d\n", sig);
	interface_exit(&nlstate);
	pcap_breakloop(handle);
	pcap_close(handle);

	exit(0);
}

void signal_timer(int32_t sig)
{
	int32_t err;
//	signal(SIGALRM, SIG_IGN);
//	alarm(0);
	nlstate.channel += 5;
	if(nlstate.channel > 11){
		nlstate.channel = 1;
	}
	pcap_breakloop(handle);
	err = interface_channel(&nlstate);
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); 
	}
	debug(LOG_DEBUG, "channel:%d\n", nlstate.channel);
	signal(SIGALRM, signal_timer);
	alarm(5);
}
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

	/* Init SIGALRM */
	sa.sa_handler = signal_timer;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		debug(LOG_ERR, "signal(): %s", strerror(errno));
		exit(1);
	}

}

void reinit_pcap(void)
{
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
	struct bpf_program fp;        /* The compiled filter */
	char filter_exp[] = PCAP_FILTER;    /* The filter expression */
	bpf_u_int32 mask;        /* Our netmask */
	bpf_u_int32 net;        /* Our IP */
	//struct pcap_pkthdr header;    /* The header that pcap gives us */

	handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		debug(LOG_ERR, "Couldn't open device %s: %s\n", interface, errbuf);
		goto err;
	}

	debug(LOG_DEBUG, "Device: %s\n", interface);

	if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
		debug(LOG_ERR, "Device %s doesn't provide 80211 headers - not supported\n", interface);
		goto out;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		debug(LOG_ERR, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		goto out;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		debug(LOG_ERR, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		goto out;
	}
/*
	if(pcap_set_timeout(handle, 1000) == -1){
		debug(LOG_ERR, "pcap_set_timeout failed %s %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if(pcap_setnonblock(handle, 1, errbuf) == -1){
		debug(LOG_ERR, "pcap_setnonblock failed %s %s\n", filter_exp, pcap_geterr(handle));
		return (2);
	}

*/
	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header.len);

	/* capture 1 packets */

	return;

out:
	pcap_close(handle);
err:
	interface_exit(&nlstate);
	exit(1);
}


int main(int argc, char *argv[])
{
	int loop = 16;
	int ret;
	const u_char *packet;        /* The actual packet */

	/*
	   dev = pcap_lookupdev(errbuf);
	   if (dev == NULL) {
	   debug(LOG_ERR, "Couldn't find default device: %s\n", errbuf);
	   return(2);
	   }
	 */
	parse_arg(argc, argv);

	if(update_pid_file()){
		debug(LOG_ERR, "could not write pid file\n");
		return -1;
	}

	nlstate.ifc = interface;

	signal_init();
	interface_init(&nlstate);
	reinit_pcap();

	nlstate.channel = 1;
//	pcap_dispatch(handle, 1, got_packet, NULL);
	alarm(5);
	while(!got){
		ret = pcap_loop(handle, 1, got_packet, NULL);
		if (ret == -1){
			debug(LOG_ERR, "PCAP:%s\n", pcap_geterr(handle));
			reinit_pcap();
		}
		else if (ret == -2){
			debug(LOG_DEBUG, "pcap_breakloop:%d", loop);
		}
//		pcap_next(handle, &header);
		if(!(loop--)){
			loop = 16;
		}
	}
	/* And close the session */
	pcap_close(handle);
	interface_exit(&nlstate);

	return(0);
}


