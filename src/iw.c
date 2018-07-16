/*
 * nl80211 userspace tool
 *
 * Copyright 2007, 2008	Johannes Berg <johannes@sipsolutions.net>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_slip.h>
#include <sys/ioctl.h>
#include <syslog.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "iw.h"
#include "debug.h"

extern int default_level;

/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}

static inline int nl_socket_set_buffer_size(struct nl_sock *sk,
					    int rxbuf, int txbuf)
{
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */

int iw_debug = 0;

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		debug(LOG_ERR, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	if (genl_connect(state->nl_sock)) {
		debug(LOG_ERR, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		nl_socket_free(state->nl_sock);
		return err;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		debug(LOG_ERR, "nl80211 not found.\n");
		err = -ENOENT;
		nl_socket_free(state->nl_sock);
		return err;
	}
	state->msg = nlmsg_alloc();
	if (!state->msg) {
		debug(LOG_ERR, "failed to allocate netlink message\n");
		return 2;
	}

	if (default_level > LOG_WARNING){
		state->cb = nl_cb_alloc(NL_CB_DEBUG);
		state->s_cb = nl_cb_alloc(NL_CB_DEBUG);
	} 
	else {
		state->cb = nl_cb_alloc(NL_CB_DEFAULT);
		state->s_cb = nl_cb_alloc(NL_CB_DEFAULT);
	}
	if (!state->cb || !state->s_cb) {
		debug(LOG_ERR, "failed to allocate netlink callbacks\n");
		goto err;
	}

	nl_socket_set_cb(state->nl_sock, state->s_cb);

	nl_cb_err(state->cb, NL_CB_CUSTOM, error_handler, &state->err);
	nl_cb_set(state->cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &state->err);
	nl_cb_set(state->cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &state->err);

	return 0;

err:
	return 1;
}

void nl80211_cleanup(struct nl80211_state *state)
{
	nl_cb_put(state->cb);
	nlmsg_free(state->msg);
	nl_socket_free(state->nl_sock);
}

static int phy_lookup(char *name)
{
	char buf[200];
	int fd, pos;
	
	debug(LOG_DEBUG, "phy:%s\n", name);

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	if (fd < 0){
		debug(LOG_ERR, "open %s fail <%s>\n", buf, strerror(errno));
		return -1;
	}
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0) {
		close(fd);
		return -1;
	}
	buf[pos] = '\0';
	close(fd);
	return atoi(buf);
}

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
		case NL80211_BAND_2GHZ:
			if (chan == 14) 
				return 2484;
			else if (chan < 14) 
				return 2407 + chan * 5;
			break;
		case NL80211_BAND_5GHZ:
			if (chan >= 182 && chan <= 196)
				return 4000 + chan * 5;
			else
				return 5000 + chan * 5;
			break;
		case NL80211_BAND_60GHZ:
			if (chan < 5)
				return 56160 + chan * 2160;
			break;
		default:
			;   
	}   
	return 0; /* not supported */
}

int interface_up(char * name)
{
	struct ifreq ifr;
	int sockfd;
	int ret = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0){
		debug(LOG_ERR, "create socket error:%s\n", strerror(errno));	
		return -1;
	}
	memset(&ifr, 0, sizeof(struct ifreq));  
	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	if (ret < 0){
		debug(LOG_ERR, "ioctl SIOCGIFFLAGS error:%s\n", strerror(errno));
		goto out;
	}
	ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
	ret = ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	if (ret < 0){
		debug(LOG_ERR, "ioctl SIOCGIFFLAGS error:%s\n", strerror(errno));
		goto out;
	}

out:
	close(sockfd);
	return ret;
}

int interface_channel(struct nl80211_state *state)
{
	unsigned int freq = state->channel;
	enum nl80211_band band;
	state->devidx = phy_lookup("phy0");
	if (state->devidx < 0){
		debug(LOG_ERR, "devidx:%lld\n", state->devidx);
		return -errno;
	}
	nlmsg_free(state->msg);
	state->msg = nlmsg_alloc();
	if (!state->msg) {
		debug(LOG_ERR, "failed to allocate netlink message\n");
		return 2;
	}

	band = freq <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
	freq = ieee80211_channel_to_frequency(freq, band);
	printf("freq :%d\n", freq);
	genlmsg_put(state->msg, 0, 0, state->nl80211_id, 0, 0,NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(state->msg, NL80211_ATTR_WIPHY, state->devidx);
	NLA_PUT_U32(state->msg, NL80211_ATTR_WIPHY_FREQ, freq);
	NLA_PUT_U32(state->msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);
	state->err = nl_send_auto_complete(state->nl_sock, state->msg);
	if(state->err < 0){
		nl_perror(state->err, "nl_send_auto_complete");
		return state->err;
	}

	state->err = 1;
	while (state->err > 0)
		nl_recvmsgs(state->nl_sock, state->cb);

	return state->err;	
nla_put_failure: /* jump from NLA_PUT_U32  */
	state->err = -ENOBUFS;
	return state->err;
}

int interface_add(struct nl80211_state *state)
{
	state->devidx = phy_lookup("phy0");
	if (state->devidx < 0){
		debug(LOG_ERR, "devidx:%lld\n", state->devidx);
		return -errno;
	}
	genlmsg_put(state->msg, NL_AUTO_PID, NL_AUTO_SEQ, state->nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(state->msg, NL80211_ATTR_WIPHY, state->devidx);
	NLA_PUT_STRING(state->msg, NL80211_ATTR_IFNAME, state->ifc);
	NLA_PUT_U32(state->msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);
	state->err = nl_send_auto_complete(state->nl_sock, state->msg);
	if(state->err < 0){
		nl_perror(state->err, "nl_send_auto_complete");
		return state->err;
	}
	state->err = 1;
	while (state->err > 0)
		nl_recvmsgs(state->nl_sock, state->cb);

	return state->err;	
nla_put_failure:
	state->err = -ENOBUFS;
	return state->err;

}

int interface_del(struct nl80211_state *state)
{
	state->devidx = if_nametoindex(state->ifc);
	if (state->devidx < 0){
		debug(LOG_ERR, "devidx:%lld\n", state->devidx);
		return -errno;
	}
	nlmsg_free(state->msg);
	state->msg = nlmsg_alloc();
	if (!state->msg) {
		debug(LOG_ERR, "failed to allocate netlink message\n");
		return 2;
	}
	genlmsg_put(state->msg, NL_AUTO_PID, NL_AUTO_SEQ, state->nl80211_id, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(state->msg, NL80211_ATTR_IFINDEX, state->devidx);
	state->err = nl_send_auto_complete(state->nl_sock, state->msg);
	debug(LOG_DEBUG, "delete interface:%s\n", state->ifc);
	return state->err;	
nla_put_failure:
	state->err = -ENOBUFS;
	return state->err;
}

#if 0
int main(int argc, char **argv)
{
	struct nl80211_state nlstate;
	int err;

	/* calculate command size including padding */

	err = nl80211_init(&nlstate);
	if (err)
		return 1;
	argv++;
	err = interface_add(&nlstate, "test");
	printf("err:%d\n", err);
	if (err < 0) {
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
	} 

	err = interface_up("test");
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
	}

	err = interface_channel(&nlstate, 11);
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
	}

#if 0
	err = interface_del(&nlstate, "test");
	if (err < 0){
		debug(LOG_ERR, "command failed: %s (%d)\n", strerror(-err), err); //ENFILE
	}
#endif

	nl80211_cleanup(&nlstate);

	return err;
}
#endif 
