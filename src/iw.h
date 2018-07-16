#ifndef __IW_H
#define __IW_H

#include <stdbool.h>
//#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <endian.h>

#include "nl80211.h"
#include "ieee80211.h"

#define ETH_ALEN 6

/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
#  define nl_sock nl_handle
#endif

struct nl80211_state {
	struct nl_msg *msg;
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	struct nl_sock *nl_sock;
	int32_t nl80211_id;
	int64_t devidx;
	uint8_t *ifc;
	uint32_t channel;
	int32_t err;
};

enum command_identify_by {
	CIB_NONE,
	CIB_PHY,
	CIB_NETDEV,
	CIB_WDEV,
};

enum id_input {
	II_NONE,
	II_NETDEV,
	II_PHY_NAME,
	II_PHY_IDX,
	II_WDEV,
};

int nl80211_init(struct nl80211_state *state);
void nl80211_cleanup(struct nl80211_state *state);
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band);
int interface_channel(struct nl80211_state *state);
int interface_up(char * name);
int interface_add(struct nl80211_state *state);
int interface_del(struct nl80211_state *state);


#endif /* __IW_H */
