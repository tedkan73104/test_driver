/******************************************************************************
 *
 * Copyright(c) 2009-2010 - 2020 Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 *****************************************************************************/

#ifndef __CUSTOM_MULTIAP_INTFS_H__
#define __CUSTOM_MULTIAP_INTFS_H__

#ifndef DBG_PLATFORM_CMAP_INTFS
#define DBG_PLATFORM_CMAP_INTFS 0
#endif

#define CMAP_UNASSOC_STA_NONE 0
#define CMAP_UNASSOC_STA_SEARCH 1
#define CMAP_UNASSOC_STA_REPORT 2

#define CMAP_UNASSOC_STA_MEASURE_IDLE 0
#define CMAP_UNASSOC_STA_MEASURE_SETTING 1
#define CMAP_UNASSOC_STA_MEASURE_ONGOING 2

struct cmap_intfs_nl_event {
	u16 type;
	void *msg;
	u32 msg_len;
};

struct cmap_intfs_ops_t {
	int (*ioctl_cmd_hdl)(struct net_device *ndev, void *cmd, u32 cmd_len);
	int nl_type;
	unsigned int nl_group;
	void (*nl_bss_report_info_event)(struct cmap_intfs_nl_event *nl_event,
		struct net_device *ndev, const u8 *bssid, u8 channel, u16 assoc_sta_num,
		u8 ch_util, s32 ch_noise);
	void (*nl_sta_report_info_event)(struct cmap_intfs_nl_event *nl_event,
		struct net_device *ndev, const u8 *bssid, const u8 *sta_addr,
		u32 bytes_sent, u32 bytes_recv, u32 pkts_sent, u32 pkts_recv,
		u32 pkts_tx_err, u32 pkts_rx_err, u32 retry_cnt, s32 rssi,
		u32 phy_tx_rate, u32 phy_rx_rate, u32 assoc_rate);
	void (*nl_unassoc_sta_report_info_event)(struct cmap_intfs_nl_event *nl_event,
		struct net_device *ndev);
	void (*nl_beacon_report_event)(struct cmap_intfs_nl_event *nl_event,
		u8 *sta_addr, u8 n_measure_rpt, u32 elem_len, u8 *elem);
	void (*nl_btm_resp_event)(struct cmap_intfs_nl_event *nl_event,
				  u8 *sta_addr, u8 *bssid, u8 status, u8 *ssid,
				  u8 *dest_bssid, u8 *candidates, u32 candi_cnt);
	void (*nl_sta_event)(struct cmap_intfs_nl_event *nl_event
		, u8 *sta_addr, u8 *bssid, bool connect, u8 *assoc_req_frame_body, size_t frame_body_len);
	void (*nl_bss_status_event)(struct cmap_intfs_nl_event *nl_event
		, struct net_device *ndev, bool is_ap
		, const u8 *bssid, u8 op_ch, u8 op_class, u8 op_txpwr
		, u8 *ht_cap_ie, u8 *vht_cap_ie);

#if DBG_PLATFORM_CMAP_INTFS
	void (*nl_bss_report_info_event_dump)(void *msg, u32 msg_len);
	void (*nl_sta_report_info_event_dump)(void *msg, u32 msg_len);
	void (*nl_unassoc_sta_report_info_event_dump)(void *msg, u32 msg_len);
	void (*nl_beacon_report_event_dump)(void *msg, u32 msg_len);
	void (*nl_btm_resp_event_dump)(void *msg, u32 msg_len);
	void (*nl_sta_event_dump)(void *msg, u32 msg_len);
	void (*nl_bss_status_event_dump)(void *msg, u32 msg_len);
#endif
};

struct cmap_intfs_bss_report_info_cmd_parm {
	struct net_device *ndev;
};

struct cmap_intfs_sta_report_info_cmd_parm {
	struct net_device *ndev;
	u8 mac[ETH_ALEN];
};

struct cmap_intfs_unassoc_sta_report_info_cmd_parm {
	struct net_device *ndev;
};

struct cmap_intfs_beacon_request_cmd_parm {
	struct net_device *ndev;
	u8 mac[ETH_ALEN];
	u16 measure_duration;
	u8 op_class;
	u8 bssid[ETH_ALEN];
	u8 measure_mode;
	u8 reporting_detail;
	u8 ssid[34];
	u8 n_ch;
	u8 *ch_list;
	u8 n_elem_id;
	u8 *elem_id_list;
};

struct cmap_intfs_btm_request_cmd_parm {
	struct net_device *ndev;
	u8 mac[ETH_ALEN];
	u8 ess_imm;
	u8 disassoc_imm;
	u16 disassoc_timer;
	u8 abridged;
	u8 valid_interval;
	u8 target_bssid_cnt;
	u8 session_url[32];
	u8 target_bssid[ETH_ALEN];
	u32 bssid_info;
	u8 op_class;
	u8 channel;
	u8 phy_type;
	u8 preference;
};

struct cmap_intfs_bss_status_cmd_parm {
	struct net_device *ndev;
};

struct cmap_intfs_sta_blacklist_cmd_parm {
	struct net_device *ndev;
	u8 mac[ETH_ALEN];
	u8 oper; /* 1: add, 0: del */
};

struct cmap_intfs_sta_disconnect_cmd_parm {
	struct net_device *ndev;
	u8 mac[ETH_ALEN];
};

void *cmap_intfs_malloc(u32 sz);
void cmap_intfs_mfree(void *buf, u32 sz);

int cmap_intfs_ioctl_bss_report_info(struct cmap_intfs_bss_report_info_cmd_parm *parm);
int cmap_intfs_ioctl_sta_report_info(struct cmap_intfs_sta_report_info_cmd_parm *parm);
void cmap_unassoc_sta_report_info_timer(_adapter *adapter);
int cmap_intfs_ioctl_unassoc_sta_report_info(struct cmap_intfs_unassoc_sta_report_info_cmd_parm *parm);
int cmap_intfs_ioctl_beacon_request(struct cmap_intfs_beacon_request_cmd_parm *parm);
int cmap_intfs_ioctl_btm_request(struct cmap_intfs_btm_request_cmd_parm *parm);
int cmap_intfs_ioctl_bss_status(struct cmap_intfs_bss_status_cmd_parm *parm);
int cmap_intfs_ioctl_sta_blacklist(struct cmap_intfs_sta_blacklist_cmd_parm *parm);
int cmap_intfs_ioctl_sta_disconnect(struct cmap_intfs_sta_disconnect_cmd_parm *parm);

int cmap_intfs_ioctl(struct net_device *ndev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra);

void cmap_intfs_nl_bss_report_info_event(_adapter *adapter);
void cmap_intfs_nl_sta_report_info_event(_adapter *adapter,
	struct net_device *ndev, const u8 *bssid, const u8 *sta_addr,
	u32 bytes_sent, u32 bytes_recv, u32 pkts_sent, u32 pkts_recv,
	u32 pkts_tx_err, u32 pkts_rx_err, u32 retry_cnt, s32 rssi,
	u32 phy_tx_rate, u32 phy_rx_rate, u32 assoc_rate);
void cmap_intfs_nl_unassoc_sta_report_info_event(_adapter *adapter);
void cmap_intfs_nl_beacon_report_event(u8 *sta_addr, u8 n_measure_rpt, u32 elem_len, u8 *elem);
void cmap_intfs_nl_btm_resp_event(_adapter *adapter, u8 *sta_addr,
				  u8 *bssid, u8 status, u8 *dest_bssid,
				  u8 *candidates, u32 candi_cnt);
void cmap_intfs_nl_sta_event(u8 *sta_addr, u8 *bssid, bool connect
	, u8 *assoc_req_frame_body, size_t frame_body_len);
void cmap_intfs_nl_bss_status_event(_adapter *adapter, bool force);

int cmap_intfs_init(void);
void cmap_intfs_deinit(void);

#endif /* __CUSTOM_MULTIAP_INTFS_H__ */
