/******************************************************************************
 *
 * Copyright(c) 2007 - 2020 Realtek Corporation.
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

#include <drv_types.h>
#include <hal_data.h>
#include <net/sock.h>
#include "custom_multiap_intfs.h"

static struct cmap_intfs_ops_t cmap_intfs_ops;

void *cmap_intfs_malloc(u32 sz)
{
	return rtw_malloc(sz);
}

void cmap_intfs_mfree(void *buf, u32 sz)
{
	rtw_mfree(buf, sz);
}

int cmap_intfs_ioctl_bss_report_info(struct cmap_intfs_bss_report_info_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);

	cmap_intfs_nl_bss_report_info_event(adapter);
	return 0;
}

int cmap_intfs_ioctl_sta_report_info(struct cmap_intfs_sta_report_info_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	struct sta_priv *stapriv = &adapter->stapriv;
	struct sta_info *sta = NULL;
	_list *head, *list;
	int ret = -ENOENT;
	const u8 *sta_addr = parm->mac;
	u32 bytes_sent, bytes_recv, pkts_sent, pkts_recv, phy_tx_rate, phy_rx_rate, assoc_rate;
	s32 rssi;

	if (!MLME_IS_AP(adapter)) {
		RTW_WARN(FUNC_ADPT_FMT" not AP iface\n", FUNC_ADPT_ARG(adapter));
		ret = -EINVAL;
		goto exit;
	}

	rtw_stapriv_asoc_list_lock(stapriv);

	head = &stapriv->asoc_list;
	list = get_next(head);

	/* check asoc_queue */
	while ((rtw_end_of_queue_search(head, list)) == _FALSE) {
		sta = LIST_CONTAINOR(list, struct sta_info, asoc_list);
		list = get_next(list);

		if (_rtw_memcmp(sta_addr, sta->cmn.mac_addr, ETH_ALEN)) {
			u8 bw = rtw_get_tx_bw_mode(adapter, sta);
			u8 assoc_rate_idx, is_vht = 0;
			s8 i;

#ifdef CONFIG_80211AC_VHT
			is_vht = sta->vhtpriv.vht_option ? 1 : 0;
#endif
			for(i = 63; i >= 0; i--)
				if (sta->cmn.ra_info.ramask >> i)
					break;
			assoc_rate_idx = is_vht ? i + (DESC_RATEVHTSS1MCS0 - DESC_RATEMCS0) : i;

			bytes_sent = sta->sta_stats.tx_bytes;
			bytes_recv = sta->sta_stats.rx_bytes;
			pkts_sent = sta->sta_stats.tx_pkts;
			pkts_recv = sta->sta_stats.rx_data_pkts;
			/* TODO: uPktsTxError, uPktsRxError, uRetransCnt */
			rssi = translate_percentage_to_dbm(sta->cmn.rssi_stat.rssi);
			phy_tx_rate = rtw_desc_rate_to_bitrate(bw, rtw_get_current_tx_rate(adapter, sta), rtw_get_current_tx_sgi(adapter, sta))/10;
			phy_rx_rate = rtw_desc_rate_to_bitrate(bw, sta->curr_rx_rate & 0x7f, (sta->curr_rx_rate & 0x80) >> 7)/10;
			assoc_rate = i < 0 ? 0 : rtw_desc_rate_to_bitrate(bw, assoc_rate_idx, query_ra_short_GI(sta, bw))/10;
			ret = 0;
			break;
		}
	}

	rtw_stapriv_asoc_list_unlock(stapriv);

	if (ret == 0)
		cmap_intfs_nl_sta_report_info_event(adapter, parm->ndev, adapter_mac_addr(adapter), sta_addr,
			bytes_sent, bytes_recv, pkts_sent, pkts_recv, 0, 0, 0,
			rssi, phy_tx_rate, phy_rx_rate, assoc_rate);
	else
		RTW_WARN(FUNC_ADPT_FMT" sta="MAC_FMT", not found\n", FUNC_ADPT_ARG(adapter), MAC_ARG(sta_addr));

exit:
	return ret;
}

int cmap_unassoc_sta_report_info(_adapter *adapter)
{
	struct mlme_priv *mlmepriv = &(adapter->mlmepriv);
	u8 i, searched, search_latter = 0, report = 0;

	for (i = 0; i < mlmepriv->cmap_unassoc_sta_cnt; i++) {
		struct unassoc_sta_info *cmap_sta = &mlmepriv->cmap_unassoc_sta[i];
		struct unassoc_sta_info sta = {{0}};

		if (cmap_sta->interested != CMAP_UNASSOC_STA_SEARCH)
			continue;

		searched = rtw_search_unassoc_sta(adapter, cmap_sta->addr, &sta);
		if (searched && sta.recv_signal_power != 0) {
			cmap_sta->recv_signal_power = sta.recv_signal_power;
			cmap_sta->time = sta.time;
			cmap_sta->interested = CMAP_UNASSOC_STA_REPORT;
			report = 1;
		} else {
			rtw_add_interested_unassoc_sta(adapter, cmap_sta->addr);
			search_latter = 1;
		}
	}
	if (report == 1)
		cmap_intfs_nl_unassoc_sta_report_info_event(adapter);

	return search_latter;
}

void cmap_unassoc_sta_report_info_timer(_adapter *adapter)
{
	struct mlme_priv *mlmepriv = &(adapter->mlmepriv);
	u8 i, searched, report = 0;

	for (i = 0; i < mlmepriv->cmap_unassoc_sta_cnt; i++) {
		struct unassoc_sta_info *cmap_sta = &mlmepriv->cmap_unassoc_sta[i];
		struct unassoc_sta_info sta = {{0}};

		if (cmap_sta->interested != CMAP_UNASSOC_STA_SEARCH)
			continue;

		searched = rtw_search_unassoc_sta(adapter, cmap_sta->addr, &sta);
		if (searched && sta.recv_signal_power != 0) {
			cmap_sta->recv_signal_power = sta.recv_signal_power;
			cmap_sta->time = sta.time;
			cmap_sta->interested = CMAP_UNASSOC_STA_REPORT;
			report = 1;
		}
	}
	if (report == 1)
		cmap_intfs_nl_unassoc_sta_report_info_event(adapter);

	rtw_undo_all_interested_unassoc_sta(adapter);
	adapter->cmap_unassoc_sta_measure_en = CMAP_UNASSOC_STA_MEASURE_IDLE;
}

int cmap_intfs_ioctl_unassoc_sta_report_info(struct cmap_intfs_unassoc_sta_report_info_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	struct mlme_priv *mlmepriv = &(adapter->mlmepriv);
	u8 search_latter = 0;

	if (mlmepriv->cmap_unassoc_sta_cnt == 0) {
		adapter->cmap_unassoc_sta_measure_en = CMAP_UNASSOC_STA_MEASURE_IDLE;
		return 0;
	}

	search_latter = cmap_unassoc_sta_report_info(adapter);
	if (search_latter == 0) {
		adapter->cmap_unassoc_sta_measure_en = CMAP_UNASSOC_STA_MEASURE_IDLE;
		return 0;
	}

	_set_timer(&mlmepriv->cmap_unassoc_sta_timer, 100);

	return 0;
}

int cmap_intfs_ioctl_beacon_request(struct cmap_intfs_beacon_request_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	struct _RT_OPERATING_CLASS ap_ch_rpt = {0};
	u8 ch, n_ap_ch_rpt;

	if (parm->n_ch > 1) {
		if (parm->n_ch > MAX_CH_NUM_IN_OP_CLASS)
			return -EINVAL;
		ch = 255;
		n_ap_ch_rpt = 1;
		ap_ch_rpt.Len = parm->n_ch;
		ap_ch_rpt.global_op_class = parm->op_class;
		_rtw_memcpy(ap_ch_rpt.Channel, parm->ch_list, parm->n_ch);
	} else if(parm->n_ch == 1){
		ch = parm->ch_list[0];
		n_ap_ch_rpt = 0;
	} else {
		ch = 0;
		n_ap_ch_rpt = 0;
	}

#if DBG_PLATFORM_CMAP_INTFS
	RTW_INFO("[%s] mac:"MAC_FMT", measure_duration:%u, op_class:%u, "
		 "bssid:"MAC_FMT", measure_mode:%u, reporting_detail:%u, "
		 "ssid:%s, n_ch:%u, n_elem_id:%u\n",
		 __func__, MAC_ARG(parm->mac), parm->measure_duration,
		 parm->op_class, MAC_ARG(parm->bssid), parm->measure_mode,
		 parm->reporting_detail, parm->ssid, parm->n_ch, parm->n_elem_id);
	if (parm->n_ch > 0)
		RTW_DUMP_SEL(RTW_DBGDUMP, parm->ch_list, parm->n_ch);
	if (parm->n_elem_id > 0)
		RTW_DUMP_SEL(RTW_DBGDUMP, parm->elem_id_list, parm->n_elem_id);
#endif
	rm_send_bcn_reqs(adapter, parm->mac, parm->op_class, ch, parm->measure_duration,
			 parm->measure_mode, parm->bssid, parm->ssid, parm->reporting_detail,
			 n_ap_ch_rpt, &ap_ch_rpt, parm->n_elem_id, parm->elem_id_list);

	return 0;
}

void cmap_intfs_nl_bss_status_event_force(_adapter *adapter)
{
	cmap_intfs_nl_bss_status_event(adapter, 1);
}

int cmap_intfs_ioctl_btm_request(struct cmap_intfs_btm_request_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	const u8 *mac = parm->mac;
	struct sta_priv *stapriv = &adapter->stapriv;
	struct sta_info *sta = NULL;
	struct btm_req_hdr req_hdr;
	struct wnm_btm_cant candidates;
	_list *head, *list;
	int ret = -ENOENT;

	RTW_INFO("PeerMac="MAC_FMT"\n", MAC_ARG(parm->mac));
	RTW_INFO("EssImm(%hhu), DisassocImm(%hhu), DisassocTimer(%hu), Abridged(%hhu), "
		 "ValidInterval(%hhu), TargetBssCnt(%hhu), SessionURL(%s)\n",
		 parm->ess_imm, parm->disassoc_imm, parm->disassoc_timer,
		 parm->abridged, parm->valid_interval,
		 parm->target_bssid_cnt, parm->session_url);
	RTW_INFO("TargetBSSID="MAC_FMT"\n", MAC_ARG(parm->target_bssid));
	RTW_INFO("bssid_info(%u), op_class(%hhu), channel(%hhu), phy_type(%hhu), preference(%hhu)\n",
		 parm->bssid_info, parm->op_class, parm->channel,
		 parm->phy_type, parm->preference);

	if (!MLME_IS_AP(adapter)) {
		RTW_WARN(FUNC_ADPT_FMT" not AP iface\n", FUNC_ADPT_ARG(adapter));
		ret = -EINVAL;
		goto exit;
	}

	rtw_stapriv_asoc_list_lock(stapriv);

	head = &stapriv->asoc_list;
	list = get_next(head);

	/* check asoc_queue */
	while ((rtw_end_of_queue_search(head, list)) == _FALSE) {
		sta = LIST_CONTAINOR(list, struct sta_info, asoc_list);
		list = get_next(list);

		if (_rtw_memcmp(mac, sta->cmn.mac_addr, ETH_ALEN)) {
			RTW_INFO(FUNC_ADPT_FMT"Send btm_req to sta="MAC_FMT"\n",
				 FUNC_ADPT_ARG(adapter),
				 MAC_ARG(sta->cmn.mac_addr));
			/* fill the btm_req content */
			_rtw_memset(&req_hdr, 0, sizeof(struct btm_req_hdr));
			get_random_bytes(&req_hdr.dialog_token, 1);
			/* have one candidate list */
			req_hdr.req_mode |= PREFERRED_CANDIDATE_LIST_INCLUDED;
			if (parm->ess_imm)
				req_hdr.req_mode |= ESS_DISASSOC_IMMINENT;

			if (parm->disassoc_imm)
				req_hdr.req_mode |= DISASSOC_IMMINENT;

			if (parm->abridged)
				req_hdr.req_mode |= ABRIDGED;

			req_hdr.disassoc_timer = parm->disassoc_timer;
			req_hdr.validity_interval = parm->valid_interval;
			/* fill candidate list */
			candidates.nb_rpt.id = RTW_WLAN_ACTION_WNM_NB_RPT_ELEM;
			candidates.nb_rpt.len = 16;
			_rtw_memcpy(candidates.nb_rpt.bssid, parm->target_bssid, ETH_ALEN);
			candidates.nb_rpt.bss_info = parm->bssid_info;
			candidates.nb_rpt.reg_class = parm->op_class;
			candidates.nb_rpt.ch_num = parm->channel;
			candidates.nb_rpt.phy_type = parm->phy_type;
			candidates.preference = parm->preference;
			rtw_wnm_issue_btm_req(adapter, parm->mac, &req_hdr,
					      parm->session_url, strlen(parm->session_url),
					      (u8 *)&candidates, 1);
			ret = 0;
			break;
		}
	}

	rtw_stapriv_asoc_list_unlock(stapriv);

exit:
	return ret;
}

int cmap_intfs_ioctl_bss_status(struct cmap_intfs_bss_status_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	u8 ret;

	ret = rtw_run_in_thread_cmd_wait(adapter
		, ((void *)(cmap_intfs_nl_bss_status_event_force)), adapter, 1000);
	if (ret != _SUCCESS) /* driver is IPS, do directly */
		cmap_intfs_nl_bss_status_event_force(adapter);

	return 0;
}

int cmap_intfs_ioctl_sta_blacklist(struct cmap_intfs_sta_blacklist_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	const u8 *mac = parm->mac;
	const u8 oper = parm->oper;
	int ret = -ENOENT;

	rtw_set_macaddr_acl(adapter, RTW_ACL_PERIOD_BSS, RTW_ACL_MODE_ACCEPT_UNLESS_LISTED);
	if (oper == 1)
		ret = rtw_acl_add_sta(adapter, RTW_ACL_PERIOD_BSS, parm->mac);
	else if (oper == 0)
		ret = rtw_acl_remove_sta(adapter, RTW_ACL_PERIOD_BSS, parm->mac);

	return ret;
}

int cmap_intfs_ioctl_sta_disconnect(struct cmap_intfs_sta_disconnect_cmd_parm *parm)
{
	_adapter *adapter = rtw_netdev_priv(parm->ndev);
	const u8 *mac = parm->mac;
	struct sta_priv *stapriv = &adapter->stapriv;
	struct sta_info *sta = NULL;
	u8 updated = _FALSE;
	_list *head, *list;
	int ret = -ENOENT;

	if (!MLME_IS_AP(adapter)) {
		RTW_WARN(FUNC_ADPT_FMT" not AP iface\n", FUNC_ADPT_ARG(adapter));
		ret = -EINVAL;
		goto exit;
	}

	rtw_stapriv_asoc_list_lock(stapriv);

	head = &stapriv->asoc_list;
	list = get_next(head);

	/* check asoc_queue */
	while ((rtw_end_of_queue_search(head, list)) == _FALSE) {
		sta = LIST_CONTAINOR(list, struct sta_info, asoc_list);
		list = get_next(list);

		if (_rtw_memcmp(mac, sta->cmn.mac_addr, ETH_ALEN)) {
			RTW_INFO(FUNC_ADPT_FMT" sta="MAC_FMT", aid=%d\n", FUNC_ADPT_ARG(adapter)
				, MAC_ARG(sta->cmn.mac_addr), sta->cmn.aid);
			rtw_stapriv_asoc_list_del(stapriv, sta);
			updated = ap_free_sta(adapter, sta, 1, WLAN_REASON_PREV_AUTH_NOT_VALID, 1);
			ret = 0;
			break;
		}

	}

	rtw_stapriv_asoc_list_unlock(stapriv);

	associated_clients_update(adapter, updated, STA_INFO_UPDATE_ALL);

	if (ret != 0)
		RTW_WARN(FUNC_ADPT_FMT" sta="MAC_FMT", not found\n", FUNC_ADPT_ARG(adapter), MAC_ARG(mac));

exit:
	return ret;
}

int cmap_intfs_ioctl(struct net_device *ndev, struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	int ret = 0;
	char *cmd;

	cmd = rtw_vmalloc(wrqu->data.length + 1);
	if (!cmd)
		return -ENOMEM;

	if (copy_from_user(cmd, wrqu->data.pointer, wrqu->data.length)) {
		ret = -EFAULT;
		goto exit;
	}
	cmd[wrqu->data.length] = 0;

	if (DBG_PLATFORM_CMAP_INTFS)
		RTW_INFO(FUNC_NDEV_FMT" %s\n", FUNC_NDEV_ARG(ndev), cmd);

	if (cmap_intfs_ops.ioctl_cmd_hdl)
		ret = cmap_intfs_ops.ioctl_cmd_hdl(ndev, cmd, wrqu->data.length);

exit:
	rtw_vmfree(cmd, wrqu->data.length + 1);

	return ret;
}

static struct sock *nl_ksock = NULL;

void cmap_intfs_nl_sendmsg(u16 type, void *msg, u32 msg_len)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;

	if (!nl_ksock || !msg)
		return;

	skb = nlmsg_new(msg_len, GFP_KERNEL);
	if (!skb) {
		RTW_ERR("%s: nlmsg_new(%d) err\n", __func__, msg_len);
		return;
	}
	rtw_mstat_update(MSTAT_TYPE_SKB, MSTAT_ALLOC_SUCCESS, skb->truesize);

	nlh = nlmsg_put(skb, 0, 0, type, msg_len, 0);
	_rtw_memcpy(NLMSG_DATA(nlh), msg, msg_len);
	NETLINK_CB(skb).dst_group = cmap_intfs_ops.nl_group;

	rtw_mstat_update(MSTAT_TYPE_SKB, MSTAT_FREE, skb->truesize);
	netlink_broadcast(nl_ksock, skb, 0, cmap_intfs_ops.nl_group, GFP_KERNEL);
}

void cmap_intfs_nl_bss_report_info_event(_adapter *adapter)
{
	if (cmap_intfs_ops.nl_bss_report_info_event) {
		struct rf_ctl_t *rfctl = adapter_to_rfctl(adapter);
		u8 iface_id = adapter->iface_id;
		u8 assoc_sta_num = adapter->stapriv.asoc_list_cnt;
		u8 ch_util = rtw_get_ch_utilization(adapter);
		s8 ch_noise = rtw_phydm_nhm_noise_pwr(adapter) - 100;
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_bss_report_info_event(&nl_event, adapter->pnetdev, adapter_mac_addr(adapter)
			, rfctl->if_op_ch[iface_id], assoc_sta_num, ch_util, ch_noise);
		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_bss_report_info_event_dump)
				cmap_intfs_ops.nl_bss_report_info_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_sta_report_info_event(_adapter *adapter,
	struct net_device *ndev, const u8 *bssid, const u8 *sta_addr,
	u32 bytes_sent, u32 bytes_recv, u32 pkts_sent, u32 pkts_recv,
	u32 pkts_tx_err, u32 pkts_rx_err, u32 retry_cnt, s32 rssi,
	u32 phy_tx_rate, u32 phy_rx_rate, u32 assoc_rate)
{
	if (cmap_intfs_ops.nl_sta_report_info_event) {
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_sta_report_info_event(&nl_event, ndev, bssid, sta_addr,
			bytes_sent, bytes_recv, pkts_sent, pkts_recv,
			pkts_tx_err, pkts_rx_err, retry_cnt,
			rssi, phy_tx_rate, phy_rx_rate, assoc_rate);
		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_sta_report_info_event_dump)
				cmap_intfs_ops.nl_sta_report_info_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_unassoc_sta_report_info_event(_adapter *adapter)
{
	if (cmap_intfs_ops.nl_unassoc_sta_report_info_event) {
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_unassoc_sta_report_info_event(&nl_event, adapter->pnetdev);
		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_unassoc_sta_report_info_event_dump)
				cmap_intfs_ops.nl_unassoc_sta_report_info_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_beacon_report_event(u8 *sta_addr, u8 n_measure_rpt, u32 elem_len, u8 *elem)
{
	if (cmap_intfs_ops.nl_beacon_report_event) {
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_beacon_report_event(&nl_event, sta_addr, n_measure_rpt, elem_len, elem);
		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_beacon_report_event_dump)
				cmap_intfs_ops.nl_beacon_report_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_btm_resp_event(_adapter *adapter, u8 *sta_addr,
				  u8 *bssid, u8 status, u8 *dest_bssid,
				  u8 *candidates, u32 candi_cnt)
{
	if (cmap_intfs_ops.nl_btm_resp_event) {
		struct mlme_priv *pmlmepriv = &(adapter->mlmepriv);
		struct wlan_network *cur_network = &(pmlmepriv->cur_network);
		u8 *ssid = cur_network->network.Ssid.Ssid;

		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_btm_resp_event(&nl_event, sta_addr, bssid,
						 status, ssid, dest_bssid,
						 candidates, candi_cnt);

		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_btm_resp_event_dump)
				cmap_intfs_ops.nl_btm_resp_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_sta_event(u8 *sta_addr, u8 *bssid, bool connect
	, u8 *assoc_req_frame_body, size_t frame_body_len)
{
	if (cmap_intfs_ops.nl_sta_event) {
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

		cmap_intfs_ops.nl_sta_event(&nl_event, sta_addr, bssid, connect, assoc_req_frame_body, frame_body_len);
		if (nl_event.msg && nl_event.msg_len) {
			#if DBG_PLATFORM_CMAP_INTFS
			if (cmap_intfs_ops.nl_sta_event_dump)
				cmap_intfs_ops.nl_sta_event_dump(nl_event.msg, nl_event.msg_len);
			#endif
			cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);
			cmap_intfs_mfree(nl_event.msg, nl_event.msg_len);
		}
	}
}

void cmap_intfs_nl_bss_status_event(_adapter *adapter, bool force)
{
	if (cmap_intfs_ops.nl_bss_status_event) {
		struct rf_ctl_t *rfctl = adapter_to_rfctl(adapter);
		u8 iface_id = adapter->iface_id;
		WLAN_BSSID_EX *network = &adapter->mlmeextpriv.mlmext_info.network;
		u8 *ht_cap_ie = NULL;
		sint ht_cap_ie_len;
		u8 *vht_cap_ie = NULL;
		sint vht_cap_ie_len;
		struct cmap_intfs_nl_event nl_event = {.msg = NULL, .msg_len = 0,};

#ifdef CONFIG_80211N_HT
		ht_cap_ie = rtw_get_ie(BSS_EX_TLV_IES(network), WLAN_EID_HT_CAP, &ht_cap_ie_len, BSS_EX_TLV_IES_LEN(network));
		if (ht_cap_ie && ht_cap_ie_len != HT_CAP_IE_LEN)
			ht_cap_ie = NULL;
#endif

#ifdef CONFIG_80211AC_VHT
		vht_cap_ie = rtw_get_ie(BSS_EX_TLV_IES(network), WLAN_EID_VHT_CAPABILITY, &vht_cap_ie_len, BSS_EX_TLV_IES_LEN(network));
		if (vht_cap_ie && vht_cap_ie_len != VHT_CAP_IE_LEN)
			vht_cap_ie = NULL;
#endif

		cmap_intfs_ops.nl_bss_status_event(&nl_event, adapter->pnetdev, MLME_IS_AP(adapter), adapter_mac_addr(adapter)
			, rfctl->if_op_ch[iface_id], rfctl->if_op_class[iface_id], rfctl->op_txpwr_max / MBM_PDBM
			, ht_cap_ie, vht_cap_ie);
		if (nl_event.msg && nl_event.msg_len) {
			if (force || !adapter->cmap_bss_status_evt || adapter->cmap_bss_status_evt_len != nl_event.msg_len
				|| _rtw_memcmp(adapter->cmap_bss_status_evt, nl_event.msg, nl_event.msg_len) == _FALSE
			) {
				/* skip the initial one without op ch */
				if (!force && !adapter->cmap_bss_status_evt && !rfctl->if_op_ch[iface_id])
					goto store;

				#if DBG_PLATFORM_CMAP_INTFS
				if (cmap_intfs_ops.nl_bss_status_event_dump)
					cmap_intfs_ops.nl_bss_status_event_dump(nl_event.msg, nl_event.msg_len);
				#endif
				cmap_intfs_nl_sendmsg(nl_event.type, nl_event.msg, nl_event.msg_len);

store:
				/* store the lastest one */
				if (adapter->cmap_bss_status_evt)
					cmap_intfs_mfree(adapter->cmap_bss_status_evt, adapter->cmap_bss_status_evt_len);
				adapter->cmap_bss_status_evt = nl_event.msg;
				adapter->cmap_bss_status_evt_len = nl_event.msg_len;
			}
		}
	}
}

static int cmap_intfs_nl_init(void)
{
	struct netlink_kernel_cfg cmap_intfs_nl_cfg = {
		.groups = cmap_intfs_ops.nl_group,
	};

	nl_ksock = netlink_kernel_create(&init_net
		, cmap_intfs_ops.nl_type, &cmap_intfs_nl_cfg);

	if (nl_ksock) {
		RTW_INFO("%s: alloc nl_sock ok\n", __func__);
		return 0;
	} else {
		RTW_ERR("%s: alloc nl_sock err\n", __func__);
		return -ENOMEM;
	}
}

static void cmap_intfs_nl_deinit(void)
{
	netlink_kernel_release(nl_ksock);
}

extern struct cmap_intfs_ops_t platform_cmap_intfs_ops;

int cmap_intfs_init(void)
{
	int ret;

	_rtw_memcpy(&cmap_intfs_ops, &platform_cmap_intfs_ops, sizeof(cmap_intfs_ops));
	ret = cmap_intfs_nl_init();

	return ret;
}

void cmap_intfs_deinit(void)
{
	cmap_intfs_nl_deinit();
	_rtw_memset(&cmap_intfs_ops, 0, sizeof(cmap_intfs_ops));
}

