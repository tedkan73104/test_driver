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
#include "custom_multiap_intfs_00.h"
#include "../os_dep/linux/custom_multiap_intfs/custom_multiap_intfs.h"

static int platform_cmap_ioctl_cmd_hdl(struct net_device *ndev, void *cmd, u32 cmd_len)
{
	int ret = 0;

	if (strncmp(cmd, "BssReportInfo=1", 15) == 0) {
		struct cmap_intfs_bss_report_info_cmd_parm parm;

		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_bss_report_info(&parm);

	} else if (strncmp(cmd, "StaReportInfo=", 14) == 0) {
		struct cmap_intfs_sta_report_info_cmd_parm parm;

		if (strlen(cmd + 14) < 17 || hwaddr_aton_i(cmd + 14, parm.mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}
		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_sta_report_info(&parm);
	} else if (strncmp(cmd, "mnt_en=1", 8) == 0) {
		_adapter *adapter = rtw_netdev_priv(ndev);
		struct mlme_priv *mlmepriv = &(adapter->mlmepriv);
		u32 size = CMAP_UNASSOC_METRICS_STA_MAX * sizeof(struct unassoc_sta_info);

		if (adapter->cmap_unassoc_sta_measure_en != CMAP_UNASSOC_STA_MEASURE_IDLE) {
			ret = -EINVAL;
			goto exit;
		}
		adapter->cmap_unassoc_sta_measure_en = CMAP_UNASSOC_STA_MEASURE_SETTING;
		mlmepriv->cmap_unassoc_sta_cnt = 0;
		memset(mlmepriv->cmap_unassoc_sta, 0, size);
	} else if (strncmp(cmd, "mnt_en=0", 8) == 0) {
		struct cmap_intfs_unassoc_sta_report_info_cmd_parm parm;
		_adapter *adapter = rtw_netdev_priv(ndev);

		if (adapter->cmap_unassoc_sta_measure_en != CMAP_UNASSOC_STA_MEASURE_SETTING) {
			ret = -EINVAL;
			goto exit;
		}
		adapter->cmap_unassoc_sta_measure_en = CMAP_UNASSOC_STA_MEASURE_ONGOING;
		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_unassoc_sta_report_info(&parm);
	} else if (strncmp(cmd, "mnt_info=", 9) == 0) {
		_adapter *adapter = rtw_netdev_priv(ndev);
		struct mlme_priv *mlmepriv = &(adapter->mlmepriv);
		struct unassoc_sta_info *sta;
		u8 mac[ETH_ALEN];

		if (adapter->cmap_unassoc_sta_measure_en != CMAP_UNASSOC_STA_MEASURE_SETTING) {
			ret = -EINVAL;
			goto exit;
		}
		if (strlen(cmd + 9) < 17 || hwaddr_aton_i(cmd + 9, mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}
		if (mlmepriv->cmap_unassoc_sta_cnt >= CMAP_UNASSOC_METRICS_STA_MAX) {
			ret = -EINVAL;
			goto exit;
		}
		sta = &mlmepriv->cmap_unassoc_sta[mlmepriv->cmap_unassoc_sta_cnt];
		memcpy(sta->addr, mac, ETH_ALEN);
		sta->interested = CMAP_UNASSOC_STA_SEARCH;
		mlmepriv->cmap_unassoc_sta_cnt++;
		
	} else if (strncmp(cmd, "BeaconRequest=", 14) == 0) {
		struct cmap_intfs_beacon_request_cmd_parm parm = {0};
		char *next, *ptr, *tmp;
		int i;

		RTW_INFO("%s BeaconRequest\n", __func__);
		if (strlen(cmd) < 14) {
			ret = -EINVAL;
			goto exit;
		}

		ptr = cmd + 14;
		next = strsep(&ptr, "-");
		if (!next || strlen(next) < 17 || hwaddr_aton_i(next, parm.mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit;
		}
		parm.measure_duration = rtw_atoi(next);

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit;
		}
		parm.op_class = rtw_atoi(next);

		next = strsep(&ptr, "-");
		if (!next || strlen(next) < 17 || hwaddr_aton_i(next, parm.bssid) != 0) {
			ret = -EINVAL;
			goto exit;
		}

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit;
		}
		parm.measure_mode = rtw_atoi(next);

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit;
		}
		parm.reporting_detail = rtw_atoi(next);

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit;
		}
		/* ch list */
		tmp = strsep(&next, " ");
		if (!tmp) {
			ret = -EINVAL;
			goto exit;
		}
		if ((int)rtw_atoi(tmp) < 0) {
			ret = -EINVAL;
			goto exit;
		} else
			parm.n_ch = rtw_atoi(tmp);
		if (parm.n_ch != 0) {
			parm.ch_list = rtw_zmalloc(parm.n_ch);
			for (i = 0; i < parm.n_ch; i++) {
				tmp = strsep(&next, " ");
				if (tmp)
					parm.ch_list[i] = rtw_atoi(tmp);
				else {
					RTW_WARN("channel list format warning\n");
					break;
				}
			}
		}

		next = strsep(&ptr, "-");
		if (!next) {
			ret = -EINVAL;
			goto exit_free1;
		}
		/* elem id list */
		tmp = strsep(&next, " ");
		if (!tmp) {
			ret = -EINVAL;
			goto exit_free1;
		}
		if ((int)rtw_atoi(tmp) < 0) {
			ret = -EINVAL;
			goto exit_free1;
		} else
			parm.n_elem_id = rtw_atoi(tmp);
		if (parm.n_elem_id != 0) {
			parm.elem_id_list = rtw_zmalloc(parm.n_elem_id);
			for (i = 0; i < parm.n_elem_id; i++) {
				tmp = strsep(&next, " ");
				if (tmp)
					parm.elem_id_list[i] = rtw_atoi(tmp);
				else {
					RTW_WARN("element ID list format waring\n");
					break;
				}
			}
		}

		next = strsep(&ptr, "\0");
		if (!next) {
			ret = -EINVAL;
			goto exit_free2;
		}
		strncpy(parm.ssid, next, sizeof(parm.ssid));

		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_beacon_request(&parm);

exit_free2:
		if (parm.elem_id_list)
			rtw_mfree(parm.elem_id_list, parm.n_elem_id);
exit_free1:
		if (parm.ch_list)
			rtw_mfree(parm.ch_list, parm.n_ch);

	} else if (strncmp(cmd, "BTMRequest=", 11) == 0) {
		struct cmap_intfs_btm_request_cmd_parm parm;
		char *c1, *c2, *next, res = 0;

		next = (char *)(cmd + 11);
		c1 = strsep(&next, " \t");
		c2 = strsep(&next, " \t");
		if (!c1 || !c2) {
			ret = -EINVAL;
			RTW_WARN(FUNC_NDEV_FMT" incorrect BTMRequest format\n",
				 FUNC_NDEV_ARG(ndev));
			goto exit;
		}

		/* c1: 94:87:e0:24:8b:4b-1-1-50-0-50-1-zte_mesh5g
		 * c2: 00:d0:d0:00:00:02-0x0-115-36-0x09-255
		 */
		next = strsep(&c1, "-");
		res = sscanf(c1, "%hhu-%hhu-%hu-%hhu-%hhu-%hhu-%s",
			     &parm.ess_imm, &parm.disassoc_imm,
			     &parm.disassoc_timer, &parm.abridged,
			     &parm.valid_interval, &parm.target_bssid_cnt,
			     parm.session_url);
		if (hwaddr_aton_i(next, parm.mac) != 0 || res != 7) {
			ret = -EINVAL;
			RTW_WARN(FUNC_NDEV_FMT" incorrect BTMRequest format\n",
				 FUNC_NDEV_ARG(ndev));
			goto exit;
		}

		next = strsep(&c2, "-");
		res = sscanf(c2, "%x-%hhu-%hhu-%hhx-%hhu",
			     &parm.bssid_info, &parm.op_class,
			     &parm.channel, &parm.phy_type, &parm.preference);
		if (hwaddr_aton_i(next, parm.target_bssid) != 0 || res != 5) {
			ret = -EINVAL;
			RTW_WARN(FUNC_NDEV_FMT" incorrect BTMRequest format\n",
				 FUNC_NDEV_ARG(ndev));
			goto exit;
		}

		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_btm_request(&parm);

	} else if (strncmp(cmd, "BssStatus=1", 11) == 0) {
		struct cmap_intfs_bss_status_cmd_parm parm;

		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_bss_status(&parm);

	} else if (strncmp(cmd, "BlacklistAdd=", 13) == 0) {
		struct cmap_intfs_sta_blacklist_cmd_parm parm;

		if (strlen(cmd + 13) < 17 || hwaddr_aton_i(cmd + 13, parm.mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}
		parm.ndev = ndev;
		parm.oper = 1;
		ret = cmap_intfs_ioctl_sta_blacklist(&parm);

	} else if (strncmp(cmd, "BlacklistDel=", 13) == 0) {
		struct cmap_intfs_sta_blacklist_cmd_parm parm;

		if (strlen(cmd + 13) < 17 || hwaddr_aton_i(cmd + 13, parm.mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}
		parm.ndev = ndev;
		parm.oper = 0;
		ret = cmap_intfs_ioctl_sta_blacklist(&parm);

	} else if (strncmp(cmd, "DisConnectSta=", 14) == 0) {
		struct cmap_intfs_sta_disconnect_cmd_parm parm;

		if (strlen(cmd + 14) < 17 || hwaddr_aton_i(cmd + 14, parm.mac) != 0) {
			ret = -EINVAL;
			goto exit;
		}
		parm.ndev = ndev;
		ret = cmap_intfs_ioctl_sta_disconnect(&parm);

	} else {
		RTW_WARN(FUNC_NDEV_FMT" unknown cmd\n", FUNC_NDEV_ARG(ndev));
		ret = -EINVAL;
	}

exit:
	return ret;
}

static void platform_cmap_intfs_nl_bss_report_info_event(struct cmap_intfs_nl_event *nl_event,
	struct net_device *ndev, const u8 *bssid, u8 channel, u16 assoc_sta_num,
	u8 ch_util, s32 ch_noise)
{
	T_MULTI_AP_BSS_METRICS_RESP *evt;

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	evt->uIfIndex = ndev->ifindex;
	_rtw_memcpy(evt->mBssid, bssid, ETH_ALEN);
	evt->u8Channel = channel;
	evt->u16AssocStaNum = assoc_sta_num;
	evt->u8ChanUtil = ch_util;
	evt->iChanNoise = ch_noise;

	nl_event->type = EV_WLAN_MULTIAP_BSS_METRICS_RESPONSE;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

static void platform_cmap_intfs_nl_sta_report_info_event(struct cmap_intfs_nl_event *nl_event,
	struct net_device *ndev, const u8 *bssid, const u8 *sta_addr,
	u32 bytes_sent, u32 bytes_recv, u32 pkts_sent, u32 pkts_recv,
	u32 pkts_tx_err, u32 pkts_rx_err, u32 retry_cnt, s32 rssi,
	u32 phy_tx_rate, u32 phy_rx_rate, u32 assoc_rate)
{
	T_MULTI_AP_STA_ASSOC_METRICS_RESP *evt;

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	evt->uIfIndex = ndev->ifindex;
	_rtw_memcpy(evt->mBssid, bssid, ETH_ALEN);
	_rtw_memcpy(evt->mStaMac, sta_addr, ETH_ALEN);
	evt->uBytesSent = bytes_sent;
	evt->uBytesRecv = bytes_recv;
	evt->uPktsSent = pkts_sent;
	evt->uPktsRecv = pkts_recv;
	evt->uPktsTxError = pkts_tx_err;
	evt->uPktsRxError = pkts_rx_err;
	evt->uRetransCnt = retry_cnt;
	evt->iRssi = rssi;
	evt->uPhyTxRate = phy_tx_rate;
	evt->uPhyRxRate = phy_rx_rate;
	evt->uAssocRate = assoc_rate;

	nl_event->type = EV_WLAN_MULTIAP_ASSOC_STA_METRICS_RESPONSE;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

static void platform_cmap_intfs_nl_unassoc_sta_report_info_event(
	struct cmap_intfs_nl_event *nl_event, struct net_device *ndev)
{
	T_MULTI_AP_STA_UNASSOC_METRICS_RESP *evt;
	_adapter *adapter = rtw_netdev_priv(ndev);
	struct mlme_priv *m = &(adapter->mlmepriv);
	struct rf_ctl_t *rfctl = adapter_to_rfctl(adapter);
	u8 ch = rfctl->if_op_ch[adapter->iface_id];
	int i, n_sta = 0;

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	evt->uIfIndex = ndev->ifindex;
	_rtw_memcpy(evt->mBssid, adapter_mac_addr(adapter), ETH_ALEN);

	for (i = 0; i < m->cmap_unassoc_sta_cnt; i++) {
		if (m->cmap_unassoc_sta[i].interested == CMAP_UNASSOC_STA_REPORT &&
		    !is_zero_mac_addr(m->cmap_unassoc_sta[i].addr)) {
			memcpy(evt->tMetrics[i].mStaMac, m->cmap_unassoc_sta[i].addr, ETH_ALEN);
			evt->tMetrics[i].iRssi = m->cmap_unassoc_sta[i].recv_signal_power;
			evt->tMetrics[i].u8Channel = ch;
			evt->tMetrics[i].uTime = rtw_systime_to_ms(rtw_get_current_time() - m->cmap_unassoc_sta[i].time);
			n_sta++;

			m->cmap_unassoc_sta[i].interested = CMAP_UNASSOC_STA_NONE;
		}
	}
	evt->u8StaNum = n_sta;

	nl_event->type = EV_WLAN_MULTIAP_UNASSOC_STA_METRICS_RESPONSE;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

static void platform_cmap_intfs_nl_beacon_report_event(struct cmap_intfs_nl_event *nl_event,
	u8 *sta_addr, u8 n_measure_rpt, u32 elem_len, u8 *elem)
{
	T_MULTI_AP_BEACON_METRICS_RESP *evt;

	if (elem_len > ELEM_LEN_MAX) {
		RTW_WARN("%s: elem_len > ELEM_LEN_MAX", __func__);
		return;
	}

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	_rtw_memcpy(evt->mStaMac, sta_addr, ETH_ALEN);
	evt->u8ElemNum = n_measure_rpt;
	evt->uElemLen = elem_len;
	_rtw_memcpy(evt->uElem, elem, elem_len);

	nl_event->type = EV_WLAN_MULTIAP_BEACON_METRICS_RESPONSE;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

static void platform_cmap_intfs_nl_btm_resp(struct cmap_intfs_nl_event *nl_event,
					    u8 *sta_addr, u8 *bssid, u8 status,
					    u8 *ssid, u8 *dest_bssid,
					    u8 *candidates, u32 candi_cnt)
{
	T_MULTI_AP_STA_STEERING_REPORT *evt;
	T_NEIGHBOR_AP *nb_ap = NULL;
	struct nb_rpt_hdr *nb_rpt = NULL;
	struct wnm_btm_cant *cand = NULL;
	u8 i;

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	_rtw_memset(evt, 0, sizeof(*evt));
	evt->u8Status = status;
	_rtw_memcpy(evt->mStaMac, sta_addr, ETH_ALEN);
	_rtw_memcpy(evt->mBssid, bssid, ETH_ALEN);
	if (status == 0 && dest_bssid)
		_rtw_memcpy(evt->mDestBssid, dest_bssid, ETH_ALEN);

	if (candi_cnt != 0) {
		evt->tCandidateList.uNum = candi_cnt;
		cand = (struct wnm_btm_cant *)candidates;
		for (i = 0; i < candi_cnt; ++i) {
			nb_ap = &evt->tCandidateList.tAp[i];
			_rtw_memcpy(nb_ap->mBssid, cand[i].nb_rpt.bssid, ETH_ALEN);
			strncpy(nb_ap->szSsid, ssid, strlen(ssid));
			nb_ap->u8Chan = cand[i].nb_rpt.ch_num;
			nb_ap->u8OpClass = cand[i].nb_rpt.reg_class;
			nb_ap->u8Pref = cand[i].preference;
			nb_ap->bHt = (TEST_FLAG(cand[i].nb_rpt.bss_info, BIT11)) ? 1 : 0;
			nb_ap->bVht = (TEST_FLAG(cand[i].nb_rpt.bss_info, BIT12)) ? 1 : 0;
		}
	}

	nl_event->type = EV_WLAN_MULTIAP_STEERING_BTM_REPORT;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

static void platform_cmap_intfs_nl_sta_event(struct cmap_intfs_nl_event *nl_event
	, u8 *sta_addr, u8 *bssid, bool connect, u8 *assoc_req_frame_body, size_t frame_body_len)
{
	T_MULTI_AP_STA_EVENT_NOTIFY *evt;
	size_t cap_len = connect ? frame_body_len : 0;

	evt = cmap_intfs_malloc(sizeof(*evt) + cap_len);
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt) + cap_len);
		return;
	}

	_rtw_memcpy(evt->mStaMac, sta_addr, ETH_ALEN);
	_rtw_memcpy(evt->mBssid, bssid, ETH_ALEN);
	evt->u8Status = connect ? 1 : 0;
	if (cap_len > 0)
		_rtw_memcpy(evt->u8Cap, assoc_req_frame_body, cap_len);
	evt->uCapLen = cap_len;

	nl_event->type = EV_WLAN_MULTIAP_STA_TOPOLOGY_NOTIFY;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt) + cap_len;
}

static void platform_cmap_nl_bss_status_event(struct cmap_intfs_nl_event *nl_event
	, struct net_device *ndev, bool is_ap
	, const u8 *bssid, u8 op_ch, u8 op_class, u8 op_txpwr
	, u8 *ht_cap_ie, u8 *vht_cap_ie)
{
	T_MULTI_AP_BSS_STATUS_REPORT *evt;

	evt = cmap_intfs_malloc(sizeof(*evt));
	if (!evt) {
		RTW_ERR("%s: cmap_intfs_malloc(%zd) err\n", __func__, sizeof(*evt));
		return;
	}

	_rtw_memset(evt, 0, sizeof(*evt));

	evt->uIfIndex = ndev->ifindex;

	if (!is_ap || !op_ch)
		goto exit;

	_rtw_memcpy(evt->mBssid, bssid, ETH_ALEN);
	evt->uStatus = 1;
	evt->u8Channel = op_ch;
	evt->u8OperClass = op_class;
	evt->u8Txpower = op_txpwr;

	if (evt->u8Channel <= 14)
		evt->uBand = MAP_BAND_24G;
	else
		evt->uBand = MAP_BAND_5G;

#ifdef CONFIG_80211N_HT
	/*AP HT Capabilities*/
	if (ht_cap_ie) {
		evt->tHtCap.TxStreamNum = rtw_ht_cap_get_tx_nss(ht_cap_ie + 2);
		evt->tHtCap.RxStreamNum = rtw_ht_cap_get_rx_nss(ht_cap_ie + 2);
		evt->tHtCap.SgiFor20M = GET_HT_CAP_ELE_SHORT_GI20M(ht_cap_ie + 2);
		evt->tHtCap.SgiFor40M = GET_HT_CAP_ELE_SHORT_GI40M(ht_cap_ie + 2);
		evt->tHtCap.HtFor40M = GET_HT_CAP_ELE_CHL_WIDTH(ht_cap_ie + 2);
	}
#endif

#ifdef CONFIG_80211AC_VHT
	/*AP VHT Capabilities*/
	if (vht_cap_ie) {
		evt->u16VhtTxMcs = RTW_GET_LE16(GET_VHT_CAPABILITY_ELE_TX_MCS(vht_cap_ie + 2));
		evt->u16VhtRxMcs = RTW_GET_LE16(GET_VHT_CAPABILITY_ELE_RX_MCS(vht_cap_ie + 2));
		evt->tVhtCap.TxStreamNum = rtw_vht_mcsmap_to_nss(GET_VHT_CAPABILITY_ELE_TX_MCS(vht_cap_ie + 2));
		evt->tVhtCap.RxStreamNum = rtw_vht_mcsmap_to_nss(GET_VHT_CAPABILITY_ELE_RX_MCS(vht_cap_ie + 2));
		evt->tVhtCap.SgiFor80M = GET_VHT_CAPABILITY_ELE_SHORT_GI80M(vht_cap_ie + 2);
		evt->tVhtCap.SgiFor160M = GET_VHT_CAPABILITY_ELE_SHORT_GI160M(vht_cap_ie + 2);
		evt->tVhtCap.VhtForDual80M = GET_VHT_CAPABILITY_ELE_CHL_WIDTH(vht_cap_ie + 2) >= 2 ? 1 : 0;
		evt->tVhtCap.VhtFor160M = GET_VHT_CAPABILITY_ELE_CHL_WIDTH(vht_cap_ie + 2) ? 1 : 0;
		evt->tVhtCap.SuBeamFormer = GET_VHT_CAPABILITY_ELE_SU_BFER(vht_cap_ie + 2);
		evt->tVhtCap.MuBeamFormer = GET_VHT_CAPABILITY_ELE_MU_BFEE(vht_cap_ie + 2);
	}
#endif

    /* TODO: AP HE Capabilities*/

exit:
	nl_event->type = EV_WLAN_MULTIAP_BSS_STATUS_REPORT;
	nl_event->msg = evt;
	nl_event->msg_len = sizeof(*evt);
}

#if DBG_PLATFORM_CMAP_INTFS
static void platform_cmap_intfs_nl_bss_report_info_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_BSS_METRICS_RESP *evt = (T_MULTI_AP_BSS_METRICS_RESP *)msg;
	RTW_INFO("%s\n"
		 "uIfIndex:%u, mBssid:"MAC_FMT", u8Channel:%u\n"
		 "u16AssocStaNum:%u, u8ChanUtil:%u, iChanNoise:%d\n",
		 __func__,
		 evt->uIfIndex, MAC_ARG(evt->mBssid), evt->u8Channel,
		 evt->u16AssocStaNum, evt->u8ChanUtil, evt->iChanNoise);
}

static void platform_cmap_intfs_nl_sta_report_info_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_STA_ASSOC_METRICS_RESP *evt = (T_MULTI_AP_STA_ASSOC_METRICS_RESP *)msg;
	RTW_INFO("%s\n"
		 "uIfIndex:%u, mBssid:"MAC_FMT", mStaMac:"MAC_FMT"\n"
		 "uBytesSent:%u, uBytesRecv:%u, uPktsSent:%u, uPktsRecv:%u\n"
		 "uPktsTxError:%u, uPktsRxError:%u, uRetransCnt:%u\n"
		 "iRssi:%d, uPhyTxRate:%u, uPhyRxRate:%u, uAssocRate:%u\n",
		 __func__,
		 evt->uIfIndex, MAC_ARG(evt->mBssid), MAC_ARG(evt->mStaMac),
		 evt->uBytesSent, evt->uBytesRecv, evt->uPktsSent, evt->uPktsRecv,
		 evt->uPktsTxError, evt->uPktsRxError, evt->uRetransCnt,
		 evt->iRssi, evt->uPhyTxRate, evt->uPhyRxRate, evt->uAssocRate);
}

static void platform_cmap_intfs_nl_unassoc_sta_report_info_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_STA_UNASSOC_METRICS_RESP *evt = (T_MULTI_AP_STA_UNASSOC_METRICS_RESP *)msg;
	int i;

	RTW_INFO("%s\n"
		 "uIfIndex:%u, mBssid:"MAC_FMT", u8StaNum:%u\n",
		 __func__, evt->uIfIndex, MAC_ARG(evt->mBssid), evt->u8StaNum);
	for (i = 0; i < evt->u8StaNum; i++)
		RTW_INFO("[%d] mStaMac:"MAC_FMT", uTime:%u, iRssi:%d, u8Channel:%u\n",
			 i, MAC_ARG(evt->tMetrics[i].mStaMac), evt->tMetrics[i].uTime,
			 evt->tMetrics[i].iRssi, evt->tMetrics[i].u8Channel);
}

static void platform_cmap_intfs_nl_beacon_report_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_BEACON_METRICS_RESP *evt = (T_MULTI_AP_BEACON_METRICS_RESP *)msg;

	RTW_INFO("%s\n"
		 "mStaMac:"MAC_FMT", u8ElemNum:%u, uElemLen:%u\n",
		 __func__, MAC_ARG(evt->mStaMac), evt->u8ElemNum, evt->uElemLen);
	RTW_DUMP_SEL(RTW_DBGDUMP, evt->uElem, evt->uElemLen);
}

static void platform_cmap_intfs_nl_btm_resp_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_STA_STEERING_REPORT *evt = (T_MULTI_AP_STA_STEERING_REPORT *)msg;
	T_NEIGHBOR_AP *nb_ap = NULL;
	u8 i;
	RTW_INFO("%s\n"
		 "mStaMac:"MAC_FMT", mBssid:"MAC_FMT", u8Status:%hhu\n"
		 "mDestBssid:"MAC_FMT"\n",
		 __func__, MAC_ARG(evt->mStaMac), MAC_ARG(evt->mBssid),
		 evt->u8Status, MAC_ARG(evt->mDestBssid));

	if (evt->tCandidateList.uNum == 0 || evt->u8Status != 6)
		return;

	RTW_INFO("%s\nNeighbor report provided\n", __func__);
	for (i = 0; i < evt->tCandidateList.uNum; ++i) {
		nb_ap = &evt->tCandidateList.tAp[i];
		RTW_INFO("mBssid:"MAC_FMT", u8OpClass:%hhu, u8Chan: %hhu\n"
			 "bHt: %d, bVht: %d, u8Pref: %hhu, szSsid: %s\n",
			 MAC_ARG(nb_ap->mBssid), nb_ap->u8OpClass, nb_ap->u8Chan,
			 nb_ap->bHt, nb_ap->bVht, nb_ap->u8Pref, nb_ap->szSsid);
	}

}

static void platform_cmap_intfs_nl_sta_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_STA_EVENT_NOTIFY *evt = (T_MULTI_AP_STA_EVENT_NOTIFY *)msg;

	RTW_INFO("%s\n"
		"mStaMac:"MAC_FMT", mBssid:"MAC_FMT", u8Status:%u, uCapLen:%u\n"
		, __func__
		, MAC_ARG(evt->mStaMac), MAC_ARG(evt->mBssid), evt->u8Status, evt->uCapLen
	);

	if (msg_len - sizeof(*evt))
		RTW_DUMP_SEL(RTW_DBGDUMP, evt->u8Cap, msg_len - sizeof(*evt));
}

static void platform_cmap_nl_bss_status_event_dump(void *msg, u32 msg_len)
{
	T_MULTI_AP_BSS_STATUS_REPORT *evt = (T_MULTI_AP_BSS_STATUS_REPORT *)msg;

	RTW_INFO("%s\n"
		"uIfIndex:%u, mBssid:"MAC_FMT", uStatus:%u\n"
		"u8Channel:%u, u8OperClass:%u, u8Txpower:%u, uBand:%u\n"
		"tHtCap.TxStreamNum:%u, RxStreamNum:%u, SgiFor20M:%u, SgiFor40M:%u, HtFor40M:%u\n"
		"u16VhtTxMcs:0x%04x, u16VhtRxMcs:0x%04x\n"
		"tVhtCap.TxStreamNum:%u, RxStreamNum:%u, SgiFor80M:%u, SgiFor160M:%u\n"
		"tVhtCap.VhtForDual80M:%u, VhtFor160M:%u, SuBeamFormer:%u, MuBeamFormer:%u\n"
		, __func__
		, evt->uIfIndex, MAC_ARG(evt->mBssid), evt->uStatus
		, evt->u8Channel, evt->u8OperClass, evt->u8Txpower, evt->uBand
		, evt->tHtCap.TxStreamNum
		, evt->tHtCap.RxStreamNum
		, evt->tHtCap.SgiFor20M
		, evt->tHtCap.SgiFor40M
		, evt->tHtCap.HtFor40M
		, evt->u16VhtTxMcs
		, evt->u16VhtRxMcs
		, evt->tVhtCap.TxStreamNum
		, evt->tVhtCap.RxStreamNum
		, evt->tVhtCap.SgiFor80M
		, evt->tVhtCap.SgiFor160M
		, evt->tVhtCap.VhtForDual80M
		, evt->tVhtCap.VhtFor160M
		, evt->tVhtCap.SuBeamFormer
		, evt->tVhtCap.MuBeamFormer
	);
}
#endif /* DBG_PLATFORM_CMAP_INTFS */

struct cmap_intfs_ops_t platform_cmap_intfs_ops = {
	.ioctl_cmd_hdl = platform_cmap_ioctl_cmd_hdl,
	.nl_type = 25,
	.nl_group = 5,
	.nl_bss_report_info_event = platform_cmap_intfs_nl_bss_report_info_event,
	.nl_sta_report_info_event = platform_cmap_intfs_nl_sta_report_info_event,
	.nl_unassoc_sta_report_info_event = platform_cmap_intfs_nl_unassoc_sta_report_info_event,
	.nl_beacon_report_event = platform_cmap_intfs_nl_beacon_report_event,
	.nl_btm_resp_event = platform_cmap_intfs_nl_btm_resp,
	.nl_sta_event = platform_cmap_intfs_nl_sta_event,
	.nl_bss_status_event = platform_cmap_nl_bss_status_event,

#if DBG_PLATFORM_CMAP_INTFS
	.nl_bss_report_info_event_dump = platform_cmap_intfs_nl_bss_report_info_event_dump,
	.nl_sta_report_info_event_dump = platform_cmap_intfs_nl_sta_report_info_event_dump,
	.nl_unassoc_sta_report_info_event_dump = platform_cmap_intfs_nl_unassoc_sta_report_info_event_dump,
	.nl_beacon_report_event_dump = platform_cmap_intfs_nl_beacon_report_event_dump,
	.nl_btm_resp_event_dump = platform_cmap_intfs_nl_btm_resp_event_dump,
	.nl_sta_event_dump = platform_cmap_intfs_nl_sta_event_dump,
	.nl_bss_status_event_dump = platform_cmap_nl_bss_status_event_dump,
#endif
};

