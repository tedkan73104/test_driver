/******************************************************************************
 *
 * Copyright(c) 2009-2010 - 2017 Realtek Corporation.
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

#ifndef __CUSTOM_MULTIAP_INTFS_00_H__
#define __CUSTOM_MULTIAP_INTFS_00_H__

#define BOOL bool
#define CHAR char
#define UINT8 u8
#define UINT16 u16
#define UINT32 u32
#define INT32 s32
typedef u8 MAC_ADDR[6];

#ifdef CONFIG_BIG_ENDIAN
#define WLAN_BIG_ENDIAN 1
#else
#define WLAN_BIG_ENDIAN 0
#endif

#define	EV_WLAN_MULTIAP_STA_TOPOLOGY_NOTIFY				0xA258
#define	EV_WLAN_MULTIAP_BSS_METRICS_RESPONSE			0xA259
#define	EV_WLAN_MULTIAP_ASSOC_STA_METRICS_RESPONSE		0xA25A
#define	EV_WLAN_MULTIAP_UNASSOC_STA_METRICS_RESPONSE	0xA25B
#define	EV_WLAN_MULTIAP_BEACON_METRICS_RESPONSE			0xA25C
#define	EV_WLAN_MULTIAP_STEERING_BTM_REPORT				0xA25D
#define	EV_WLAN_MULTIAP_BSS_STATUS_REPORT				0xA25F

#define ELEM_LEN_MAX 1024

typedef struct
{
	UINT32 uIfIndex;
	MAC_ADDR mBssid;
	UINT8 u8Channel;
	UINT16 u16AssocStaNum;
	UINT8 u8ChanUtil;
	INT32 iChanNoise;
} T_MULTI_AP_BSS_METRICS_RESP;

typedef struct
{
	UINT32 uIfIndex;
	MAC_ADDR mBssid;
	MAC_ADDR mStaMac;
	UINT32 uBytesSent;
	UINT32 uBytesRecv;
	UINT32 uPktsSent;
	UINT32 uPktsRecv;
	UINT32 uPktsTxError;
	UINT32 uPktsRxError;
	UINT32 uRetransCnt;
	INT32 iRssi;
	UINT32 uPhyTxRate;
	UINT32 uPhyRxRate;
	UINT32 uAssocRate;
} T_MULTI_AP_STA_ASSOC_METRICS_RESP;

typedef struct
{
	MAC_ADDR mStaMac;
	UINT32 uTime;
	INT32 iRssi;
	UINT8 u8Channel;
} T_MULTI_AP_STA_UNASSOC_METRICS;

typedef struct
{
	UINT32 uIfIndex;
	MAC_ADDR mBssid;
	UINT8 u8StaNum;
	T_MULTI_AP_STA_UNASSOC_METRICS tMetrics[CMAP_UNASSOC_METRICS_STA_MAX];
} T_MULTI_AP_STA_UNASSOC_METRICS_RESP;

typedef struct
{
	MAC_ADDR mStaMac;
	UINT8 u8ElemNum;
	UINT32 uElemLen;
	UINT8 uElem[ELEM_LEN_MAX];
} T_MULTI_AP_BEACON_METRICS_RESP;

typedef struct
{
	MAC_ADDR mBssid;
	UINT8    u8OpClass;
	UINT8    u8Chan;
	BOOL     bHt;
	BOOL     bVht;
	UINT8    u8Pref;
	CHAR     szSsid[34];
} T_NEIGHBOR_AP;

typedef struct
{
	UINT32         uNum;
	T_NEIGHBOR_AP  tAp[12];
} T_NEIGHBOR_LIST;

typedef struct
{
	MAC_ADDR        mStaMac;
	MAC_ADDR        mBssid;
	UINT8           u8Status;
	MAC_ADDR        mDestBssid;
	T_NEIGHBOR_LIST tCandidateList;
} T_MULTI_AP_STA_STEERING_REPORT;

typedef struct
{
	MAC_ADDR			mStaMac;
	MAC_ADDR			mBssid;

	/*0:disconnected, 1:connected */
	UINT8				u8Status;

	UINT32				uCapLen;
	UINT8				u8Cap[0];
} T_MULTI_AP_STA_EVENT_NOTIFY;

#define MAP_BAND_24G_INDEX  0
#define MAP_BAND_5G_INDEX   1
#define MAP_BAND_24G  (1 << MAP_BAND_24G_INDEX)
#define MAP_BAND_5G   (1 << MAP_BAND_5G_INDEX)

/* Refer to Multi-AP spec 17.2.8 AP HT Capabilities TLV format
bits 7-6    Maximum number of supported Tx spatial streams.
    00: 1 Tx spatial stream
    01: 2 Tx spatial stream
    10: 3 Tx spatial stream
    11: 4 Tx spatial stream

bits 5-4    Maximum number of supported Rx spatial streams.
    00: 1 Rx spatial stream
    01: 2 Rx spatial stream
    10: 3 Rx spatial stream
    11: 4 Rx spatial stream

bit 3       Short GI Support for 20 MHz.
    0: Not supported
    1: Supported

bit 2       Short GI Support for 40 MHz.
    0: Not supported
    1: Supported

bit 1       HT support for 40MHz.
0: Not supported
1: Supported

bit 0       Reserved.
*/
typedef struct
{
	union
	{
		struct
		{
#if WLAN_BIG_ENDIAN
			UINT8	TxStreamNum  : 2,  /*Maximum number of supported Tx spatial streams.*/
					RxStreamNum  : 2,  /*Maximum number of supported Rx spatial streams.*/
					SgiFor20M    : 1,  /*Short GI Support for 20 MHz.*/
					SgiFor40M    : 1,  /*Short GI Support for 40 MHz.*/
					HtFor40M     : 1,  /*HT support for 40MHz.*/
					Reserved     : 1;  /*Reserved.*/
#else
			UINT8	Reserved     : 1,
					HtFor40M     : 1,
					SgiFor40M    : 1,
					SgiFor20M    : 1,
					RxStreamNum  : 2,
					TxStreamNum  : 2;
#endif
		};
		UINT8   u8Cap;
	};
} __attribute__((__packed__)) T_AP_HTCAP;

/* Refer to Multi-AP spec 17.2.9 AP VHT Capabilities TLV format
bits 7-5        Maximum number of supported Tx spatial streams.
    000: 1 Tx spatial stream
    001: 2 Tx spatial stream
    010: 3 Tx spatial stream
    011: 4 Tx spatial stream
    100: 5 Tx spatial stream
    101: 6 Tx spatial stream
    110: 7 Tx spatial stream
    111: 8 Tx spatial stream

bits 4-2        Maximum number of supported Rx spatial streams.
    000: 1 Rx spatial stream
    001: 2 Rx spatial stream
    010: 3 Rx spatial stream
    011: 4 Rx spatial stream
    100: 5 Rx spatial stream
    101: 6 Rx spatial stream
    110: 7 Rx spatial stream
    111: 8 Rx spatial stream

bit 1       Short GI support for 80 MHz.
    0: Not supported
    1: Supported

bit 0       Short GI support for 160 MHz and 80+80 MHz.
    0: Not supported
    1: Supported

bit 7       VHT support for 80+80 MHz.
    0: Not supported
    1: Supported

bit 6       VHT support for 160 MHz.
    0: Not supported
    1: Supported

bit 5   SU beamformer capable.
    0: Not supported
    1: Supported

bit 4       MU beamformer capable.
    0: Not supported
    1: Supported

bits 3-0    Reserved.
*/
typedef struct
{
	union
	{
		struct
		{
#if WLAN_BIG_ENDIAN
			UINT16	TxStreamNum  : 3,  /*Maximum number of supported Tx spatial streams.*/
					RxStreamNum  : 3,  /*Maximum number of supported Rx spatial streams.*/
					SgiFor80M    : 1,  /*Short GI support for 80 MHz.*/
					SgiFor160M   : 1,  /*Short GI support for 160 MHz and 80+80 MHz.*/
					VhtForDual80M: 1,  /*VHT support for 80+80 MHz.*/
					VhtFor160M   : 1,  /*VHT support for 160 MHz.*/
					SuBeamFormer : 1,  /*SU beamformer capable.*/
					MuBeamFormer : 1,  /*MU beamformer capable.*/
					Reserved     : 4;  /*Reserved.*/
#else
			UINT16	Reserved     : 4,
					MuBeamFormer : 1,
					SuBeamFormer : 1,
					VhtFor160M   : 1,
					VhtForDual80M: 1,
					SgiFor160M   : 1,
					SgiFor80M    : 1,
					RxStreamNum  : 3,
					TxStreamNum  : 3;
#endif
		};
		UINT16  u16Cap;
	};
} __attribute__((__packed__)) T_AP_VHTCAP;

/* Refer to IEEE Std. 802.11-2016 spec, Figure 9-562¡XRx VHT-MCS Map and Tx VHT-MCS Map subfields*/
/*
The Max VHT-MCS For n SS subfield (where n = 1, ..., 8) is encoded as follows:
¡X 0 indicates support for VHT-MCS 0-7 for n spatial streams
¡X 1 indicates support for VHT-MCS 0-8 for n spatial streams
¡X 2 indicates support for VHT-MCS 0-9 for n spatial streams
¡X 3 indicates that n spatial streams is not supported
*/
typedef struct
{
	union
	{
		struct
		{
#if WLAN_BIG_ENDIAN
			UINT16	McsFor8Ss : 2,
					McsFor7Ss : 2,
					McsFor6Ss : 2,
					McsFor5Ss : 2,
					McsFor4Ss : 2,
					McsFor3Ss : 2,
					McsFor2Ss : 2,
					McsFor1Ss : 2;
#else
			UINT16	McsFor1Ss : 2,
					McsFor2Ss : 2,
					McsFor3Ss : 2,
					McsFor4Ss : 2,
					McsFor5Ss : 2,
					McsFor6Ss : 2,
					McsFor7Ss : 2,
					McsFor8Ss : 2;
#endif
		};
		UINT16  u16Data;
	};

} __attribute__((__packed__)) T_AP_VHTMCS;

/* Refer to Multi-AP spec 17.2.10 AP HE Capabilities TLV format
bits 7-5    Maximum number of supported Tx spatial streams.
    000: 1 Tx spatial stream
    001: 2 Tx spatial stream
    010: 3 Tx spatial stream
    011: 4 Tx spatial stream
    100: 5 Tx spatial stream
    101: 6 Tx spatial stream
    110: 7 Tx spatial stream
    111: 8 Tx spatial stream

bits 4-2    Maximum number of supported Rx spatial streams.
    000: 1 Rx spatial stream
    001: 2 Rx spatial stream
    010: 3 Rx spatial stream
    011: 4 Rx spatial stream
    100: 5 Rx spatial stream
    101: 6 Rx spatial stream
    110: 7 Rx spatial stream
    111: 8 Rx spatial stream

bit 1       HE support for 80+80 MHz.
    0: Not supported
    1: Supported

bit 0       HE support for 160 MHz.
    0: Not supported
    1: Supported

bit 7       SU beamformer capable.
    0: Not supported
    1: Supported

bit 6       MU beamformer capable.
    0: Not supported
    1: Supported

bit 5       UL MU-MIMO capable.
    0: Not supported
    1: Supported

bit 4       UL MU-MIMO + OFDMA capable.
    0: Not supported
    1: Supported

bit 3       DL MU-MIMO + OFDMA capable.
    0: Not supported
    1: Supported

bit 2       UL OFDMA capable.
    0: Not supported
    1: Supported

bit 1       DL OFDMA capable.
    0: Not supported
    1: Supported

bit 0       Reserved.
*/
typedef struct
{
	union
	{
		struct
		{
#if WLAN_BIG_ENDIAN
			UINT16	TxStreamNum  : 3,  /*Maximum number of supported Tx spatial streams.*/
					RxStreamNum  : 3,  /*Maximum number of supported Rx spatial streams.*/
					HeForDual80M : 1,  /*HE support for 80+80 MHz.*/
					HeFor160M    : 1,  /*HE support for 160 MHz.*/
					SuBeamFormer : 1,  /*SU beamformer capable.*/
					MuBeamFormer : 1,  /*MU beamformer capable.*/
					UlMuMimo     : 1,  /*UL MU-MIMO capable.*/
					UlMuMimoOfdma: 1,  /*UL MU-MIMO + OFDMA capable.*/
					DlMuMimoOfdma: 1,  /*DL MU-MIMO + OFDMA capable.*/
					UlOfdma      : 1,  /*UL OFDMA capable.*/
					DlOfdma      : 1,  /*DL OFDMA capable.*/
					Reserved     : 1;  /*Reserved.*/
#else
			UINT16	Reserved     : 1,
					DlOfdma      : 1,
					UlOfdma      : 1,
					DlMuMimoOfdma: 1,
					UlMuMimoOfdma: 1,
					UlMuMimo     : 1,
					MuBeamFormer : 1,
					SuBeamFormer : 1,
					HeFor160M    : 1,
					HeForDual80M : 1,
					RxStreamNum  : 3,
					TxStreamNum  : 3;
#endif
		};
		UINT16  u16Cap;
	};
} __attribute__((__packed__)) T_AP_HECAP;

typedef struct
{
	UINT32			uIfIndex;
	MAC_ADDR		mBssid;

	/*BSS status¡Gdown, 1: up*/
	UINT32			uStatus;

	UINT8			u8Channel;
	UINT8			u8OperClass;
	UINT8			u8Txpower; /* dBm */

	/* 2.4G: MAP_BAND_24G  5G: MAP_BAND_5G */
	UINT32			uBand;

	/*AP HT Capabilities*/
	T_AP_HTCAP		tHtCap;

	/*AP VHT Capabilities*/
	UINT16			u16VhtTxMcs;
	UINT16			u16VhtRxMcs;
	T_AP_VHTCAP		tVhtCap;

	/*AP HE Capabilities*/
	UINT8			u8HeMcsNum;
	UINT8			u8HeMcs[16];
	T_AP_HECAP		tHeCap;
} T_MULTI_AP_BSS_STATUS_REPORT;

#endif /* __CUSTOM_MULTIAP_INTFS_00_H__ */
