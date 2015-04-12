/*
 * Copyright 2014, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */
#ifndef INCLUDED_SOC_4390_WWD_BUS_PROTOCOL_H
#define INCLUDED_SOC_4390_WWD_BUS_PROTOCOL_H


#include "wwd_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************
 *             Constants
 ******************************************************/

/******************************************************
 *             Structures
 ******************************************************/


#pragma pack(1)

typedef struct
{
    char  dma_descriptor[8];
} wwd_bus_header_t;

#pragma pack()

#define WWD_BUS_HAS_HEADER

#define WWD_BUS_HEADER_SIZE               ( sizeof(wwd_bus_header_t) )

#define WWD_BUS_USE_STATUS_REPORT_SCHEME  ( 1 == 1 ) /* read the section "Interrupt and Status logic" in TWIKI */

/* Reserved length for SDPCM header, generally the larger of the TX and RX headers */
#define WWD_SDPCM_HEADER_RESERVED_LENGTH  ( 22 )

/* SDPCM transmit header length */
#define WWD_SDPCM_HEADER_TX_LENGTH        ( WWD_SDPCM_HEADER_RESERVED_LENGTH - 4 )

/* SDPCM receive header length includes 4 bytes data offset prior to the start of the payload */
#define WWD_SDPCM_HEADER_RX_LENGTH        ( WWD_SDPCM_HEADER_RESERVED_LENGTH )

/******************************************************
 *             Function declarations
 ******************************************************/


/******************************************************
 *             Global variables
 ******************************************************/

#ifdef __cplusplus
} /*extern "C" */
#endif

#endif /* ifndef INCLUDED_SOC_4390_WWD_BUS_PROTOCOL_H */
