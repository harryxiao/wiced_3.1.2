/*
 * Copyright 2014, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */

/** @file
 *
 * Bluetooth Audio AVDT Sink Application
 *
 * This application demonstrates how to use the Bluetooth Application Layer (BTA)
 *  APIs
 *
 * The application demonstrates the following features ...
 *  - Bluetooth intialization
 *  - AVDT sink
 *  - SBC Decoding
 *  - Audio playback
 *
 *
 * Application Operation
 * The app runs in a thread, the entry point is application_start()
 *
 *
 *    Usage
 *        On startup device will be discoverable and connectable,
 *        allowing a BT audio source to connect and streaming
 *        audio.
 *
 *    Notes
 *        Currently only supports 44.1kHz audio s
 *
 */
#include <stdlib.h>
#include "wiced.h"
#include "bt_audio.h"
#include "platform_audio.h"

/******************************************************
 *                      Macros
 ******************************************************/

/******************************************************
 *                    Constants
 ******************************************************/

/******************************************************
 *                   Enumerations
 ******************************************************/

/******************************************************
 *                 Type Definitions
 ******************************************************/

/******************************************************
 *                    Structures
 ******************************************************/

/******************************************************
 *               Static Function Declarations
 ******************************************************/

static void bt_event_callback( bt_audio_event_t event, void* data );

/******************************************************
 *               Variable Definitions
 ******************************************************/

/******************************************************
 *               Function Definitions
 ******************************************************/

/*******************************************************************************
 **
 ** Function         application_start
 **
 ** Description      Application entry point for Wiced framework
 **
 ** Returns          nothing
 **
 *******************************************************************************/
void application_start( )
{
    wiced_init( );
    platform_init_audio( );

    /* Initialize BT stack and profiles */
    bt_audio_init( bt_event_callback );
}

static void bt_event_callback( bt_audio_event_t event, void* data )
{
    switch ( event )
    {
        case BT_AUDIO_EVENT_ENABLE:
            WPRINT_LIB_INFO ( ("bt_event_callback: BT enabled\n") );
            bt_audio_get_device_info();
            break;

        case BT_AUDIO_EVENT_DEVICE_INFO:
        {
            bt_audio_device_info_t* p_data = (bt_audio_device_info_t*)data;
            WPRINT_LIB_INFO( ("bt_event_callback: Dev Info Name: %s Mode: %d\n", p_data->bd_name.name, p_data->scan_mode) );
            WPRINT_LIB_INFO ( ("bt_event_callback: Dev Info Addr [0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n",
                              p_data->bd_addr.address[0], p_data->bd_addr.address[1],
                              p_data->bd_addr.address[2], p_data->bd_addr.address[3],
                              p_data->bd_addr.address[4], p_data->bd_addr.address[5]) );
            bt_audio_set_scan_mode(BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE);
        } break;

        case BT_AUDIO_EVENT_CONNECT:
        {
            bt_audio_connection_event_data_t* p_data = (bt_audio_connection_event_data_t*)data;
            if ( p_data->status == WICED_SUCCESS )
            {
                WPRINT_LIB_INFO ( ("bt_event_callback: Connected to the phone [0x%x:0x%x:0x%x:0x%x:0x%x:0x%x\n",
                                  p_data->bd_addr.address[0], p_data->bd_addr.address[1],
                                  p_data->bd_addr.address[2], p_data->bd_addr.address[3],
                                  p_data->bd_addr.address[4], p_data->bd_addr.address[5]) );
            }
            else
            {
                WPRINT_LIB_INFO ( ("bt_event_callback: Connection to phone failed\n") );
            }
        } break;

        case BT_AUDIO_EVENT_DISCONNECT:
        {
            bt_audio_disconnection_event_data_t* p_data = (bt_audio_disconnection_event_data_t*)data;
            WPRINT_LIB_INFO( ("bt_event_callback: Disconnected from the phone\n") );
            if (p_data->reason == BT_AUDIO_DISCONNECT_REASON_LINK_LOSS)
            {
                 WPRINT_LIB_INFO( ("Disconnection due to link-loss. Re-connecting\n") );
                 bt_audio_connect( NULL );
            }

        } break;

        case BT_AUDIO_EVENT_DISABLE:        WPRINT_LIB_INFO( ("bt_event_callback: BT disabled\n") );                    break;

        case BT_AUDIO_EVENT_STREAM_START:   WPRINT_LIB_INFO( ("bt_event_callback: Music streaming from the phone\n") ); break;
        case BT_AUDIO_EVENT_STREAM_SUSPEND: WPRINT_LIB_INFO( ("bt_event_callback: Music suspended from the phone\n") ); break;

        default: break;
    }
}
