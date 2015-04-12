/*
 * Copyright 2014, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */
#include "wwd_wifi.h"
#include "wiced_management.h"
#include "wiced_network.h"
#include "wwd_network.h"
#include "network/wwd_buffer_interface.h"
#include "RTOS/wwd_rtos_interface.h"
#include "lwip/opt.h"
#include "lwip/mem.h"
#include <string.h>
#include "lwip/init.h"
#include "lwip/tcpip.h"
#include "netif/etharp.h"
#include "lwip/dhcp.h"
#include "lwip/sockets.h"  /* equivalent of <sys/socket.h> */
#include "lwip/inet.h"
#include "wwd_debug.h"
#include "wwd_assert.h"
#include "console.h"
#include "wiced.h"

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

/******************************************************
 *               Variable Definitions
 ******************************************************/

/******************************************************
 *               Function Definitions
 ******************************************************/

/**
 *  Initial thread function - Starts LwIP and calls console_app_main
 *
 *  This function starts up LwIP using the tcpip_init function, then waits on a semaphore
 *  until LwIP indicates that it has started by calling the callback @ref tcpip_init_done.
 *  Once that has been done, the @ref console_app_main function of the app is called.
 *
 * @param arg : Unused - required for conformance to thread function prototype
 */

void application_start( void )
{
    /* Initialise the device */
    wiced_init( );

    /* Run the main application function */
    console_app_main( );
}

int set_ip( int argc, char* argv[] )
{
    struct ip_addr ipaddr, netmask, gw;
    if ( argc < 4 )
    {
        return ERR_UNKNOWN;
    }
    ipaddr.addr  = str_to_ip(argv[1]);
    netmask.addr = str_to_ip(argv[2]);
    gw.addr      = str_to_ip(argv[3]);
    netif_set_addr( &IP_HANDLE(WICED_STA_INTERFACE), &ipaddr, &netmask, &gw );
    return ERR_CMD_OK;
}

void network_print_status( uint8_t interface )
{
    if ( netif_is_up(&IP_HANDLE(interface)) )
    {
        WPRINT_APP_INFO( ( "   IP Addr     : %u.%u.%u.%u\n", (unsigned char) ( ( htonl( IP_HANDLE(interface).ip_addr.addr ) >> 24 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).ip_addr.addr ) >> 16 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).ip_addr.addr ) >> 8 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).ip_addr.addr ) >> 0 ) & 0xff ) ) );
        WPRINT_APP_INFO( ( "   Gateway     : %u.%u.%u.%u\n", (unsigned char) ( ( htonl( IP_HANDLE(interface).gw.addr ) >> 24 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).gw.addr ) >> 16 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).gw.addr ) >> 8 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).gw.addr ) >> 0 ) & 0xff ) ) );
        WPRINT_APP_INFO( ( "   Netmask     : %u.%u.%u.%u\n", (unsigned char) ( ( htonl( IP_HANDLE(interface).netmask.addr ) >> 24 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).netmask.addr ) >> 16 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).netmask.addr ) >> 8 ) & 0xff ), (unsigned char) ( ( htonl( IP_HANDLE(interface).netmask.addr ) >> 0 ) & 0xff ) ) );
    }
}

uint32_t host_get_time( void )
{
    return host_rtos_get_time();
}
