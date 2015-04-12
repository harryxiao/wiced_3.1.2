/*
 * Copyright 2014, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */
#ifndef INCLUDED_TRAFFIC_GENERATION_H_
#define INCLUDED_TRAFFIC_GENERATION_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONSOLE_ENABLE_TRAFFIC_GENERATION

extern int traffic_stream_ipv4( int argc, char *argv[] );

#define TRAFFIC_GENERATION_COMMANDS \
    { (char*) "traffic_stream_ipv4", traffic_stream_ipv4,  0, DELIMIT, NULL, (char*) "[-c <destination ip>] [-p <port>] [-u (for udp)] [-l <length>] [-d <duration in seconds>] [-r <rate (pps)>] [-S <type of service>] [-i <interface>]", (char*) "Start a traffic stream."},

#else /* ifdef CONSOLE_ENABLE_TRAFFIC_GENERATION */
#define TRAFFIC_GENERATION_COMMANDS
#endif /* CONSOLE_ENABLE_TRAFFIC_GENERATION */

#ifdef __cplusplus
} /*extern "C" */
#endif

#endif /* ifndef INCLUDED_TRAFFIC_GENERATION_H_ */
