#
# Copyright 2014, Broadcom Corporation
# All Rights Reserved.
#
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#

ifeq ($(findstring custom.h, $(wildcard $(CURDIR)*.h)), custom.h)

$(NAME)_DEFINES += USE_CUSTOM_COMMANDS


#==============================================================================
# Configuration
#==============================================================================
ALL_TESTS := 1

ifeq (1, $(ALL_TESTS))
MALLINFO	       := 1
PLATFORM_CMD       := 1
THREADS            := 1
TRAFFIC_GENERATION := 1
TRACE              := 0
endif


#==============================================================================
# Defines and sources
#==============================================================================

ifeq (1, $(MALLINFO))
$(NAME)_DEFINES += CONSOLE_ENABLE_MALLINFO
$(NAME)_SOURCES += mallinfo/mallinfo.c
endif

ifeq (1, $(PLATFORM_CMD))
$(NAME)_DEFINES += CONSOLE_ENABLE_PLATFORM_CMD
$(NAME)_SOURCES += platform/platform.c
endif

ifeq (1, $(THREADS))
$(NAME)_DEFINES += CONSOLE_ENABLE_THREADS
$(NAME)_SOURCES += thread/thread.c
endif

ifeq (1, $(TRACE))
$(NAME)_DEFINES += CONSOLE_ENABLE_TRACE
include $(CURDIR)trace/trace.mk
endif

ifeq (1, $(TRAFFIC_GENERATION))
$(NAME)_DEFINES += CONSOLE_ENABLE_TRAFFIC_GENERATION
$(NAME)_SOURCES += traffic_generation/traffic_generation.c
endif


endif