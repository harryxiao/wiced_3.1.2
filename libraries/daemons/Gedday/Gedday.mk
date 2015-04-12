#
# Copyright 2014, Broadcom Corporation
# All Rights Reserved.
#
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#

NAME := Lib_Gedday

ifneq ($(wildcard $(CURDIR)Gedday.$(RTOS).$(NETWORK).$(HOST_ARCH).$(BUILD_TYPE).a),)
$(NAME)_PREBUILT_LIBRARY := Gedday.$(RTOS).$(NETWORK).$(HOST_ARCH).$(BUILD_TYPE).a
else
$(NAME)_SOURCES := gedday.c \
                   text_record.c
endif # ifneq ($(wildcard $(CURDIR)Gedday.$(RTOS).$(NETWORK).$(HOST_ARCH).$(BUILD_TYPE).a),)

GLOBAL_INCLUDES := .

ifeq (NETWORK,LwIP)
GLOBAL_DEFINES += LWIP_AUTOIP=1
endif

$(NAME)_CFLAGS  = $(COMPILER_SPECIFIC_PEDANTIC_CFLAGS)