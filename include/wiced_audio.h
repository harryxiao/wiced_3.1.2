/*
 * Copyright 2014, Broadcom Corporation
 * All Rights Reserved.
 *
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 */
#pragma once

#include "wwd_constants.h"
#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************
 *                      Macros
 ******************************************************/

#ifdef DEBUG
#define WICED_AUDIO_DEBUG_PRINT(x)
#define WICED_AUDIO_INFO_PRINT(x)     do { printf x; } while(0)
#else
#define WICED_AUDIO_DEBUG_PRINT(x)
#define WICED_AUDIO_INFO_PRINT(x)
#endif

/******************************************************
 *                    Constants
 ******************************************************/

#define MAX_NUM_AUDIO_DEVICES (3)

/******************************************************
 *                   Enumerations
 ******************************************************/

/**
 * WICED audio output type
 */
typedef enum
{
    SPEAKERS,
    HEADPHONES,
    SPEAKERS_AND_HEADPHONES
} wiced_audio_output_t;

/**
 * WICED audio device channel
 */
typedef enum
{
    WICED_PLAY_CHANNEL,
    WICED_RECORD_CHANNEL
} wiced_audio_device_channel_t;

/**
 * WICED audio event type
 */
typedef enum
{
    WICED_AUDIO_PERIOD_ELAPSED = 0,
    WICED_AUDIO_UNDERRUN       = 1,
} wiced_audio_platform_event_t;

/******************************************************
 *                 Type Definitions
 ******************************************************/

typedef void (*wiced_audio_data_provider_t)( uint8_t** buffer, uint16_t* size, void* context);
typedef struct wiced_audio_session_t* wiced_audio_session_ref;

/******************************************************
 *                    Structures
 ******************************************************/

/**
 * WICED audio configuration
 */
typedef struct
{
    uint32_t sample_rate;
    uint8_t  bits_per_sample;
    uint8_t  channels;
    uint8_t  volume;
} wiced_audio_config_t;

/**
 * WICED audio device interface
 * @note : Only used by device drivers
 */
typedef struct
{
    const char*    name;
    void*          audio_device_driver_specific;
    wiced_result_t (*audio_device_init)           ( void* device_data );
    wiced_result_t (*audio_device_deinit)         ( void* device_data );
    wiced_result_t (*audio_device_port)           ( void* device_data, wiced_i2s_t* port );
    wiced_result_t (*audio_device_configure)      ( void* device_data, wiced_audio_config_t* config, uint32_t* mclk );
    wiced_result_t (*audio_device_start_streaming)( void* device_data );
    wiced_result_t (*audio_device_pause)          ( void* device_data );
    wiced_result_t (*audio_device_resume)         ( void* device_data );
    wiced_result_t (*audio_device_set_volume)     ( void* device_data, double decibles );
    wiced_result_t (*audio_device_set_treble)     ( void* device_data, uint8_t percentage );
    wiced_result_t (*audio_device_set_bass)       ( void* device_data, uint8_t percentage );
    wiced_result_t (*audio_device_get_volume_range) ( void *device_data, double *min_volume_decibels, double *max_volume_decibels);
} wiced_audio_device_interface_t;

/**
 * WICED audio device class
 */
typedef struct
{
    wiced_audio_device_interface_t audio_devices[MAX_NUM_AUDIO_DEVICES];
    int                            device_count;
} audio_device_class_t;

/******************************************************
 *                 Global Variables
 ******************************************************/

/******************************************************
 *               Function Declarations
 ******************************************************/

wiced_result_t wiced_audio_init                        ( const char* device_name, wiced_audio_session_ref* sh, uint16_t period_size );
wiced_result_t wiced_audio_configure                   ( wiced_audio_session_ref sh, wiced_audio_config_t* config );
wiced_result_t wiced_audio_create_buffer               ( wiced_audio_session_ref sh, uint16_t size, uint8_t* buffer_ptr, void*(*allocator)(uint16_t size));
wiced_result_t wiced_audio_set_volume                  ( wiced_audio_session_ref sh, double volume_in_db );
wiced_result_t wiced_audio_get_volume_range    ( wiced_audio_session_ref sh, double *min_volume_in_db, double *max_volume_in_db );
wiced_result_t wiced_audio_deinit                      ( wiced_audio_session_ref sh );
wiced_result_t wiced_audio_get_buffer                  ( wiced_audio_session_ref sh, uint8_t** ptr, uint16_t* size);
wiced_result_t wiced_audio_get_current_hw_pointer      ( wiced_audio_session_ref sh, uint32_t* hw_pointer);
wiced_result_t wiced_audio_start                       ( wiced_audio_session_ref sh );
wiced_result_t wiced_audio_stop                        ( wiced_audio_session_ref sh );
wiced_result_t wiced_audio_release_buffer              ( wiced_audio_session_ref sh, uint16_t size);
wiced_result_t wiced_audio_buffer_platform_event       ( wiced_audio_session_ref sh, wiced_audio_platform_event_t event);
uint16_t       wiced_audio_buffer_platform_get_periods ( wiced_audio_session_ref sh );
wiced_result_t wiced_audio_wait_buffer                 ( wiced_audio_session_ref sh, uint16_t size, uint32_t timeout );
wiced_result_t wiced_audio_get_current_buffer_weight   ( wiced_audio_session_ref sh, uint32_t* weight );

/* Returns the latency of the audio system in audio frames */
wiced_result_t wiced_audio_get_latency                 ( wiced_audio_session_ref sh, uint32_t* latency );
wiced_result_t wiced_register_audio_device             ( const char* name, wiced_audio_device_interface_t* interface );


#ifdef __cplusplus
} /* extern "C" */
#endif
