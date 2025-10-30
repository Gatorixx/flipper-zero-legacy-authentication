#pragma once
#include <nfc/nfc_device.h>

#include <mfdesfire_types.h>
#include <mfdesfire_config.h>

// #include <mfdesfire_auth_i.h>

typedef void* MfDesAppForDeviceContext;

typedef struct {
    NfcDevice* nfc_device;
    const uint8_t* key;
    const uint8_t* initial_vector;

    BitBuffer* tx_buf;
    // BitBuffer* rx_buf; // Bude potřeba pokud budu chtít logovat nějaký věci

    FuriString* uid; // UID karty 7
    FuriString* sak; // 1
    FuriString* atqa; // 2
    // FuriString* ats; // ATS (Answer To Select) for ISO14443-4A

    MfDesDeviceEventCallback event_callback;
    MfDesAppForDeviceContext app_event_context;

    MfDesSpecificContext* specific_context;
    NfcGenericCallback listener_callback;
} MfDesDevice;

MfDesDevice* mfdes_device_alloc();
void mfdes_device_free(MfDesDevice* device);

void mfdes_set_device_app_context(MfDesDevice* device, MfDesAppForDeviceContext context);

void mfdes_device_set_event_callback(
    MfDesDevice* device,
    MfDesDeviceEventCallback callback,
    MfDesAppForDeviceContext context);

NfcDevice* mfdes_get_nfc_device(const MfDesDevice* device);

NfcGenericCallback mfdes_get_nfc_callback(const MfDesDevice* device);

void device_set_specific_context(
    MfDesDevice* device,
    MfDesListenerStates MfDesListenerStateSelected);

void mfdes_pre_callback(MfDesDevice* instance, MfDesDeviceEventType type);

bool mfdes_load_card_info(MfDesDevice* device, FuriString* path);

void mfdes_load_key_and_iv(MfDesDevice* device, const uint8_t* key, const uint8_t* iv);

void mfdes_init_nfc_device(MfDesDevice* device);
