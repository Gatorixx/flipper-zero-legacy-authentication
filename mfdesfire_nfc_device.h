#pragma once
#include <nfc/nfc_device.h>

#include <mfdesfire_types.h>
#include <mfdesfire_config.h>

// typedef void* MfDesAppContext; //No.1

typedef struct {
    NfcDevice* nfc_device;
    uint8_t* key;
    uint8_t* initial_vector;

    BitBuffer* tx_buf;
    // BitBuffer* rx_buf; // Bude potřeba pokud budu chtít logovat nějaký věci

    MfDesDeviceEventCallback event_callback;
    MfDesSpecificContext* specific_context;
    NfcGenericCallback listener_callback;
    // MfDesAppContext app_context; //No.1
} MfDesDevice;

MfDesDevice* mfdes_device_alloc(void);
void mfdes_device_free(MfDesDevice* device);

static inline mfdes_device_set_callback(MfDesDevice* device, MfDesDeviceEventCallback callback);

NfcDevice* mfdes_get_nfc_device(const MfDesDevice* device);

NfcGenericCallback mfdes_get_nfc_callback(const MfDesDevice* device);

// void mfdes_device_set_app_context(MfDesDevice device, MfDesAppContext cxt); //No.1