#pragma once
#include <nfc/protocols/iso14443_4a/iso14443_4a.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_listener.h>
#include <nfc/protocols/iso14443_4a/iso14443_4a_poller.h>
#include <nfc/helpers/iso14443_crc.h>

#include <nfc/nfc_device.h>
#include <mfdesfire_types.h>

// #include <mfdesfire_nfc_device.h>
#include <mbedtls/des.h>
#include <furi_hal_random.h>

#define MFDES_RND_SIZE 8

#define MFDES_SELECT_APPLICATION      0x5A
#define MFDES_LEGACY_AUTHENTICATION   0x0A
#define MFDES_CONTINUE_AUTHENTICATION 0xAF
#define MFDES_READ_DATA               0xBD
#define MFDES_PERMISSION_DENIED       0x9D
#define MFDES_CLASS_REQUEST           0x90
#define MFDES_CLASS_RESPONSE          0x91
#define MFDES_SUCCESS                 0x00
#define MFDES_NEGATIVE_ACK_B2         0xB2
#define MFDES_POSITIVE_ACK_A3         0xA3
#define MFDES_NEGATIVE_ACK_BA         0xBA
#define MFDES_POSITIVE_ACK_AB         0xAB
#define MFDES_PCB_02                  0x02
#define MFDES_PCB_03                  0x03
#define MFDES_neco_neco 0xC2


typedef enum {
    MfDesListenerStateIdle,
    MfDesListenerStateSelected, // Po SELECT (0x5A), čekám AUTH (0x0A)
    MfDesListenerStatePhase1Sent, // Poslal jsem E(RndB) + 0x91 0xAF, čekám druhý rámec
    MfDesListenerStateAuthenticated, // Legacy auth hotová
    MfDesListenerStateError,
} MfDesListenerStates;

typedef struct {
    MfDesListenerStates listener_state;
    // const uint8_t* key;
    uint8_t rndB[8];
    bool authenticated;
    // uint8_t buf[16 * 4];
} MfDesSpecificContext;

#define mfdes_on_done(instance) mfdes_pre_callback(instance, MfDesAuthenticationFinish)

#define mfdes_on_target_lost(instance) mfdes_pre_callback(instance, MfDesTargetLost)

#define mfdes_on_target_detected(instance) mfdes_pre_callback(instance, MfDesTargetDetected)

#define mfdes_on_error(instance) mfdes_pre_callback(instance, MfDesAuthenticationError)

NfcCommand mfdes_listener_callback(NfcGenericEvent event, void* device);

MfDesSpecificContext* mfdes_context_alloc();
void mfdes_context_free(MfDesSpecificContext* context);
