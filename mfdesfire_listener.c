#include "mfdesfire_nfc_device.h"
#include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <furi_hal.h>

#define TAG "DES_Listener"

typedef NfcCommand (*MfDesListenerCommandCallback)(MfDesDevice* device, const uint8_t* data);

typedef struct {
    uint8_t cmd;
    MfDesListenerCommandCallback callback;
} MfDesListenerCommandHandler;

NfcCommand mfdes_listener_select_application_cmd(MfDesDevice* device, const uint8_t* data) {
    UNUSED(data);
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_SUCCESS);
    device_set_specific_context(device, MfDesListenerStateSelected);
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_legacy_authentication_cmd(MfDesDevice* device, const uint8_t* data) {
    UNUSED(data);
    uint8_t rndB[8];
    uint8_t encrypted_rndB[8];
    uint8_t init_vector[8];

    memcpy(
        init_vector,
        device->initial_vector,
        sizeof(init_vector)); // To prevent overwriting the app vector

    furi_hal_random_fill_buf(rndB, sizeof(rndB));
    memcpy(device->specific_context->rndB, rndB, sizeof(rndB));

    // mbedtls_des3_context ctx; //OLD API

    // mbedtls_des3_init(&ctx);

    // int result = mbedtls_des3_set3key_enc(&ctx, device->key);
    // furi_check(result); //Krici z nejakeho duvodu

    // result = mbedtls_des3_crypt_cbc(
    //     &ctx,
    //     MBEDTLS_DES_ENCRYPT,
    //     sizeof(rndB),
    //     init_vector,
    //     rndB, // in
    //     encrypted_rndB); // out

    // mbedtls_des3_free(&ctx); // release memory

    // furi_check(result);

    // NEW WAY =====

    // Use exported 2-key 3DES CBC wrapper (expects 16-byte key K1||K2)
    uint8_t ck[16];
    memcpy(ck, device->key, sizeof(ck)); // if provided key is 24B, this uses K1||K2
    mbedtls_des3_context ctx = {0};
    mf_ultralight_3des_encrypt(&ctx, ck, init_vector, rndB, sizeof(rndB), encrypted_rndB);

    //NEW WAY =====

    bit_buffer_append_bytes(device->tx_buf, encrypted_rndB, sizeof(encrypted_rndB));
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_CONTINUE_AUTHENTICATION);

    device_set_specific_context(device, MfDesListenerStatePhase1Sent);

    return NfcCommandContinue;
}

void mfdes_rotate(uint8_t* dest, const uint8_t* src, MfDesRotation rotation) {
    int8_t direction = (rotation == ROT_LEFT) ? 1 : -1;
    for(uint8_t i = 0; i < MFDES_RND_SIZE; i++) {
        dest[i] =
            src[(i + direction + MFDES_RND_SIZE) % 8]; //Adding size to prevent negative numbers
    }
}

NfcCommand mfdes_listener_continue_authentication(MfDesDevice* device, const uint8_t* data) {
    uint8_t init_vector[8];
    uint8_t decrypted_output[16];
    uint8_t encrypted_rndA[8];

    memcpy(
        init_vector,
        device->initial_vector,
        sizeof(init_vector)); // To prevent overwriting the app vector

    // BitBuffer *bit_buffer_data = bit_buffer_alloc(sizeof(data)); //OLD API
    // bit_buffer_append_bytes(bit_buffer_data, data, sizeof(data));

    uint8_t data_to_decrypt[16];
    // for(uint8_t i = 0; i < 16; i++) {
    //     data_to_decrypt[i] = bit_buffer_get_byte(bit_buffer_data, i + 6);
    // }

    // mbedtls_des3_context ctx;

    // mbedtls_des3_init(&ctx);

    // int result = mbedtls_des3_set3key_dec(&ctx, device->key);

    // furi_check(result);

    // result = mbedtls_des3_crypt_cbc(
    //     &ctx,
    //     MBEDTLS_DES_DECRYPT, // decrypt
    //     sizeof(data_to_decrypt),
    //     init_vector,
    //     data_to_decrypt,    // in
    //     decrypted_output);  // out

    // mbedtls_des3_free(&ctx); // release memory

    // furi_check(result);

    // NEW WAY =====

    memcpy(data_to_decrypt, &data[5], sizeof(data_to_decrypt));
    uint8_t ck[16];
    memcpy(ck, device->key, sizeof(ck));
    mbedtls_des3_context ctx = {0};
    mf_ultralight_3des_decrypt(
        &ctx, ck, init_vector, data_to_decrypt, sizeof(data_to_decrypt), decrypted_output);

    // NEW WAY =====

    uint8_t rndA[8];
    memcpy(rndA, decrypted_output, 8);

    if(!memcmp(device->specific_context->rndB, decrypted_output + MFDES_RND_SIZE, MFDES_RND_SIZE)) {
        //TODO selhala ctecka, Nevim jeste co tady udelat
        // TODO jeste by se to myslim melo zrotovat doprava
    }

    uint8_t rotL_rndA[8];
    // for(uint8_t i = 0; i < 8; i++) {
    //     rotL_rndA[i] = rndA[(i + 1) % 8];
    // }
    mfdes_rotate(rotL_rndA, rndA, ROT_LEFT);

    memset(init_vector, 0, sizeof(init_vector));

    // mbedtls_des3_init(&ctx); //OLD API

    // result = mbedtls_des3_set3key_enc(&ctx, device->key);

    // furi_check(result);

    // result = mbedtls_des3_crypt_cbc(
    //     &ctx,
    //     MBEDTLS_DES_ENCRYPT,
    //     sizeof(rotL_rndA),
    //     init_vector,
    //     rotL_rndA, // in
    //     encrypted_rndA); // out

    // mbedtls_des3_free(&ctx); // release memory

    // furi_check(result);

    // NEW WAY =====

    uint8_t ck2[16];
    memcpy(ck2, device->key, sizeof(ck2));
    mbedtls_des3_context ctx2 = {0};
    mf_ultralight_3des_encrypt(
        &ctx2, ck2, init_vector, rotL_rndA, sizeof(rotL_rndA), encrypted_rndA);

    // NEW WAY =====

    bit_buffer_append_bytes(device->tx_buf, encrypted_rndA, sizeof(encrypted_rndA));
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_SUCCESS);

    device_set_specific_context(device, MfDesListenerStateAuthenticated);

    return NfcCommandContinue;
}

NfcCommand mfdes_listener_read_data(MfDesDevice* device, const uint8_t* data) {
    UNUSED(data);
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_PERMISSION_DENIED);

    return NfcCommandContinue;
}

NfcCommand mfdes_listener_unknown_cmd(MfDesDevice* device, const uint8_t* data) {
    FURI_LOG_D(TAG, "Unknown: %02X %02X", data[0], data[1]);
    bit_buffer_append_byte(device->tx_buf, 0x00);
    bit_buffer_append_byte(device->tx_buf, 0x00);
    return NfcCommandContinue;
    // TODO log data to some buffer
}

static const MfDesListenerCommandHandler mfdes_commands[] = {
    {
        .cmd = MFDES_SELECT_APPLICATION,
        .callback = mfdes_listener_select_application_cmd,
    },
    {
        .cmd = MFDES_LEGACY_AUTHENTICATION,
        .callback = mfdes_listener_legacy_authentication_cmd,
    },
    {
        .cmd = MFDES_CONTINUE_AUTHENTICATION,
        .callback = mfdes_listener_continue_authentication,
    },
    {
        .cmd = MFDES_READ_DATA,
        .callback = mfdes_listener_read_data,
    }};

MfDesListenerCommandCallback mfdes_listerner_get_command_callback(const uint8_t* command) {
    furi_assert(command); //Pak se muze dat pryc TODO
    uint8_t cmd_code = (command[0] == MFDES_CLASS_REQUEST) ? command[1] : command[0];

    MfDesListenerCommandCallback callback = mfdes_listener_unknown_cmd;
    for(uint8_t i = 0; i < COUNT_OF(mfdes_commands); i++) {
        if(cmd_code == mfdes_commands[i].cmd) {
            callback = mfdes_commands[i].callback;
        }
    }
    return callback;
}

NfcCommand mfdes_listener_process(Nfc* nfc, MfDesDevice* device, const uint8_t* data) {
    NfcCommand command = NfcCommandContinue;
    bit_buffer_reset(device->tx_buf);

    MfDesListenerCommandCallback callback = mfdes_listerner_get_command_callback(data);
    if(callback != NULL) {
        command = callback(device, data);
        // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf); 4a dela crc sama
    }

    if(bit_buffer_get_size_bytes(device->tx_buf) > 0) {
        NfcError error = nfc_listener_tx(nfc, device->tx_buf);
        if(error != NfcErrorNone) {
            FURI_LOG_E(TAG, "Tx error");
        }
    }

    return command;
}

NfcCommand mfdes_listener_callback(NfcGenericEvent event, void* device) {
    FURI_LOG_D(TAG, "NfcCommand mfdes_listener_callback");
    NfcCommand command = NfcCommandContinue;
    MfDesDevice* instance = device;

    MfDesSpecificContext* context = instance->specific_context;

    Iso14443_4aListenerEvent* Iso14443_4a_event = event.event_data;

    if(Iso14443_4a_event->type == Iso14443_4aListenerEventTypeFieldOff) {
        FURI_LOG_D(TAG, "FieldOff");
        if(context->listener_state == MfDesListenerStateAuthenticated) {
            mfdes_on_done(instance);
        } else if(
            context->listener_state !=
            MfDesListenerStateIdle) { //Pokud cokoliv jineho nez idle a authenticated tak je to error
            mfdes_on_error(instance);
        }
        command = NfcCommandStop;
    } else if(Iso14443_4a_event->type == Iso14443_4aListenerEventTypeHalted) {
        FURI_LOG_D(TAG, "Halted");
        if(context->listener_state == MfDesListenerStateAuthenticated) {
            mfdes_on_done(
                instance); //Pokud by ji uspal po tom co je hotovo tak mi to nevadi a mam done
        }
    } else if(Iso14443_4a_event->type == Iso14443_4aListenerEventTypeReceivedData) {
        BitBuffer* buffer = Iso14443_4a_event->data->buffer;

        const uint8_t* data = bit_buffer_get_data(buffer);
        command = mfdes_listener_process(event.instance, device, data);
    }
    return command;
}
