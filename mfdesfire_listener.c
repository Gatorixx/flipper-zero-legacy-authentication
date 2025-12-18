#include "mfdesfire_nfc_device.h"
// #include <nfc/protocols/mf_ultralight/mf_ultralight.h>
#include <mbedtls/des.h>
#include <furi_hal.h>
#include <stdio.h>
#include <string.h>

#define TAG "DES_Listener"

typedef NfcCommand (*MfDesListenerCommandCallback)(MfDesDevice* device, const uint8_t* data);

typedef struct {
    uint8_t cmd;
    MfDesListenerCommandCallback callback;
} MfDesListenerCommandHandler;

NfcCommand mfdes_listener_select_application_cmd(MfDesDevice* device, const uint8_t* data) {
    bit_buffer_reset(device->tx_buf);
    bit_buffer_append_byte(device->tx_buf, data[0]);
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_SUCCESS);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    device_set_specific_context(device, MfDesListenerStateSelected);
    // FURI_LOG_D(TAG, "Listener: select application");
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_legacy_authentication_cmd(MfDesDevice* device, const uint8_t* data) {
    // FURI_LOG_D(TAG, "Zacinam A0");
    uint8_t rndB[8];
    uint8_t encrypted_rndB[8];
    uint8_t init_vector[8];
    // memcpy(
    //     init_vector,
    //     device->initial_vector,
    //     sizeof(init_vector)); // To prevent overwriting the app vector
    memset(init_vector, 0, sizeof(init_vector));

    uint32_t r1 = furi_hal_random_get();
    uint32_t r2 = furi_hal_random_get();
    memcpy(rndB, &r1, sizeof(r1));
    memcpy(rndB + sizeof(r1), &r2, sizeof(r2));

    mbedtls_des3_context ctx; //OLD API
    int result;

    mbedtls_des3_init(&ctx);

    result = mbedtls_des3_set3key_enc(&ctx, device->key);
    if(result != 0) {
        mbedtls_des3_free(&ctx);
        return NfcCommandContinue;
    }

    result = mbedtls_des3_crypt_cbc(
        &ctx,
        MBEDTLS_DES_ENCRYPT,
        sizeof(rndB),
        init_vector,
        rndB, // in
        encrypted_rndB); // out

        

    mbedtls_des3_free(&ctx); // release memory
    if(result != 0) {
        FURI_LOG_D(TAG, "Selhal mbedtls_des3_crypt_cbc");
    }

    bit_buffer_append_byte(device->tx_buf, data[0]);
    bit_buffer_append_bytes(device->tx_buf, encrypted_rndB, sizeof(encrypted_rndB));
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_CONTINUE_AUTHENTICATION);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    device_set_specific_context(device, MfDesListenerStatePhase1Sent);
    // FURI_LOG_D(TAG, "Koncim A0");
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
    // bit_buffer_reset(device->tx_buf);
    // FURI_LOG_D(TAG, "Zacinam AF");
    mbedtls_des3_context ctx;
    // int result;
    uint8_t init_vector[8];
    uint8_t decrypted_output[16];
    uint8_t encrypted_rndA[8];

    memcpy(init_vector, device->initial_vector, sizeof(init_vector)); // To prevent overwriting the app vector

        
    uint8_t data_to_decrypt[16];
    
    memcpy(data_to_decrypt, &data[5], sizeof(data_to_decrypt));
        
    mbedtls_des3_init(&ctx);
    mbedtls_des3_crypt_cbc(
                    &ctx,
                    MBEDTLS_DES_DECRYPT, // decrypt
                    sizeof(data_to_decrypt),
                    init_vector,
                    data_to_decrypt, // in
                    decrypted_output); // out

                mbedtls_des3_free(&ctx);

    mbedtls_des3_set3key_dec(&ctx, device->key);

    uint8_t rndA[8];
    memcpy(rndA, decrypted_output, 8);
    // uint8_t rndB[8];
    // memcpy(rndB, decrypted_output + 8, 8);

    uint8_t rotated_rndA[8];
    for(uint8_t i = 0; i < 8; i++) {
        rotated_rndA[i] = rndA[(i + 1) % 8];
    }
    memcpy(rndA, rotated_rndA, 8);

    memset(init_vector, 0, sizeof(init_vector));

    mbedtls_des3_init(&ctx);

    mbedtls_des3_set3key_enc(&ctx, device->key);

    mbedtls_des3_crypt_cbc(
    &ctx,
    MBEDTLS_DES_ENCRYPT,
    sizeof(rndA),
    init_vector,
    rndA, // in
    encrypted_rndA); // out

    mbedtls_des3_free(&ctx); // release memory

    bit_buffer_append_byte(device->tx_buf, data[0]);
    bit_buffer_append_bytes(device->tx_buf, encrypted_rndA, sizeof(encrypted_rndA));
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_SUCCESS);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    device_set_specific_context(device, MfDesListenerStateAuthenticated);

    // FURI_LOG_D(TAG, "Listener: continue authentication");
    // FURI_LOG_D(TAG, "Koncim AF");
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_read_data(MfDesDevice* device, const uint8_t* data) {
    bit_buffer_reset(device->tx_buf);
    bit_buffer_append_byte(device->tx_buf, data[0]);
    bit_buffer_append_byte(device->tx_buf, MFDES_CLASS_RESPONSE);
    bit_buffer_append_byte(device->tx_buf, MFDES_PERMISSION_DENIED);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    // FURI_LOG_D(TAG, "Listener: read data");
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_negative_ack_b2(MfDesDevice* device, const uint8_t* data){
    UNUSED(data);
    bit_buffer_reset(device->tx_buf);
    bit_buffer_append_byte(device->tx_buf, MFDES_POSITIVE_ACK_A3);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    // FURI_LOG_D(TAG, "Listener: negative ack b2");
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_negative_ack_ba(MfDesDevice* device, const uint8_t* data){
    UNUSED(data);
    bit_buffer_reset(device->tx_buf);
    bit_buffer_append_byte(device->tx_buf, MFDES_POSITIVE_ACK_AB);
    // iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
    // FURI_LOG_D(TAG, "Listener: negative ack ba");
    return NfcCommandContinue;
}

NfcCommand mfdes_listener_unknown_cmd(MfDesDevice* device, const uint8_t* data) {
    FURI_LOG_D(TAG, "Unknown: %02X %02X %02X", data[0], data[1], data[2]);
    bit_buffer_reset(device->tx_buf);
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
    },
    {
        .cmd = MFDES_NEGATIVE_ACK_B2,
        .callback = mfdes_listener_negative_ack_b2,
    },
    {
        .cmd = MFDES_NEGATIVE_ACK_BA,
        .callback = mfdes_listener_negative_ack_ba,
    }

};

MfDesListenerCommandCallback mfdes_listerner_get_command_callback(const uint8_t* command) {
    furi_assert(command); //Pak se muze dat pryc TODO
    // uint8_t cmd_code = (command[1] == MFDES_CLASS_REQUEST) ? command[2] : command[1];
    uint8_t cmd_code;
    if (command[1] == MFDES_CLASS_REQUEST) {
        cmd_code = command[2];
        // FURI_LOG_D(TAG, "Nastavuju cmd_code na command[2]");
    }
    else{
        if(command[0] == MFDES_PCB_02 || command[0] == MFDES_PCB_03) {
            cmd_code = command[1];
            // FURI_LOG_D(TAG, "Nastavuju cmd_code na command[1]");
        }
        else{
            cmd_code = command[0];
            // FURI_LOG_D(TAG, "Nastavuju cmd_code na command[0]");
        }
    }
    
    MfDesListenerCommandCallback callback = mfdes_listener_unknown_cmd;
    for(uint8_t i = 0; i < COUNT_OF(mfdes_commands); i++) {
        // FURI_LOG_D(TAG, "Porovnavam: %02X a %02X", cmd_code, mfdes_commands[i].cmd);
        if(cmd_code == mfdes_commands[i].cmd) {
            callback = mfdes_commands[i].callback;
            break;
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
        iso14443_crc_append(Iso14443CrcTypeA, device->tx_buf);
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
    // FURI_LOG_D(TAG, "NfcCommand mfdes_listener_callback");
    NfcCommand command = NfcCommandContinue;
    MfDesDevice* instance = device;

    MfDesSpecificContext* context = instance->specific_context;

    Iso14443_4aListenerEvent* Iso14443_4a_event = event.event_data;

    if(Iso14443_4a_event->type == Iso14443_4aListenerEventTypeFieldOff) {
        // FURI_LOG_D(TAG, "FieldOff");
        if(context->listener_state == MfDesListenerStateAuthenticated) {
            // mfdes_on_done(instance); //TODO - testovne ted dano pryc
        } else if(
            context->listener_state !=
            MfDesListenerStateIdle) { //Pokud cokoliv jineho nez idle a authenticated tak je to error
            mfdes_on_error(instance);
        }
        // command = NfcCommandStop;
        command = NfcCommandContinue; // Continue because for some reason our systems needs 2 authentications in a row
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
