#include <mfdesfire_nfc_device.h>
#include <ctype.h>

#define TAG "MfDesNfcDevice"

bool mfdes_load_card_info(MfDesDevice* device, FuriString* path) {
    furi_check(device);
    furi_check(path);

    bool result = false;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* file = flipper_format_file_alloc(storage);

    // char uid[] = furi_string_get_cstr(instance->uid);
    // char sak[] = furi_string_get_cstr(instance->sak);
    // char atqa[] = furi_string_get_cstr(instance->atqa);

    do {
        FURI_LOG_D(TAG, "Opening file: %s", furi_string_get_cstr(path));

        if(!flipper_format_file_open_existing(file, furi_string_get_cstr(path))) {
            FURI_LOG_E(TAG, "Failed to open file");
            break;
        }

        // TODO mela by tu byt kontrola na to jestli klic existuje
        if(!flipper_format_read_string(file, "UID", device->uid)) {
            FURI_LOG_E(TAG, "Failed to read UID");
            break;
        }
        FURI_LOG_D(TAG, "UID: %s", furi_string_get_cstr(device->uid));

        if(!flipper_format_read_string(file, "ATQA", device->atqa)) {
            FURI_LOG_E(TAG, "Failed to read ATQA");
            break;
        }
        FURI_LOG_D(TAG, "ATQA: %s", furi_string_get_cstr(device->atqa));

        if(!flipper_format_read_string(file, "SAK", device->sak)) {
            FURI_LOG_E(TAG, "Failed to read SAK");
            break;
        }
        FURI_LOG_D(TAG, "SAK: %s", furi_string_get_cstr(device->sak));

        result = true;

    } while(false);

    flipper_format_free(file);
    furi_record_close(RECORD_STORAGE);
    return result;
}

void mfdes_load_key_and_iv(MfDesDevice* device, const uint8_t* key, const uint8_t* iv) {
    device->initial_vector = iv;
    device->key = key;
    return;
}

// "AA BB CC" / "AA:BB:CC" / "AABBCC" -> bytes
static size_t parse_hex_bytes(const char* s, uint8_t* out, size_t max_out) {
    size_t n = 0;
    while(*s && n < max_out) {
        // přeskoč oddělovače
        while(*s == ' ' || *s == ':' || *s == '-' || *s == '\t')
            s++;
        if(!isxdigit((unsigned char)s[0])) break;
        char b[3] = {0, 0, 0};
        b[0] = s[0];
        if(isxdigit((unsigned char)s[1])) {
            b[1] = s[1];
            s += 2;
        } else {
            s += 1;
        }
        out[n++] = (uint8_t)strtoul(b, NULL, 16);
    }
    return n;
}

static NfcDevice* mfdes_alloc_nfc_device(MfDesDevice* device, FuriString* path) {
    FURI_LOG_D(TAG, "Building NFC device");

    Iso14443_4aData* iso14443_4a_edit_data = iso14443_4a_alloc();
    // iso14443_4a_set_uid(iso14443_4a_edit_data, furi_string_get_cstr(app->uid), sizeof(app->uid));
    uint8_t uid[7] = {0};
    size_t uid_len = parse_hex_bytes(furi_string_get_cstr(device->uid), uid, sizeof(uid));
    FURI_LOG_D(TAG, "UID length: %zu", uid_len);
    iso14443_4a_set_uid(iso14443_4a_edit_data, uid, uid_len);

    Iso14443_3aData* iso14443_3a_data = iso14443_4a_get_base_data(iso14443_4a_edit_data);
    // iso14443_3a_set_atqa(iso14443_3a_data, furi_string_get_cstr(app->atqa));
    // iso14443_3a_set_sak(iso14443_3a_data, furi_string_get_cstr(app->sak));
    uint8_t atqa[2] = {0};
    (void)parse_hex_bytes(furi_string_get_cstr(device->atqa), atqa, sizeof(atqa));
    FURI_LOG_D(TAG, "ATQA: %02X %02X", atqa[0], atqa[1]);
    iso14443_3a_set_atqa(iso14443_3a_data, atqa);

    uint8_t sak = 0;
    uint8_t sak_arr[1] = {0};
    (void)parse_hex_bytes(furi_string_get_cstr(device->sak), sak_arr, 1);
    sak = sak_arr[0];
    FURI_LOG_D(TAG, "SAK: %02X", sak);
    iso14443_3a_set_sak(iso14443_3a_data, sak);

    //------------ ats ----------

    Storage* storage = furi_record_open(RECORD_STORAGE);
    FlipperFormat* file = flipper_format_file_alloc(storage);
    if(!flipper_format_file_open_existing(file, furi_string_get_cstr(path))) {
            FURI_LOG_E(TAG, "Failed to open file");
        }

    uint32_t temp = 0;
    (void)flipper_format_read_uint32(file, "Version", &temp, 1);

    if(iso14443_4a_load(iso14443_4a_edit_data, file, temp)){
        FURI_LOG_D(TAG, "Nacetl jsem ats");
    }

    flipper_format_free(file);
    furi_record_close(RECORD_STORAGE);

    //-------------- end of ats -----------

    NfcDevice* nfc_device = nfc_device_alloc();

    nfc_device_set_data(nfc_device, NfcProtocolIso14443_4a, iso14443_4a_edit_data);

    iso14443_4a_free(iso14443_4a_edit_data);

    FURI_LOG_D(TAG, "NFC device built successfully");

    return nfc_device;
}

MfDesDevice* mfdes_device_alloc() {
    MfDesDevice* device = malloc(sizeof(MfDesDevice));
    // device->nfc_device = mfdes_alloc_nfc_device(app);
    device->specific_context = mfdes_context_alloc();

    device->tx_buf = bit_buffer_alloc(512);
    device->uid = furi_string_alloc();
    device->sak = furi_string_alloc();
    device->atqa = furi_string_alloc();

    // device->initial_vector = app->initial_vector;
    // device->key = app->key;
    device->listener_callback = mfdes_listener_callback;

    return device;
}

void mfdes_init_nfc_device(MfDesDevice* device, FuriString* path) {
    device->nfc_device = mfdes_alloc_nfc_device(device, path);
}

void mfdes_set_device_app_context(MfDesDevice* device, MfDesAppForDeviceContext context) {
    device->app_event_context = context;
}

void mfdes_device_free(MfDesDevice* device) {
    nfc_device_free(device->nfc_device);
    bit_buffer_free(device->tx_buf);
    furi_string_free(device->uid);
    furi_string_free(device->sak);
    furi_string_free(device->atqa);
    mfdes_context_free(device->specific_context);
    free(device);
}

void device_set_specific_context(MfDesDevice* device, MfDesListenerStates state) {
    device->specific_context->listener_state = state;
}

void mfdes_device_set_event_callback(
    MfDesDevice* device,
    MfDesDeviceEventCallback callback,
    MfDesAppForDeviceContext context) {
    device->event_callback = callback;
    device->app_event_context = context;
}

NfcGenericCallback mfdes_get_nfc_callback(const MfDesDevice* device) { //Get listener callback
    return device->listener_callback;
}

NfcDevice* mfdes_get_nfc_device(const MfDesDevice* device) {
    return device->nfc_device;
}

void mfdes_pre_callback(MfDesDevice* instance, MfDesDeviceEventType type) {
    if(instance->event_callback != NULL) {
        instance->event_callback(type, instance->app_event_context);
    }
}

MfDesSpecificContext* mfdes_context_alloc() {
    MfDesSpecificContext* context = malloc(sizeof(MfDesSpecificContext));
    context->listener_state = MfDesListenerStateIdle;
    return context;
}

void mfdes_context_free(MfDesSpecificContext* context) {
    free(context);
}
