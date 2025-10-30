#include "mfdesfire_auth_i.h"

#define TAG "MfDesEmulate"

static void mfdes_nfc_stop_emulation(MfDesApp* instance) {
    furi_assert(instance);
    furi_delay_ms(5);
    nfc_listener_stop(instance->listener);
    nfc_listener_free(instance->listener);
    mfdes_device_free(instance->device);
}

static void mfdes_nfc_emulate_callback(MfDesDeviceEventType type, void* context) {
    furi_check(context);
    MfDesApp* instance = context;
    MfDesDeviceEventType event = MfDesAuthenticationFinish;

    switch(type) {
    case MfDesAuthenticationFinish:
        break;
    case MfDesTargetDetected:
        FURI_LOG_D(TAG, "Target detected");
        break;
    case MfDesTargetLost:
        FURI_LOG_D(TAG, "Target lost");
        break;
    case MfDesAuthenticationError:
        FURI_LOG_D(TAG, "Target error");
        furi_crash();
        break;
    }

    view_dispatcher_send_custom_event(instance->view_dispatcher, event);
}

void desfire_app_scene_emulate_on_enter(void* context) {
    MfDesApp* instance = context;
    Widget* widget = instance->widget;

    // widget_add_icon_element(widget, 0, 3, &I_NFC_dolphin_emulation_51x64); //TODO
    widget_add_string_element(widget, 90, 26, AlignCenter, AlignCenter, FontPrimary, "Emulating");

    view_dispatcher_switch_to_view(instance->view_dispatcher, MfDesAppViewWidget);

    instance->device = mfdes_device_alloc();
    mfdes_device_set_event_callback(instance->device, mfdes_nfc_emulate_callback, instance);
    mfdes_load_card_info(instance->device, instance->selected_card_path);
    mfdes_load_key_and_iv(instance->device, instance->key, instance->initial_vector);
    mfdes_init_nfc_device(instance->device);
    NfcDevice* nfc_device = mfdes_get_nfc_device(instance->device);
    NfcProtocol protocol = nfc_device_get_protocol(nfc_device);
    const NfcDeviceData* data = nfc_device_get_data(nfc_device, protocol);
    instance->listener = nfc_listener_alloc(instance->nfc, protocol, data);
    FURI_LOG_D(TAG, "Listener: %p", (void*)instance->listener);
    NfcGenericCallback cb = mfdes_get_nfc_callback(instance->device);
    FURI_LOG_D(TAG, "1");
    nfc_listener_start(instance->listener, cb, instance->device);
    FURI_LOG_D(TAG, "2");

    //TODO blink
}

bool desfire_app_scene_emulate_on_event(void* context, SceneManagerEvent event) {
    MfDesApp* instance = context;
    UNUSED(event);
    SceneManager* scene_manager = instance->scene_manager;

    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        uint32_t event_index = event.event;
        if(event_index == MfDesAuthenticationFinish) {
            mfdes_nfc_stop_emulation(instance);
            //TODO zatim se to vrati ale chce to pridat nejakou uspech obrazovku
            scene_manager_previous_scene(scene_manager);
        } else if(event_index == MfDesAuthenticationError) {
            mfdes_nfc_stop_emulation(instance);
            //TODO zatim se to vrati ale chce to pridat nejakou error obrazovku
            scene_manager_previous_scene(scene_manager);
        }
        consumed = true;
    } else if(event.type == SceneManagerEventTypeBack) {
        mfdes_nfc_stop_emulation(instance);
        scene_manager_previous_scene(scene_manager);
        consumed = true;
    }

    return consumed;
}

void desfire_app_scene_emulate_on_exit(void* context) {
    MfDesApp* instance = context;
    widget_reset(instance->widget);
}
