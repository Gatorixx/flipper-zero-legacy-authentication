#include "mfdesfire_auth_i.h"

static void mfdes_popup_callback(void* context) {
    MfDesApp* instance = context;
    view_dispatcher_send_custom_event(instance->view_dispatcher, MfDesAppCustomExit);
}

void desfire_app_scene_emulate_on_enter(void* context) {
    MfDesApp* instance = context;
    Popup* widget = instance->widget;

    // widget_add_icon_element(widget, 0, 3, &I_NFC_dolphin_emulation_51x64); TODO
    widget_add_string_element(widget, 90, 26, AlignCenter, AlignCenter, FontPrimary, "Emulating");

    view_dispatcher_switch_to_view(instance->view_dispatcher, MfDesAppViewWidget);

    instance->device = mfdes_device_alloc();
}

bool desfire_app_scene_emulate_on_event(void* context, SceneManagerEvent event){
    MfDesApp* instance = context;
    UNUSED(event);
    SceneManager* scene_manager = instance->scene_manager;
    
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom){
        uint32_t event_index = event.event;
        if(event_index == MfDesAppCustomExit){
            consumed = scene_manager_search_and_switch_to_previous_scene(scene_manager, MfDesAppViewSubmenu);
        }
    }else if(event.type == SceneManagerEventTypeBack){


    }

    return consumed;
}

void desfire_app_scene_emulate_on_exit(void* context){
    MfDesApp* instance = context;

    // Clear view
    popup_reset(instance->popup);
}

