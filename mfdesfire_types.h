
#pragma once

typedef enum {
    ROT_LEFT,
    ROT_RIGHT,
} MfDesRotation;

// K precallback funkci
typedef enum {
    MfDesTargetDetected,
    MfDesTargetLost,

    MfDesAuthenticationFinish,
    MfDesAuthenticationError,
} MfDesDeviceEventType;

typedef void (*MfDesDeviceEventCallback)(MfDesDeviceEventType type, void* context);
