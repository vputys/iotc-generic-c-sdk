//
// Copyright: Avnet 2021
// Created by Nik Markovic <nikola.markovic@avnet.com> on 6/24/21.
//

#ifndef IOTC_PAHO_CLIENT_H
#define IOTC_PAHO_CLIENT_H

#include <MQTTClient.h>
#include "iotconnect_discovery.h"
#include "iotconnect.h"

#ifdef __cplusplus
extern   "C" {
#endif


typedef void (*IotConnectC2dCallback)(unsigned char* message, size_t message_len);

typedef struct {
    int qos; // default QOS is 1
    IotclSyncResponse* sr;
    IotConnectAuthInfo *auth; // Pointer to IoTConnect auth configuration
    IotConnectC2dCallback c2d_msg_cb; // callback for inbound messages
    IotConnectStatusCallback status_cb; // callback for connection status
} IotConnectPahoConfig;

int iotc_paho_client_init(IotConnectPahoConfig *c);

int iotc_paho_client_disconnect();

bool iotc_paho_client_is_connected();

// sends message with QOS 1
int iotc_paho_client_send_message(const char *message);

// sends message with specified qos
int iotc_paho_client_send_message_qos(const char *message, int qos);

#ifdef __cplusplus
}
#endif

#endif // IOTC_PAHO_CLIENT_H
