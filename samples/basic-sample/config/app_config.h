//
// Copyright: Avnet 2020
// Created by Nik Markovic <nikola.markovic@avnet.com> on 6/28/21.
//
#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include "iotconnect.h"

#define IOTCONNECT_CPID "your-cpid" // Account Settings -> Key Vault
#define IOTCONNECT_ENV  "your-environment" // Account Settings -> Key Vault

#define IOTCONNECT_DUID "test-device" // you can supply a custom device UID, or...

// from iotconnect.h
// If IOTC_KEY is used, but IOTCONNECT_SYMMETRIC_KEY string length is 0, simple key-based authentication is used
// which should only be used for testing and never in production.
#define IOTCONNECT_AUTH_TYPE IOTC_KEY
#define IOTCONNECT_SYMMETRIC_KEY "your-symmetric-key" // In device connection info panel
// If executing from cmake-build-debug
#define IOTCONNECT_CERT_PATH "../certs"
#define IOTCONNECT_SERVER_CERT (IOTCONNECT_CERT_PATH "/server.pem")

// if IOTC_X509 is used:
#define IOTCONNECT_IDENTITY_CERT (IOTCONNECT_CERT_PATH "/client-crt.pem")
#define IOTCONNECT_IDENTITY_KEY (IOTCONNECT_CERT_PATH "/client-key.pem")


#endif //APP_CONFIG_H
