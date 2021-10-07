## Introduction

This IoTConnect C SDK is intended for standard operating systems Linux/Windows/MacOS.

The SDK can be integrated with Azure IoT C SDK or Paho MQTT C Client.

The Paho MQTT implementation does not support TPM authentication.

## Building

It is recommended to use JetBrains CLion IDE with the sample projects, but you can also build the projects
with cmake command line tool manually.

Install cmake, make and an adequate C compiler and tools before building. This can be done on Ubuntu by executing:
```shell script
sudo apt-get install build-essential cmake 
``` 

Note that the following build options are configured by default and can be toggled with cmake flags:
* IOTC_USE_PAHO=OFF - builds with Azure IoT C SDK by default.

#### Dependencies

The project depends on curl openssl libraries and uuid library (uuid required for for Azure C SDK flavor onl) .

Both the shared libraries and the C source headers are required to be present on the build host for building. 
Curl and openssl shared libraries must be present on the device when running the project. 

On Ubuntu, you can run the following command to satisfy the library dependencies: 

```shell script
sudo apt-get install libcurl4-openssl-dev libssl-dev uuid-dev
```

The project uses the following dependent projects as git submodules:

* [cJSON](https://github.com/DaveGamble/cJSON.git) v1.7.13
* [iotc-c-lib](https://github.com/avnet-iotconnect/iotc-c-lib.git) v2.0.2
* [azure-iot-sdk-c](https://github.com/Azure/azure-iot-sdk-c.git) lts_01_2021
* [paho.mqtt.c](https://github.com/eclipse/paho.mqtt.c.git) v1.3.9

#### Initializing/Downloading The Project

This project has git submodules that need to be pulled before building. You can either:

* Download this project from the GitHub Releases or Actions
* or Clone this repo or download and perform the following steps:
* Follow the instructions for your OS:
  * [Linux Instructions](doc/Linux.md)
  * [Windows Instructions](doc/Windows.md) 
* Edit samples/basic-sample/config/app_config.h to reflect your account and device's configuration.
* If using CA Certificate based authentication, follow the instructions in the 
[iotc-c-lib/tools/ecc-certs](https://github.com/avnet-iotconnect/iotc-c-lib/tree/master/tools/ecc-certs) 
repo and create the identify for your device. 
Place the device certificate and private key into *certs/client-crt.pem* and *certs/client-key.pem* in the basic-sample project.

 