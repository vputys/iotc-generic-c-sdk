## Introduction

This IoTConnect C SDK is intended for standard operating systems Linux/Windows/MacOS.

## Building

It is recommended to use JetBrains CLion IDE with the sample projects, but you can also build the projects
with cmake command line tool manually.

#### Dependencies

The project depends on curl and openssl libraries.

Both the shared libraries and the C source headers are required to be present on the build host for building. 
Curl and openssl shared libraries must be present on the device when running the project. 

On Ubuntu, you can run: 

```shell script
sudo apt-get install libcurl4-openssl-dev libssl-dev
```

The project uses the following dependent projects as git submodules:

* [cJSON](https://github.com/DaveGamble/cJSON.git) v1.7.13
* [paho.mqtt.c](https://github.com/eclipse/paho.mqtt.c.git) v1.3.9
* [iotc-c-lib](https://github.com/avnet-iotconnect/iotc-c-lib.git) v2.0.2

#### Initializing/Downloading The Project

This project has git submodules that need to be pulled before building. You can either:

* Download this project from the GitHub Releases or Actions
* or Clone this repo and perform the following steps: 
  * Initialize the project using the script on Linux/MacOS with ```scripts/setup-project.sh```
  * or examine the script and perform the actions for your OS.
* Edit samples/basic-sample/config/app_config.h to reflect your account and device's configuration.
* If using CA Certificate based authentication, follow the instructions in the 
[iotc-c-lib/tools/ecc-certs](https://github.com/avnet-iotconnect/iotc-c-lib/tree/master/tools/ecc-certs) 
repo and create the identify for your device. 
Place the device certificate and private key into *certs/client-crt.pem* and *certs/client-key.pem* in the basic-sample project.

#### Building and Running with CLion

* In CLion, open the *basic-sample* project from the *samples* directory of this repo
* In the top right of of the IDE next to the hammer icon, select *basic-sample*
* Click the build, execute or debug icon.

#### Building and Running with CMake Command Line

```shell script
cd samples/basic-sample
mkdir build
cd build
cmake ..
cmake --build . --target basic-sample
./basic-sample
```

