#### Initial Setup

Install cmake, make and an adequate C compiler and tools before building. This can be done on Ubuntu by executing:
```shell script
sudo apt-get install build-essential cmake 
``` 
On Ubuntu, you can run the following command to satisfy the library dependencies: 

```shell script
sudo apt-get install libcurl4-openssl-dev libssl-dev uuid-dev
```

#### Git Setup

If you cloned the repo, execute ```scripts/setup-project.sh```. 
The script will pull the dependency submodules and it will ensure 
that you don't accidentally check in your device credentials or account information in app_config.h.

#### Building and Running with CMake Command Line
  * Initialize the project using the script on Linux/MacOS with ```scripts/setup-project.sh```

```shell script
cd samples/basic-sample
mkdir build
cd build
cmake ..
cmake --build . --target basic-sample
./basic-sample
```

* If you wish to build with the Paho MQTT client, append ```-DIOTC_USE_PAHO=ON``` to the ```cmake ..``` command line.

#### Building and Running with CLion

* In CLion, open the *basic-sample* project from the *samples* directory of this repo
* In the top right of of the IDE next to the hammer icon, select *basic-sample*
* If you wish to build with the Paho MQTT client instead of Azure SDK, Select File->Settings->Build,Execution,Deployment->CMake 
and enter ```-DIOTC_USE_PAHO=ON``` in the "CMake options" entry box.
* Click the build, execute or debug icon.

#### Running on SmartEdge IIoT Gateway

The cmake building steps can be run on the gateway and do not require any addtional build tools or libraries to be installed.

The gateway requires a fix to openssl. If ```openssl version -d``` returns **OPENSSLDIR: "/usr/local/ssl"**, execute these steps before running the sample:

```shell script
sudo rmdir  /usr/local/ssl/certs
sudo ln -sf /etc/ssl/certs /usr/local/ssl/.
```

If you have configured your gateway using the phone app or you are using the pre-installed IoTConnect app, 
you should also disable it  using the commands below.
A device can have only one connection to IoTConnect.

```shell script
sudo systemctl disable iotconnectservice.service
sudo systemctl stop iotconnectservice.service
```

It is recommended to use TPM authentication on the gateway, so configure app_config.h accordingly. 
