# Breaking Point Static Virtual Blade Shell 
<p align="center">
<img src="https://github.com/QualiSystems/devguide_source/raw/master/logo.png"></img>
</p>

## Overview
Shell implements integration of a device model, application or other technology with CloudShell. A shell consists of a data-model that defines how the device and its properties are modeled in CloudShell along with an automation that enables interaction with the device via CloudShell

### About Breaking Point Static Virtual Blade Shell
Breaking Point Static Virtual Blade Shell provides data model and autoload functionality

### Standard version
Breaking Point Static Virtual Blade Shell is based on the Deployed App Standard 1.0.3

### Supported Breaking Point versions
▪ 8.20 and above

### Requirements
▪ CloudShell version 8.3 and above<br>
▪ Breaking Point Controller Shell 1.2.3 and above


### Downloading the Shell
Breaking Point Static Virtual Blade Shell is available on the [Quali Download Center](https://support.quali.com/entries/87063688-Solution-Pack-Download-Center).
Download the files into a temporary location on your local machine.
___
**Note:** Registration to the Quali Support Portal is required. If you have not registered,
click this link to register [New registration](http://portal.qualisystems.com/entries/43187197)
___

### Shell comprises:
|File name|Description|
|---|---|
|`Breaking Point Static Virtual Blade Shell.zip`|`Breaking Point Static Virtual Blade Shell`|
|`breakingpoint-static-offline-dependecies.zip`|`Shell Python dependecies (for offline installation only)`|

### Automation
This section describes the automation (drivers or scripts) associated with the data model. The automation code (either script or driver) is associated with the model and provided as part of the Shell package (in the .zip file). The following commands are associated with a model inside the Shell:

## Import and Configure Shell
This section describes how to import, configure and modify Breaking Point Static Virtual Blade Shell

### Importing the Shell into CloudShell
Use the following procedure to import the downloaded Shell:

**To import the Shell into CloudShell:**
  1. Download the Shell from the Quali Download Center.
  2. Backup your database.
  3. Log in to CloudShell Portal as administrator of the relevant domain.
  4. In the User menu select Import Package
  5. Browse to the location of the downloaded Shell file, select the relevant .zip file and Click Open. Alternatively, drag   the shell’s .zip file into CloudShell Portal.

### Offline installation of a Shell
___
**Note:** Offline installation instructions are relevant only if Cloudshell Execution Server has no access to PyPi. You can skip this section if your execution server has access to Pypi.
___
Breaking Point Static Virtual Blade Shell uses a variety of Python packages. To work in offline mode:
  1. Download the breakingpoint-static-offline-dependecies.zip file (see "Downloading the Shell" section).
  2. Unzip it into the "_C:\Program Files (x86)\QualiSystems\CloudShell\Server\Config\Pypi Server Repository_" folder
  3. Restart Execution Server.

### Configuring a new applications
Use the following procedure to load a device, which will use this Shell, into CloudShell:
  1. In the CloudShell Portal, in the **Inventory** dashboard, click **Add New**
  2. From the list, select the **BP vBlade**.
  3. Enter the Blade’s Name and IP address.
  4. Click **Create**.
  5. In the Resource Discovery information form, enter the all the fields relevant for
the device.
  6. Click **Continue**.

This command discovers the device, fills in its attributes and creates the device’s
structure in CloudShell (if such structure exists).
