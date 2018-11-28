![](https://github.com/stsuberi/SaraTest/blob/master/cloudshell_logo.png)

# BreakingPoint VE Static VBlade 2G Shell 

Release date: July 2018

Shell version: 1.0.0

Document version: 1.0.0

# In This Guide

* [Overview](#overview)
* [Downloading the Shell](#downloading-the-shell)
* [Importing and Configuring the Shell](#importing-and-configuring-the-shell)
* [Updating Python Dependencies for Shells](#updating-python-dependencies-for-shells)
* [Typical Workflows](#typical-workflows)
* [References](#references)

## Overview
A shell integrates a device model, application or other technology with CloudShell. A shell consists of a data model that defines how the device and its properties are modeled in CloudShell, along with automation that enables interaction with the device via CloudShell.

### Traffic Generator Shells
CloudShell's traffic generator shells enable you to conduct traffic test activities on Devices Under Test (DUT) or Systems Under Test (SUT) from a sandbox. In CloudShell, a traffic generator is typically modeled using a chassis resource, which represents the traffic generator device and ports, and a controller service that runs the chassis commands, such as Load Configuration File, Start Traffic and Get Statistics. Chassis and controllers are modeled by different shells, allowing you to accurately model your real-life architecture. For example, scenarios where the chassis and controller are located on different machines.

For additional information on traffic generator shell architecture, and setting up and using a traffic generator in CloudShell, see the [Traffic Generators Overiew](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/LAB-MNG/Trffc-Gens.htm?Highlight=traffic%20generator%20overview) online help topic.

### BreakingPoint VE Static VBlade 2G Shell
The **BreakingPoint VE Static VBlade 2G** shell provides you with connectivity and management capabilities such as device structure discovery and power management for the BreakingPoint VE Static VBlade.

The blade's main function is to autoload and map the ports on its VM with the autoloaded ports on the CloudShell resource.

For more information on the BreakingPoint VE Static VBlade, see the BreakingPoint official product documentation.

To model a BreakingPoint VE Static VBlade device in CloudShell, use the following:
 
▪ [BreakingPoint Static VChassis](https://community.quali.com/repos/3910/breakingpoint-static-vchassis-shell), which enables autoloading the VChassis structure and attributes of a specific BreakingPoint VE Static VChassis to CloudShell.

▪ [BreakingPoint Controller 1G Shell (service)](https://community.quali.com/repos/1295/breaking-point-controller-shell), which provides automation commands to run on the VChassis, such as Load Test Configuration, Start Traffic, Get Statistics.

### Standard version
The BreakingPoint VE Static VBlade 2G shell is based on the Deployed App Standard version 1.0.3.

For detailed information about the shell’s structure and attributes, see the [Shell Standard: Deployed App](https://community.quali.com/repos/423/shell-standard-deployed-app) in GitHub.

### Requirements
Release: BreakingPoint VE Static VBlade 2G Shell 1.0.0

▪ CloudShell version 8.3 and above

▪ BreakingPoint VE version 8.20 and above

▪ Breaking Point Controller Shell version 1.2.3 and above

**Note:** If your CloudShell version does not support this shell, you should consider upgrading to a later version of CloudShell or contact customer support.

## Data Model

The shell's data model includes all shell metadata, families, and attributes.

**BreakingPoint Blade Families and Models**

The Blade families and models are listed in the following table:

|Family|Model|Description|
|:---|:---|:---|
|CS_GenericAppFamily|BP vBlade|Static Virtual BreakingPoint modules located on the chassis.|
|CS_Port|BP vBlade.GenericVPort|Generic Virtual Port.|

**BreakingPoint Static VBlade Attributes**

The VBlade attribute names and types are listed in the following table:

|Attribute|Type|Description|
|:---|:---|:---|
|Password|Password|Password is required by some CLI protocols, such as Telnet, as well as for device configuration.|
|Public IP|String|The name of the controller group that the traffic generator is associated with or the group(s) (comma-separated) the traffic controller is part of.|
|User|String|User with administrative privileges.|
|vBlade vCenter VM|String|Name of Virtual Blade vCenter VM in VCenter. <br>Should include the full path (realtive to the datacenter)  and the name of the VM.<br> For example: *QualiFolder/VM121*.|
|vCenter Name|String|vCenter cloud provider resource name in CloudShell.|
|vChassis vCenter VM|String|Name of Virtual Chassis vCenter VM in vCenter. <br>Should include the full path and the name of the VM. <br>For example: *QualiFolder/VM121*.|

### Automation
This section describes the automation (drivers) associated with the data model. The shell’s driver is associated with the model and provided as part of the shell package). There are two types of automation processes, Autoload and Resource. Autoload is executed when creating the resource in the Inventory dashboard, while resource commands are run in the Sandbox, providing that the resource has been discovered and is online.

For Traffic Generator Shells, commands are configured and executed from the controller service in the sandbox, with the exception of the Autoload command, which is executed when creating the resource.

### Downloading the shell
The **BreakingPoint VE Static VBlade** shell is available from the [Quali Community Integrations](https://community.quali.com/integrations) page. 

Download the files into a temporary location on your local machine. 

The shell comprises:

|File name|Description|
|:-----|:-----|
|Breaking.Point.Static.Virtual.Blade.Shell.zip|BreakingPoint VE Static VBlade 2G Shell package|
|breakingpoint-static-offline-dependencies.zip|Shell Python dependencies (for offline deployments only)|

## Importing and Configuring the Shell
This section describes how to import the BreakingPoint VE Static VBlade 2G shell and configure and modify the shell’s devices.

### Importing the shell into CloudShell

**To import the shell into CloudShell:**
  1. Make sure you have the shell’s zip package. If not, download the shell from the [Quali Community's Integrations](https://community.quali.com/integrations) page.
  2. In CloudShell Portal, as Global administrator, open the **Manage – Shells** page.
  3. Click **Import**.
  4. In the dialog box, navigate to the shell’s zip package, select it and click **Open**.
    
The shell is displayed in the **Shells** page and can be used by domain administrators in all CloudShell domains to create new inventory resources, as explained in [Adding Inventory Resources](http://help.quali.com/Online%20Help/9.0/Portal/Content/CSP/INVN/Add-Rsrc-Tmplt.htm?Highlight=adding%20inventory%20resources). 

### Offline installation of a Shell

**Note:** Offline installation instructions are relevant only if CloudShell Execution Server has no access to PyPi. You can skip this section if your execution server has access to PyPi. For additional information, see the online help topic on offline dependencies.

In offline mode, import the shell into CloudShell and place any dependencies in the appropriate dependencies folder.

### Adding shell and script packages to the local PyPi Server repository
If your Quali Server and/or execution servers work offline, you will need to copy all required Python packages, including the out-of-the-box ones, to the PyPi Server's repository on the Quali Server computer (by default *C:\Program Files (x86)\QualiSystems\CloudShell\Server\Config\Pypi Server Repository*).

For more information, see [Configuring CloudShell to Execute Python Commands in Offline Mode](http://help.quali.com/Online%20Help/9.0/Portal/Content/Admn/Cnfgr-Pyth-Env-Wrk-Offln.htm?Highlight=Configuring%20CloudShell%20to%20Execute%20Python%20Commands%20in%20Offline%20Mode).

**To add Python packages to the local PyPi Server repository:**
  1. If you haven't created and configured the local PyPi Server repository to work with the execution server, perform the steps in [Add Python packages to the local PyPi Server repository (offline mode)](http://help.quali.com/Online%20Help/9.0/Portal/Content/Admn/Cnfgr-Pyth-Env-Wrk-Offln.htm?Highlight=offline%20dependencies#Add). 
  2. For each shell or script you add into CloudShell, do one of the following (from an online computer):
      * Connect to the Internet and download each dependency specified in the shell's *requirements.txt* file with the following command: 
*pip download -r requirements.txt*. 
     The sell or script's requirements are downloaded as zip files.

      * In the [Quali Community's Integrations](https://community.quali.com/integrations) page, locate the sell and click the sell's **Download** link. In the page that is displayed, from the Downloads area, extract the dependencies package zip package

3. Place these zip files in the local PyPi Server repository.
 
### Configuring a new resource
This section explains how to create a new resource from the shell.

In CloudShell, the component that models the device is called a resource. It is based on the shell that models the device and allows the CloudShell user and API to remotely control the device from CloudShell.

You can also modify existing resources, see [Managing Resources in the Inventory](http://help.quali.com/Online%20Help/8.3/Portal/Content/CSP/INVN/Mng-Rsrc-in-Invnt.htm?Highlight=managing%20resources).

**To create a resource for the device:**
  1. In CloudShell Portal, in the **Inventory** dashboard, click **Add New**. 
     ![](https://github.com/stsuberi/SaraTest/blob/master/create_a_resource_device.png)
  2. From the list, select the **BP vBlade** shell.
  3. Enter the **Name** and **IP address** of the blade.
  4. Click **Create**.
  5. In the **Resource** dialog box, edit the device's settings as follows to discover the resource: You must provide values for each of the device settings.
  
  |Attribute|Type|Description|
  |:---|:---|:---|
  |Address|String|BreakingPoint vBlade Public IP.|
  |vBlade vCenter VM|String|Name of Virtual Blade vCenter VM in vCenter. <br>Should include the full path and the name of the VM.<br>For example:*QualiFolder/VM121*.|
  |vChassis vCenter VM|String|Name of Virtual Chassis vCenter VM in vCenter. <br>Should include the full path and the name of the VM.<br>For example: *QualiFolder/VM121*.|
  |vCenter Name|String|vCenter resource name in CloudShell.|
  |User|String|User with administrative privileges.|
  |Password|Password|Password is required by some CLI protocols, such as Telnet, as well as for device configuration.|
  6. Click **Continue**.

CloudShell validates the device’s settings and updates the new resource with the device’s structure (if the device has a structure).

## Updating Python Dependencies for Shells
This section explains how to update your Python dependencies folder. This is required when you upgrade a shell that uses new/updated dependencies. It applies to both online and offline dependencies.

### Updating offline Python dependencies
**To update offline Python dependencies:**
1. Download the latest Python dependencies package zip file locally.
2. Extract the zip file to the suitable offline package folder(s). 
3. Restart any execution server that has a live instance of the relevant driver or script. This requires running the Execution Server's configuration wizard, as explained in the [Configure the Execution Server](http://help.quali.com/doc/9.0/CS-Install/content/ig/configure%20cloudshell%20products/cfg-ts-exec-srver.htm?Highlight=configure%20the%20execution%20server) topic of the CloudShell Suite Installation guide. 

### Updating online Python dependencies
In online mode, the execution server automatically downloads and extracts the appropriate dependencies file from the public PyPi repository every time a new instance of the driver or script is created.

**To update online Python dependencies:**
* If there is a live instance of the shell's driver or script, restart the execution server, as explained above. If an instance does not exist, the execution server will download the Python dependencies the next time a command of the driver or script runs.

## Typical Workflows

**Workflow 1 - Creating a new blueprint**
1. Create a new blueprint.
   * In CloudShell Portal, create a new blueprint **Blueprints>Create Blueprint**.
   * Give the blueprint a name.
2. Add resources and services to the blueprint. 
   * Click the **Resource** button and add the BreakingPoint Chassis resource and all needed ports into the diagram. 
   * Associate the port sub resources with the BreakingPoint Network Neighborhood Interfaces, by specifying the port attribute **Logical Name** with the BP interface ID.
   * Click the **App/Services** tab and add the **BreakingPointController** service.
   * Specify the attribute **Test Files Location**, where test files will be downloaded.
3. Add a teardown script, which runs the **cleanup_reservation** driver command when the reservation ends. This command releases ports which were used by the reservation. 
   * In CloudShell Portal, **Scripts** management page **Manage>Scripts>Blueprint**, click **Add New Script**.
   * Select the **Cleanup Reservation.zip** file. 
   * Click **Edit** and change **Script Type** to **Teardown**.
   * Return to the blueprint and open the properties, **Blueprint>Properties**. 
   * In the **Driver** section, select **Python Setup & Teardown**, and edit the **Estimated teardown duration** to 1 min.
   * Click **Add Scripts** and choose **Cleanup Reservation** from the list. 
   * Click **Update** to save changes.

**Workflow 2 - Getting a test file with network configuration**

*You cannot change predefined Tests and Network Neighborhoods. Predefined Network Neighborhoods will not be included in Test files.*

This scenario helps you use predefined Tests and Network Neighborhoods.

1. Duplicate the BreakingPoint Network Neighborhood configuration.
   * Open the BreakingPoint UI.
   * Go to **Control Center>Open Neighborhood**.
   * Find and select **Network Neighborhood** from the list.
   * Click **Save As** and enter **New Network Neighborhood Name**.
   * Click **Ok**.
2. Duplicate the BreakingPoint Test.
   * Go to **Test>Open Test**.
   * Find and select the **Test** from the list.
   * Press **Save As** and save it with a new name.
3. Change the **Network Neighborhood** in the duplicated test.
   * Find and select the duplicated test from the list and open it.
   * In the section **Network Neighborhood** click ‘…’, find and select the duplicated Network Neighborhood.
   * Click **Save**.
4. Run the `GetTestFile BreakingPointController` command.
   * In CloudShell Portal, reserve the new blueprint.
   * Run the BreakingComandController service command `GetTestFile` with the duplicated test name.
   * Open the folder specified in the attribute **Test Files Location**+<reservation_id> to view the file with the name of your duplicated test (extension “bpt”).

**Workflow 3 - Running a test**
1. Enter your blueprint.
2. From the BreakingPointController service, run the **Load Configuration** command.
   * Hover over the BreakingPointController service and click **Commands**.
   * In the **Resource Commands** pane, click the **Load Configuration** command.
   * Specify the **BreakingPoint config file** with the path of your test configuration file. <br>It can be a full path, or relative path under the location specified in the attribute **Test Files Location**, such as *<reservation_id>/test_name.bpt*, or only *test_name.bpt*, if it is a current sandbox. Make sure the path is accessible to the execution server running the command.
   * Click **Run**, to load the test and network configuration from this file and reserve necessary ports.
3. Run the **Start Traffic** command.
   * Click BreakingPointController **Commands** and enter the service commands.
   * Find the **Start Traffic** command and click enter to run the menu.
   * Set **Blocking** to **True**, if you want subsequent commands to wait until the test finishes, or **False** to allow additional commands to run during the command's execution. 
   * Click **Run**.
4. Run the **Stop Traffic** command.
<br>If the **Start Traffic** test was run with **Blocking** disabled, you can immediately stop the test.
   * Run the **Stop Traffic** command.
5. Get the test's result file.
   * Run the **Get Result** command.
   * The result file is attached to the sandbox.

## References
To download and share integrations, see [Quali Community's Integrations](https://community.quali.com/integrations). 

For instructional training and documentation resources, see the [Quali University](https://www.quali.com/university/).

To suggest an idea for the product, see [Quali's Idea box](https://community.quali.com/ideabox). 

To connect with Quali users and experts from around the world, ask questions and discuss issues, see [Quali's Community forums](https://community.quali.com/forums). 
