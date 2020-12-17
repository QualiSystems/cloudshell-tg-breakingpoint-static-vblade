#!/usr/bin/python
# -*- coding: utf-8 -*-

import jsonpickle

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

from bp_api.bp_api import BP_API

from cloudshell.api.cloudshell_api import CloudShellAPISession

from cloudshell.devices.driver_helper import get_logger_with_thread_id
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, AutoLoadDetails, AutoLoadAttribute, \
    AutoLoadResource
from cloudshell.shell.core.driver_context import ApiVmDetails, ApiVmCustomParam
from cloudshell.cp.vcenter.commands.load_vm import VMLoader
# from cloudshell.cp.vcenter.common.cloud_shell.driver_helper import CloudshellDriverHelper
from cloudshell.cp.vcenter.common.model_factory import ResourceModelParser
from cloudshell.cp.vcenter.common.vcenter.vmomi_service import pyVmomiService
from cloudshell.cp.vcenter.common.vcenter.task_waiter import SynchronousTaskWaiter
from cloudshell.cp.vcenter.models.QualiDriverModels import AutoLoadAttribute
from cloudshell.cp.vcenter.vm.ip_manager import VMIPManager

VCENTER_CONNECTION_PORT = 443


class BreakingPointVBladeShellDriver(ResourceDriverInterface):
    SHELL_NAME = "BP vBlade"
    PORT_MODEL = "GenericVPort"
    DOMAIN = "Global"
    IP_KEY = "ipAddress"
    ID_KEY = "id"

    def __init__(self):
        # self.cs_helper = CloudshellDriverHelper()
        self.model_parser = ResourceModelParser()
        self.ip_manager = VMIPManager()
        self.task_waiter = SynchronousTaskWaiter()
        self.pv_service = pyVmomiService(SmartConnect, Disconnect, self.task_waiter)

    def initialize(self, context):
        """
        Initialize the driver session, this function is called everytime a new instance of the driver is created
        This is a good place to load and cache the driver configuration, initiate sessions etc.
        :param InitCommandContext context: the context the command runs on
        """
        pass

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def get_inventory(self, context):
        """
        Will locate vm in vcenter and fill its uuid
        :type context: cloudshell.shell.core.context.ResourceCommandContext
        """

        logger = get_logger_with_thread_id(context)
        logger.info("Start Autoload process")

        # session = self.cs_helper.get_session(context.connectivity.server_address,
        #                                      context.connectivity.admin_auth_token,
        #                                      self.DOMAIN)

        session = CloudShellAPISession(host=context.connectivity.server_address,
                                       token_id=context.connectivity.admin_auth_token,
                                       domain=self.DOMAIN)

        vcenter_vblade = context.resource.attributes["{}.vBlade vCenter VM".format(self.SHELL_NAME)].replace("\\", "/")
        vcenter_vchassis = context.resource.attributes["{}.vChassis vCenter VM".format(self.SHELL_NAME)].replace("\\",
                                                                                                                 "/")
        username = context.resource.attributes["{}.User".format(self.SHELL_NAME)]
        password = self._decrypt_password(session,
                                          context.resource.attributes["{}.Password".format(self.SHELL_NAME)])
        vcenter_name = context.resource.attributes["{}.vCenter Name".format(self.SHELL_NAME)]

        logger.info("Start AutoLoading VM_Path: {0} on vCenter: {1}".format(vcenter_vblade, vcenter_name))

        vcenter_api_res = session.GetResourceDetails(vcenter_name)
        vcenter_resource = self.model_parser.convert_to_vcenter_model(vcenter_api_res)

        si = None

        try:
            logger.info("Connecting to vCenter ({0})".format(vcenter_api_res.Address))
            si = self._get_connection_to_vcenter(self.pv_service, session, vcenter_resource, vcenter_api_res.Address)

            logger.info("Loading VMs UUID")
            vm_loader = VMLoader(self.pv_service)

            vchassis_uuid = vm_loader.load_vm_uuid_by_name(si, vcenter_resource, vcenter_vchassis)
            logger.info("vChassis VM UUID: {0}".format(vchassis_uuid))
            logger.info("Loading the IP of the vChassis VM")
            vchassis_ip = self._try_get_ip(self.pv_service, si, vchassis_uuid, vcenter_resource, logger)
            if vchassis_ip:
                bp_api = BP_API(ip=vchassis_ip, username=username, password=password, logger=logger)
                bp_api.login()
                modules_position = {module[self.IP_KEY]: module[self.ID_KEY] for module in bp_api.get_modules() if
                                    module[self.IP_KEY]}
                bp_api.logout()
                logger.debug("Modules position: {}".format(modules_position))
            else:
                raise Exception("Determination of vChassis IP address failed. Please, verify that VM is up and running")

            vblade_uuid = vm_loader.load_vm_uuid_by_name(si, vcenter_resource, vcenter_vblade)
            logger.info("vBlade VM UUID: {0}".format(vblade_uuid))
            logger.info("Loading the IP of the vBlade VM")
            vblade_ip = self._try_get_ip(self.pv_service, si, vblade_uuid, vcenter_resource, logger)
            if vblade_ip:
                module_id = modules_position.get(vblade_ip)
                if module_id is None:
                    raise Exception("Provided vBlade IP incorrect or vBlade isn't connect to vChassis")
                session.UpdateResourceAddress(context.resource.name,
                                              "{blade_ip}\{chassis_ip}\M{module_id}".format(blade_ip=vblade_ip,
                                                                                            chassis_ip=vchassis_ip,
                                                                                            module_id=module_id))
            else:
                raise Exception("Determination of vBlade IP address failed. Please, verify that VM is up and running")

            vm = self.pv_service.get_vm_by_uuid(si, vblade_uuid)

            phys_interfaces = []

            for device in vm.config.hardware.device:
                if isinstance(device, vim.vm.device.VirtualEthernetCard):
                    phys_interfaces.append(device)

            resources = []
            attributes = []
            for port_number, phys_interface in enumerate(phys_interfaces):
                if port_number == 0:  # First interface (port number 0) should be Management
                    continue

                network_adapter_number = phys_interface.deviceInfo.label.lower().strip("network adapter ")
                unique_id = hash(phys_interface.macAddress)

                relative_address = "P{}".format(port_number)

                resources.append(AutoLoadResource(model="{}.{}".format(self.SHELL_NAME, self.PORT_MODEL),
                                                  name="Port {}".format(port_number),
                                                  relative_address=relative_address,
                                                  unique_identifier=unique_id))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.MAC Address".format(self.SHELL_NAME,
                                                                                              self.PORT_MODEL),
                                                    attribute_value=phys_interface.macAddress,
                                                    relative_address=relative_address))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.Requested vNIC Name".format(self.SHELL_NAME,
                                                                                                      self.PORT_MODEL),
                                                    attribute_value=network_adapter_number,
                                                    relative_address=relative_address))

                attributes.append(AutoLoadAttribute(attribute_name="{}.{}.Logical Name".format(self.SHELL_NAME,
                                                                                               self.PORT_MODEL),
                                                    attribute_value="Interface {}".format(port_number),
                                                    relative_address=relative_address))

            attributes.append(AutoLoadAttribute("",
                                                "VmDetails",
                                                self._get_vm_details(vblade_uuid, vcenter_name)))

            autoload_details = AutoLoadDetails(resources=resources, attributes=attributes)
        except Exception:
            logger.exception("Get inventory command failed")
            raise
        finally:
            if si:
                self.pv_service.disconnect(si)

        return autoload_details

    def _try_get_ip(self, pv_service, si, uuid, vcenter_resource, logger):
        ip = None
        try:
            vm = pv_service.get_vm_by_uuid(si, uuid)
            ip_res = self.ip_manager.get_ip(vm,
                                            vcenter_resource.holding_network,
                                            self.ip_manager.get_ip_match_function(None),
                                            cancellation_context=None,
                                            timeout=None,
                                            logger=logger)
            if ip_res.ip_address:
                ip = ip_res.ip_address
        except Exception:
            logger.debug("Error while trying to load VM({0}) IP".format(uuid), exc_info=True)
        return ip

    @staticmethod
    def _get_vm_details(uuid, vcenter_name):

        vm_details = ApiVmDetails()
        vm_details.UID = uuid
        vm_details.CloudProviderName = vcenter_name
        vm_details.CloudProviderFullName = vcenter_name
        vm_details.VmCustomParams = []
        str_vm_details = jsonpickle.encode(vm_details, unpicklable=False)
        return str_vm_details

    def _get_connection_to_vcenter(self, pv_service, session, vcenter_resource, address):
        password = self._decrypt_password(session, vcenter_resource.password)
        si = pv_service.connect(address,
                                vcenter_resource.user,
                                password,
                                VCENTER_CONNECTION_PORT)
        return si

    @staticmethod
    def _decrypt_password(session, password):
        return session.DecryptPassword(password).Value
