namespace RwCal {

  public class RwcalStatus : GLib.Object {
    public RwTypes.RwStatus status;
    public string error_msg;
    public string traceback;
  }

  public interface Cloud: GLib.Object {
    /*
     * Init routine
     */
    public abstract RwTypes.RwStatus init(RwLog.Ctx log_ctx);

    /*
     * Cloud Account Credentails Validation related API
     */
    public abstract RwTypes.RwStatus validate_cloud_creds(
      Rwcal.CloudAccount account,
      out Rwcal.CloudConnectionStatus status);

    /*
     * Image related APIs
     */
    public abstract RwTypes.RwStatus get_image_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources images);

    public abstract RwTypes.RwStatus create_image(
      Rwcal.CloudAccount account,
      Rwcal.ImageInfoItem image,
      out string image_id);

    public abstract RwTypes.RwStatus delete_image(
      Rwcal.CloudAccount account,
      string image_id);

    public abstract RwTypes.RwStatus get_image(
        Rwcal.CloudAccount account,
        string image_id,
        out Rwcal.ImageInfoItem image);

    /*
     * VM Releated APIs
     */
    public abstract RwTypes.RwStatus create_vm(
      Rwcal.CloudAccount account,
      Rwcal.VMInfoItem vm,
      out string vm_id);

    public abstract RwTypes.RwStatus start_vm(
      Rwcal.CloudAccount account,
      string vm_id);

    public abstract RwTypes.RwStatus stop_vm(
      Rwcal.CloudAccount account,
      string vm_id);

    public abstract RwTypes.RwStatus delete_vm(
      Rwcal.CloudAccount account,
      string vm_id);

    public abstract RwTypes.RwStatus reboot_vm(
      Rwcal.CloudAccount account,
      string vm_id);

    public abstract RwTypes.RwStatus get_vm_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources vms);

    public abstract RwTypes.RwStatus get_vm(
      Rwcal.CloudAccount account,
      string vm_id,
      out Rwcal.VMInfoItem vm);

    /*
     * Flavor related APIs
     */
    public abstract RwTypes.RwStatus create_flavor(
      Rwcal.CloudAccount account,
      Rwcal.FlavorInfoItem flavor_info_item,
      out string flavor_id);

    public abstract RwTypes.RwStatus delete_flavor(
      Rwcal.CloudAccount account,
      string flavor_id);

    public abstract RwTypes.RwStatus get_flavor_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources flavors);

    public abstract RwTypes.RwStatus get_flavor(
      Rwcal.CloudAccount account,
      string flavor_id,
      out Rwcal.FlavorInfoItem flavor);


    /*
     * Tenant related APIs
     */
    public abstract RwTypes.RwStatus create_tenant(
      Rwcal.CloudAccount account,
      string tenant_name,
      [CCode (array_length = false, array_null_terminated = true)]
      out string [] tenant_info);

    public abstract RwTypes.RwStatus delete_tenant(
      Rwcal.CloudAccount account,
      string tenant_id);

    public abstract RwTypes.RwStatus get_tenant_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources tenants);

    /*
     * Role related APIs
     */
    public abstract RwTypes.RwStatus create_role(
      Rwcal.CloudAccount account,
      string role_name,
      [CCode (array_length = false, array_null_terminated = true)]
      out string [] role_info);

    public abstract RwTypes.RwStatus delete_role(
      Rwcal.CloudAccount account,
      string role_id);

    public abstract RwTypes.RwStatus get_role_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources roles);

    /*
     * Port related APIs
     */
    public abstract RwTypes.RwStatus create_port(
      Rwcal.CloudAccount account,
      Rwcal.PortInfoItem port,
      out string port_id);

    public abstract RwTypes.RwStatus delete_port(
      Rwcal.CloudAccount account,
      string port_id);

    public abstract RwTypes.RwStatus get_port(
      Rwcal.CloudAccount account,
      string port_id,
      out Rwcal.PortInfoItem port);

    public abstract RwTypes.RwStatus get_port_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources ports);

    /*
     * Host related APIs
     */
    public abstract RwTypes.RwStatus add_host(
      Rwcal.CloudAccount account,
      Rwcal.HostInfoItem host,
      out string host_id);

    public abstract RwTypes.RwStatus remove_host(
      Rwcal.CloudAccount account,
      string host_id);

    public abstract RwTypes.RwStatus get_host(
      Rwcal.CloudAccount account,
      string host_id,
      out Rwcal.HostInfoItem host);

    public abstract RwTypes.RwStatus get_host_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources hosts);

    /*
     * Network related APIs
     */
    public abstract RwTypes.RwStatus create_network(
      Rwcal.CloudAccount account,
      Rwcal.NetworkInfoItem network,
      out string network_id);

    public abstract RwTypes.RwStatus delete_network(
      Rwcal.CloudAccount account,
      string network_id);

    public abstract RwTypes.RwStatus get_network(
      Rwcal.CloudAccount account,
      string network_id,
      out Rwcal.NetworkInfoItem network);

    public abstract RwTypes.RwStatus get_network_list(
      Rwcal.CloudAccount account,
      out Rwcal.VimResources networks);

    public abstract RwTypes.RwStatus get_management_network(
      Rwcal.CloudAccount account,
      out Rwcal.NetworkInfoItem network);

    /*
     * Higher Order CAL APIs
     */
    public abstract void create_virtual_link(
      Rwcal.CloudAccount account,
      Rwcal.VirtualLinkReqParams link_params,
      out RwcalStatus status,
      out string link_id);
    
    public abstract RwTypes.RwStatus delete_virtual_link(
      Rwcal.CloudAccount account,
      string link_id);

    public abstract RwTypes.RwStatus get_virtual_link(
      Rwcal.CloudAccount account,
      string link_id,
      out Rwcal.VirtualLinkInfoParams response);

    public abstract RwTypes.RwStatus get_virtual_link_list(
      Rwcal.CloudAccount account,
      out Rwcal.VNFResources resources);


    public abstract void create_vdu(
      Rwcal.CloudAccount account,
      Rwcal.VDUInitParams vdu_params,
      out RwcalStatus status,
      out string vdu_id);

    public abstract RwTypes.RwStatus modify_vdu(
      Rwcal.CloudAccount account,
      Rwcal.VDUModifyParams vdu_params);
    
    public abstract RwTypes.RwStatus delete_vdu(
      Rwcal.CloudAccount account,
      string vdu_id);

    public abstract RwTypes.RwStatus get_vdu(
      Rwcal.CloudAccount account,
      string vdu_id,
      out Rwcal.VDUInfoParams response);
    
    public abstract RwTypes.RwStatus get_vdu_list(
      Rwcal.CloudAccount account,
      out Rwcal.VNFResources resources);
    
  }
}


