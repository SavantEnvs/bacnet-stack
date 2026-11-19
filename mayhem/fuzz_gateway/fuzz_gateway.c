/*
 * The BACnet gateway's receive path, as in apps/gateway/main.c: every received NPDU goes to
 * routing_npdu_handler() (src/bacnet/basic/npdu/h_routed_npdu.c), which reaches its static
 * network_control_handler() (Who-Is-Router-To-Network, Initialize-Routing-Table, What-Is-Network-
 * Number, ...) and routed_apdu_handler(), which picks the addressed gateway or virtual Device
 * (gw_device.c Routed_Device_GetNext) and runs the APDU handlers apps/gateway registers
 * (Who-Is, Who-Has, ReadProperty, RPM, WriteProperty, ReadRange, ReinitializeDevice, time sync,
 * SubscribeCOV, DeviceCommunicationControl) against it. Replies go nowhere (no BIP socket open).
 *
 * The gateway is set up the way apps/gateway/main.c does: Device_Init + Routing_Device_Init, the
 * gateway Device plus MAX_NUM_DEVICES-1 routed Devices (Add_Routed_Device), their addresses as
 * Initialize_Device_Addresses() assigns them, and DNET_list = { VIRTUAL_DNET, -1 }.
 *
 * Each input's result depends only on that input: before every input the whole gateway is rebuilt
 * (Device_Init re-runs every object's Init - the object table is the Device and Network Port, see
 * Gateway_Object_Table -, Routing_Device_Init resets the routed Device table
 * with Routed_Device_Table_Reset, and the routed Devices are re-added), the device.c values a
 * WriteProperty can set and Device_Init does not touch are restored from a baseline captured once,
 * and the COV subscriptions, the address cache and DCC are reset. State kept on purpose: the
 * time-sync handlers have no callback registered (as in apps/gateway), so they change nothing,
 * and no CreateObject handler is registered, so the (empty) object lists cannot grow.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/bacdef.h"
#include "bacnet/bacdcode.h"
#include "bacnet/apdu.h"
#include "bacnet/dcc.h"
#include "bacnet/npdu.h"
#include "bacnet/datalink/datalink.h"
#include "bacnet/datalink/bip.h"
#include "bacnet/basic/binding/address.h"
#include "bacnet/basic/npdu/h_routed_npdu.h"
#include "bacnet/basic/services.h"
#include "bacnet/basic/service/h_apdu.h"
#include "bacnet/basic/service/h_cov.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/basic/object/netport.h"

/* apps/gateway/gateway.h */
#define FIRST_DEVICE_NUMBER 260001
#define VIRTUAL_DNET 2709
#define DEV_NAME_BASE "Gateway Demo Device"
#define DEV_DESCR_GATEWAY "Gateway Device and Router"
#define DEV_DESCR_REMOTE "Routed Remote Device"

/* apps/gateway/main.c: the list of DNETs the gateway can reach, -1 terminated */
static int32_t DNET_list[2] = { VIRTUAL_DNET, -1 };

/* device.c values a WriteProperty to the gateway Device can change that Device_Init() leaves
 * alone (gw_device.c handles Object_Identifier/Name, Description, Model_Name, Location and
 * Vendor_Identifier itself, in the routed Device table that is rebuilt every input). */
static struct {
    BACNET_DEVICE_STATUS system_status;
    int32_t utc_offset;
    uint16_t apdu_timeout;
    uint8_t apdu_retries;
    uint8_t apdu_priority;
    uint16_t network_number;
    uint8_t network_number_status;
    BACNET_RESTART_REASON restart_reason;
    uint32_t database_revision;
    BACNET_TIMESTAMP time_of_restart;
    char location[MAX_DEV_LOC_LEN + 1];
    char description[MAX_DEV_DESC_LEN + 1];
    char model_name[MAX_DEV_MOD_LEN + 1];
} Baseline;

/* apps/gateway/main.c Init_Service_Handlers(), without Device_Init/Routing_Device_Init */
static void init_service_handlers(void)
{
    apdu_set_unconfirmed_handler(
        SERVICE_UNCONFIRMED_WHO_IS, handler_who_is_unicast);
    apdu_set_unconfirmed_handler(SERVICE_UNCONFIRMED_WHO_HAS, handler_who_has);
    apdu_set_unrecognized_service_handler_handler(handler_unrecognized_service);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_READ_PROPERTY, handler_read_property);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_READ_PROP_MULTIPLE, handler_read_property_multiple);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_WRITE_PROPERTY, handler_write_property);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_READ_RANGE, handler_read_range);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_REINITIALIZE_DEVICE, handler_reinitialize_device);
    apdu_set_unconfirmed_handler(
        SERVICE_UNCONFIRMED_UTC_TIME_SYNCHRONIZATION, handler_timesync_utc);
    apdu_set_unconfirmed_handler(
        SERVICE_UNCONFIRMED_TIME_SYNCHRONIZATION, handler_timesync);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_SUBSCRIBE_COV, handler_cov_subscribe);
    apdu_set_confirmed_handler(
        SERVICE_CONFIRMED_DEVICE_COMMUNICATION_CONTROL,
        handler_device_communication_control);
}

/* apps/gateway/main.c Devices_Init() */
static void devices_init(uint32_t first_object_instance)
{
    int i;
    char nameText[MAX_DEV_NAME_LEN];
    char descText[MAX_DEV_DESC_LEN];
    BACNET_CHARACTER_STRING name_string;

    Routed_Device_Set_Description(DEV_DESCR_GATEWAY, strlen(DEV_DESCR_GATEWAY));
    for (i = 1; i < MAX_NUM_DEVICES; i++) {
        snprintf(nameText, MAX_DEV_NAME_LEN, "%s %d", DEV_NAME_BASE, i + 1);
        snprintf(descText, MAX_DEV_DESC_LEN, "%s %d", DEV_DESCR_REMOTE, i);
        characterstring_init_ansi(&name_string, nameText);
        Add_Routed_Device((first_object_instance + i), &name_string, descText);
    }
}

/* apps/gateway/main.c Initialize_Device_Addresses(), without the startup I-Am broadcast */
static void initialize_device_addresses(void)
{
    int i;
    uint32_t virtual_mac;
    BACNET_ADDRESS virtual_address = { 0 };
    DEVICE_OBJECT_DATA *pDev = Get_Routed_Device_Object(0);

    bip_get_my_address(&virtual_address);
    bacnet_address_copy(&pDev->bacDevAddr, &virtual_address);
    for (i = 1; i < MAX_NUM_DEVICES; i++) {
        pDev = Get_Routed_Device_Object(i);
        if (pDev == NULL) {
            continue;
        }
        bacnet_address_copy(&pDev->bacDevAddr, &virtual_address);
        pDev->bacDevAddr.net = VIRTUAL_DNET;
        virtual_mac = pDev->bacObj.Object_Instance_Number;
        encode_unsigned24(&pDev->bacDevAddr.adr[0], virtual_mac);
        pDev->bacDevAddr.len = 3;
    }
    /* the gateway Device is the current one between messages */
    (void)Get_Routed_Device_Object(0);
}

/* The gateway's object table: device.c's Default_Object_Table entries for the Device (whose
 * functions Routing_Device_Init() replaces with the routed ones) and the Network Port, the two
 * objects apps/gateway has instances of whose Init resets them. The other objects that table gives
 * the gateway with instances (Trend Log x8, Access Door/Point/Rights/User/Zone/Credential and
 * Credential Data Input x4) initialise only once per process (a static "initialized" flag), so a
 * WriteProperty to them would leak into later inputs; their services are fuzzed by fuzz_npdu. */
static object_functions_t Gateway_Object_Table[] = {
    { OBJECT_DEVICE, NULL /* Init - don't init Device or it will recourse! */,
      Device_Count, Device_Index_To_Instance,
      Device_Valid_Object_Instance_Number, Device_Object_Name,
      Device_Read_Property_Local, Device_Write_Property_Local,
      Device_Property_Lists, DeviceGetRRInfo, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, Device_Writable_Property_List },
    { OBJECT_NETWORK_PORT, Network_Port_Init, Network_Port_Count,
      Network_Port_Index_To_Instance, Network_Port_Valid_Instance,
      Network_Port_Object_Name, Network_Port_Read_Property,
      Network_Port_Write_Property, Network_Port_Property_Lists, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
      Network_Port_Writable_Property_List },
    { MAX_BACNET_OBJECT_TYPE, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

static void build_gateway(void)
{
    Device_Init(&Gateway_Object_Table[0]);
    Routing_Device_Init(FIRST_DEVICE_NUMBER);
    devices_init(FIRST_DEVICE_NUMBER);
    initialize_device_addresses();
}

static void capture_baseline(void)
{
    Baseline.system_status = Device_System_Status();
    Baseline.utc_offset = Device_UTC_Offset();
    Baseline.apdu_timeout = apdu_timeout();
    Baseline.apdu_retries = apdu_retries();
    Baseline.apdu_priority = apdu_network_priority();
    Baseline.network_number = npdu_network_number();
    Baseline.network_number_status = npdu_network_number_status();
    Baseline.restart_reason = Device_Last_Restart_Reason();
    Baseline.database_revision = Device_Database_Revision();
    Device_Time_Of_Restart(&Baseline.time_of_restart);
    snprintf(Baseline.location, sizeof(Baseline.location), "%s", Device_Location());
    snprintf(
        Baseline.description, sizeof(Baseline.description), "%s",
        Device_Description());
    snprintf(
        Baseline.model_name, sizeof(Baseline.model_name), "%s",
        Device_Model_Name());
}

static void reset_gateway(void)
{
    build_gateway();
    (void)Device_Set_System_Status(Baseline.system_status, true);
    (void)Device_UTC_Offset_Set((int16_t)Baseline.utc_offset);
    apdu_timeout_set(Baseline.apdu_timeout);
    apdu_retries_set(Baseline.apdu_retries);
    apdu_network_priority_set(Baseline.apdu_priority);
    npdu_network_number_set(Baseline.network_number);
    npdu_network_number_status_set(Baseline.network_number_status);
    (void)Device_Last_Restart_Reason_Set(Baseline.restart_reason);
    Device_Set_Database_Revision(Baseline.database_revision);
    (void)Device_Set_Time_Of_Restart(&Baseline.time_of_restart);
    (void)Device_Set_Location(Baseline.location, strlen(Baseline.location));
    (void)Device_Set_Description(
        Baseline.description, strlen(Baseline.description));
    (void)Device_Set_Model_Name(
        Baseline.model_name, strlen(Baseline.model_name));
    (void)Device_Reinitialize_State_Set(BACNET_REINIT_IDLE);
    (void)dcc_set_status_duration(COMMUNICATION_ENABLE, 0);
    /* COV subscriptions and the COV address table */
    handler_cov_init();
    /* I-Am bindings */
    address_init();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    init_service_handlers();
    build_gateway();
    capture_baseline();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* where a BACnet/IP datagram came from, as datalink_receive() would fill it in */
    BACNET_ADDRESS src = { 0 };
    uint8_t *pdu;

    /* apps/gateway/main.c only calls routing_npdu_handler() for a non-empty PDU
     * (`if (pdu_len)`) of at most MAX_MPDU octets (its Rx_Buf, passed to datalink_receive()). */
    if (size == 0 || size > MAX_MPDU) {
        return -1;
    }
    reset_gateway();
    src.mac_len = 6; /* 192.168.0.2:47808 */
    src.mac[0] = 192;
    src.mac[1] = 168;
    src.mac[2] = 0;
    src.mac[3] = 2;
    src.mac[4] = 0xBA;
    src.mac[5] = 0xC0;
    /* exact-size private copy: the handler takes a writable buffer */
    pdu = (uint8_t *)malloc(size);
    if (!pdu) {
        return 0;
    }
    memcpy(pdu, data, size);
    routing_npdu_handler(&src, DNET_list, pdu, (uint16_t)size);
    free(pdu);
    return 0;
}
