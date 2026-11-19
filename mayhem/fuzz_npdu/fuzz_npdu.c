/*
 * Full receive path of a BACnet device: NPDU -> APDU -> confirmed/unconfirmed service handlers
 * (ReadProperty, RPM, WriteProperty, WPM, CreateObject, DeleteObject, COV, DCC, ReinitializeDevice,
 * Who-Is/Who-Has, time sync, ...) against the server-basic Device holding one instance of every
 * object type the stack can create. Replies go nowhere (the BIP socket is closed).
 * Everything an input can change is reset per input (see reset_device), including the BACnet
 * clock offset a TimeSynchronization or Local_Date/Local_Time write sets; the only state kept is
 * the OS clock itself and library-internal counters that no message can set.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "bacnet/bacdef.h"
#include "bacnet/datalink/datalink.h"
#include "bacnet/create_object.h"
#include "bacnet/datetime.h"
#include "bacnet/dcc.h"
#include "bacnet/apdu.h"
#include "bacnet/basic/binding/address.h"
#include "bacnet/basic/npdu/h_npdu.h"
#include "bacnet/basic/service/h_apdu.h"
#include "bacnet/basic/service/h_cov.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/basic/server/bacnet_basic.h"

#define FUZZ_DEVICE_INSTANCE 1234
#define FUZZ_MAX_OBJECT_TYPE 64

static void create_fixture(void)
{
    BACNET_CREATE_OBJECT_DATA cod;
    unsigned type;

    for (type = 0; type < FUZZ_MAX_OBJECT_TYPE; type++) {
        if (type == OBJECT_DEVICE) {
            continue;
        }
        memset(&cod, 0, sizeof(cod));
        cod.object_type = (BACNET_OBJECT_TYPE)type;
        cod.object_instance = 1;
        (void)Device_Create_Object(&cod);
    }
}

/* Device settings a WriteProperty/WPM, Reinitialize, time-sync or Network-Number-Is message can
 * change. Captured once after bacnet_basic_init() and restored before every input, so no input sees
 * what an earlier one wrote. */
static struct {
    char location[MAX_DEV_LOC_LEN + 1];
    char description[MAX_DEV_DESC_LEN + 1];
    char model_name[MAX_DEV_MOD_LEN + 1];
    BACNET_DEVICE_STATUS system_status;
    uint16_t vendor_id;
    int32_t utc_offset;
    uint16_t apdu_timeout;
    uint8_t apdu_retries;
    uint8_t apdu_priority;
    uint16_t network_number;
    uint8_t network_number_status;
    BACNET_RESTART_REASON restart_reason;
    uint32_t database_revision;
    BACNET_TIMESTAMP time_of_restart;
} Baseline;

/* datetime_timesync() (TimeSynchronization, UTCTimeSynchronization, Local_Date/Local_Time writes)
 * stores a permanent offset from the OS clock in ports/linux/datetime-init.c. Syncing to the OS
 * clock's own local time puts the offset back to under 10 ms. */
static void reset_clock_offset(void)
{
    struct timeval tv;
    struct tm tm;
    BACNET_DATE bdate;
    BACNET_TIME btime;

    if (gettimeofday(&tv, NULL) != 0 || !localtime_r(&tv.tv_sec, &tm)) {
        return;
    }
    bdate.year = (uint16_t)(tm.tm_year + 1900);
    bdate.month = (uint8_t)(tm.tm_mon + 1);
    bdate.day = (uint8_t)tm.tm_mday;
    bdate.wday = (uint8_t)(tm.tm_wday == 0 ? 7 : tm.tm_wday);
    btime.hour = (uint8_t)tm.tm_hour;
    btime.min = (uint8_t)tm.tm_min;
    btime.sec = (uint8_t)tm.tm_sec;
    btime.hundredths = (uint8_t)(tv.tv_usec / 10000);
    datetime_timesync(&bdate, &btime, false);
}

static void capture_baseline(void)
{
    snprintf(Baseline.location, sizeof(Baseline.location), "%s", Device_Location());
    snprintf(
        Baseline.description, sizeof(Baseline.description), "%s",
        Device_Description());
    snprintf(
        Baseline.model_name, sizeof(Baseline.model_name), "%s",
        Device_Model_Name());
    Baseline.system_status = Device_System_Status();
    Baseline.vendor_id = Device_Vendor_Identifier();
    Baseline.utc_offset = Device_UTC_Offset();
    Baseline.apdu_timeout = apdu_timeout();
    Baseline.apdu_retries = apdu_retries();
    Baseline.apdu_priority = apdu_network_priority();
    Baseline.network_number = npdu_network_number();
    Baseline.network_number_status = npdu_network_number_status();
    Baseline.restart_reason = Device_Last_Restart_Reason();
    Baseline.database_revision = Device_Database_Revision();
    Device_Time_Of_Restart(&Baseline.time_of_restart);
}

static void reset_device(void)
{
    Device_Delete_Objects();
    (void)Device_Set_Object_Instance_Number(FUZZ_DEVICE_INSTANCE);
    (void)Device_Object_Name_ANSI_Init("fuzz-device");
    (void)dcc_set_status_duration(COMMUNICATION_ENABLE, 0);
    /* COV subscriptions and the COV address table (clears both, keeps the lists allocated) */
    handler_cov_init();
    /* I-Am bindings */
    address_init();
    (void)Device_Set_Location(Baseline.location, strlen(Baseline.location));
    (void)Device_Set_Description(
        Baseline.description, strlen(Baseline.description));
    (void)Device_Set_Model_Name(
        Baseline.model_name, strlen(Baseline.model_name));
    (void)Device_Set_System_Status(Baseline.system_status, true);
    Device_Set_Vendor_Identifier(Baseline.vendor_id);
    (void)Device_UTC_Offset_Set((int16_t)Baseline.utc_offset);
    apdu_timeout_set(Baseline.apdu_timeout);
    apdu_retries_set(Baseline.apdu_retries);
    apdu_network_priority_set(Baseline.apdu_priority);
    npdu_network_number_set(Baseline.network_number);
    npdu_network_number_status_set(Baseline.network_number_status);
    (void)Device_Last_Restart_Reason_Set(Baseline.restart_reason);
    Device_Set_Database_Revision(Baseline.database_revision);
    (void)Device_Set_Time_Of_Restart(&Baseline.time_of_restart);
    (void)Device_Reinitialize_State_Set(BACNET_REINIT_IDLE);
    reset_clock_offset();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    bacnet_basic_init();
    capture_baseline();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    BACNET_ADDRESS src;
    uint8_t *pdu;

    if (size < 2 || size > MAX_MPDU) {
        return -1;
    }
    reset_device();
    create_fixture();
    memset(&src, 0, sizeof(src));
    src.mac_len = 6;
    src.mac[0] = 192;
    src.mac[1] = 168;
    src.mac[2] = 0;
    src.mac[3] = 10;
    src.mac[4] = 0xBA;
    src.mac[5] = 0xC0;
    pdu = (uint8_t *)malloc(size);
    if (!pdu) {
        return -1;
    }
    memcpy(pdu, data, size);
    npdu_handler(&src, pdu, (uint16_t)size);
    free(pdu);
    reset_device();
    return 0;
}
