/*
 * Link stubs for fuzz_libfuzzer, in the spirit of the "FIXME" stubs in upstream's
 * apps/fuzz-libfuzzer/main.c. Upstream's target links with -Wl,--gc-sections, which drops the
 * only callers of these Device_* functions (the AtomicReadFile/AtomicWriteFile, CreateObject and
 * DeleteObject handlers, which the harness never registers); with SanitizerCoverage those callers
 * are kept, so the symbols must exist. No input can reach them. Their real definitions live in the
 * server Device object (device.c / bacnet_device.c), which this router harness does not link.
 */
#include <stdbool.h>
#include <stdint.h>
#include "bacnet/create_object.h"
#include "bacnet/delete_object.h"
#include "bacnet/basic/object/device.h"

bool Device_Is_Configuration_File(uint32_t instance)
{
    (void)instance;
    return false;
}

void Device_Backup_Failure_Timeout_Restart(void)
{
}

bool Device_Create_Object(BACNET_CREATE_OBJECT_DATA *data)
{
    (void)data;
    return false;
}

bool Device_Delete_Object(BACNET_DELETE_OBJECT_DATA *data)
{
    (void)data;
    return false;
}
