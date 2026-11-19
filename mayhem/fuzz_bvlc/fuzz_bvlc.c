/* BACnet/IP BVLC datagrams through the BBMD (BDT/FDT) handlers. Bytes 0-5: sender IPv4 + port. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/datalink/bvlc.h"
#include "bacnet/basic/bbmd/h_bbmd.h"

static void reset_bbmd(void)
{
    bvlc_bdt_list_clear();
    /* age out every foreign-device registration (two ticks of the max step) */
    bvlc_maintenance_timer(65535);
    bvlc_maintenance_timer(65535);
    bvlc_bbmd_accept_fd_registrations_set(true);
    bvlc_set_last_result(0);
    bvlc_set_function_code(0);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    bvlc_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    BACNET_IP_ADDRESS addr;
    BACNET_ADDRESS src;
    uint8_t *buf;
    size_t len;
    int offset;

    if (size < 7 || size > 1600) {
        return -1;
    }
    reset_bbmd();
    memset(&addr, 0, sizeof(addr));
    memset(&src, 0, sizeof(src));
    memcpy(addr.address, data, 4);
    addr.port = (uint16_t)((data[4] << 8) | data[5]);
    len = size - 6;
    buf = (uint8_t *)malloc(len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, data + 6, len);
    offset = bvlc_handler(&addr, &src, buf, (uint16_t)len);
    if (offset > 0 && (size_t)offset <= len) {
        (void)buf[len - 1];
    }
    free(buf);
    buf = (uint8_t *)malloc(len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, data + 6, len);
    (void)bvlc_broadcast_handler(&addr, &src, buf, (uint16_t)len);
    free(buf);
    reset_bbmd();
    return 0;
}
