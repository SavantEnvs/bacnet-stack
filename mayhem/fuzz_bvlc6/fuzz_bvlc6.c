/* BACnet/IPv6 BVLC6 datagrams through the BBMD6/VMAC handlers. Bytes 0-17: sender IPv6 + port. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/datalink/bvlc6.h"
#include "bacnet/basic/bbmd6/h_bbmd6.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    BACNET_IP6_ADDRESS addr;
    BACNET_ADDRESS src;
    uint8_t *buf;
    size_t len;

    if (size < 19 || size > 1600) {
        return -1;
    }
    bvlc6_cleanup();
    bvlc6_init();
    memset(&addr, 0, sizeof(addr));
    memset(&src, 0, sizeof(src));
    memcpy(addr.address, data, 16);
    addr.port = (uint16_t)((data[16] << 8) | data[17]);
    len = size - 18;
    buf = (uint8_t *)malloc(len);
    if (!buf) {
        return -1;
    }
    memcpy(buf, data + 18, len);
    (void)bvlc6_handler(&addr, &src, buf, (uint16_t)len);
    free(buf);
    bvlc6_cleanup();
    return 0;
}
