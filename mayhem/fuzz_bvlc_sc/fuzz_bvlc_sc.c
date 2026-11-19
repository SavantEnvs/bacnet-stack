/* BACnet/SC BVLC-SC message decoder (pure codec, no websocket/TLS). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/datalink/bsc/bvlc-sc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    BVLC_SC_DECODED_MESSAGE msg;
    uint16_t error_code = 0, error_class = 0;
    const char *err_desc = NULL;
    uint8_t *buf;

    if (size < 1 || size > 4096) {
        return -1;
    }
    buf = (uint8_t *)malloc(size);
    if (!buf) {
        return -1;
    }
    memcpy(buf, data, size);
    memset(&msg, 0, sizeof(msg));
    (void)bvlc_sc_decode_message(
        buf, size, &msg, &error_code, &error_class, &err_desc);
    free(buf);
    return 0;
}
