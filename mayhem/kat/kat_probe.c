/* Known-answer probe: encodes fixed values with the stack and prints the bytes as hex. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "bacnet/bacdcode.h"
#include "bacnet/bacstr.h"
#include "bacnet/whois.h"
#include "bacnet/rp.h"

static void hex(const char *label, const uint8_t *buf, int len)
{
    int i;
    printf("%s", label);
    for (i = 0; i < len; i++) {
        printf(" %02X", buf[i]);
    }
    printf("\n");
}

int main(void)
{
    uint8_t apdu[64];
    int len;
    BACNET_CHARACTER_STRING cs;
    BACNET_READ_PROPERTY_DATA rpdata, out;
    uint8_t invoke = 0;

    len = encode_application_unsigned(apdu, 1000);
    hex("UNSIGNED_1000:", apdu, len);
    len = encode_application_signed(apdu, -2);
    hex("SIGNED_-2:", apdu, len);
    len = encode_application_real(apdu, 1.0f);
    hex("REAL_1.0:", apdu, len);
    characterstring_init_ansi(&cs, "abc");
    len = encode_application_character_string(apdu, &cs);
    hex("CHARSTRING_abc:", apdu, len);
    len = whois_encode_apdu(apdu, 10, 20);
    hex("WHOIS_10_20:", apdu, len);
    memset(&rpdata, 0, sizeof(rpdata));
    rpdata.object_type = OBJECT_ANALOG_INPUT;
    rpdata.object_instance = 5;
    rpdata.object_property = PROP_PRESENT_VALUE;
    rpdata.array_index = BACNET_ARRAY_ALL;
    len = rp_encode_apdu(apdu, 1, &rpdata);
    hex("RP_AI5_PV:", apdu, len);
    memset(&out, 0, sizeof(out));
    len = rp_decode_service_request(apdu + 4, (unsigned)(len - 4), &out);
    printf("RP_DECODE: %d type=%d instance=%u property=%d\n", len,
        (int)out.object_type, (unsigned)out.object_instance,
        (int)out.object_property);
    (void)invoke;
    return 0;
}
