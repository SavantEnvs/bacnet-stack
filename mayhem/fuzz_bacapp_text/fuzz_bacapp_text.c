/* ASCII (command-line / config text) parsers: first byte selects the parser, rest is the text. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/bacapp.h"
#include "bacnet/bacstr.h"
#include "bacnet/bacaddr.h"
#include "bacnet/bacdest.h"
#include "bacnet/hostnport.h"
#include "bacnet/lighting.h"
#include "bacnet/timer_value.h"
#include "bacnet/channel_value.h"
#include "bacnet/access_rule.h"
#include "bacnet/shed_level.h"
#include "bacnet/datalink/bvlc.h"
#include "bacnet/datalink/bvlc6.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char *text, *p;
    char out[256];
    unsigned selector;

    if (size < 2) {
        return -1;
    }
    selector = data[0];
    text = (char *)malloc(size);
    if (!text) {
        return -1;
    }
    memcpy(text, data + 1, size - 1);
    text[size - 1] = 0;

    switch (selector % 14) {
        case 0: /* every application tag, tag chosen by the second byte */
        case 1: {
            BACNET_APPLICATION_DATA_VALUE value;
            BACNET_OBJECT_PROPERTY_VALUE opv;
            uint8_t apdu[MAX_APDU];
            unsigned tag = (unsigned char)text[0] % (MAX_BACNET_APPLICATION_TAG + 1);

            memset(&value, 0, sizeof(value));
            if (bacapp_parse_application_data(tag, text + 1, &value)) {
                memset(&opv, 0, sizeof(opv));
                opv.object_type = OBJECT_ANALOG_VALUE;
                opv.object_instance = 1;
                opv.object_property = PROP_PRESENT_VALUE;
                opv.array_index = BACNET_ARRAY_ALL;
                opv.value = &value;
                (void)bacapp_snprintf_value(out, sizeof(out), &opv);
                if (bacapp_encode_application_data(NULL, &value) <= (int)sizeof(apdu)) {
                    (void)bacapp_encode_application_data(apdu, &value);
                }
            }
            break;
        }
        case 2: {
            BACNET_PRIMITIVE_DATA_VALUE prim;

            memset(&prim, 0, sizeof(prim));
            prim.tag = (unsigned char)text[0] % (MAX_BACNET_APPLICATION_TAG + 1);
            (void)bacapp_parse_primitive_value(text + 1, &prim);
            break;
        }
        case 3: {
            BACNET_LIGHTING_COMMAND lc;

            memset(&lc, 0, sizeof(lc));
            if (lighting_command_from_ascii(&lc, text)) {
                (void)lighting_command_to_ascii(&lc, out, sizeof(out));
            }
            break;
        }
        case 4: {
            BACNET_TIMER_STATE_CHANGE_VALUE tv;
            uint8_t tag = 0;

            memset(&tv, 0, sizeof(tv));
            if (bacnet_timer_value_from_ascii(&tv, text)) {
                (void)bacnet_timer_value_to_ascii(&tv, out, sizeof(out));
            }
            (void)bacnet_timer_value_no_value_from_ascii(&tag, text);
            break;
        }
        case 5: {
            const char *trim_set = " \t\r\n,";

            (void)bacnet_ltrim(text, trim_set);
            p = bacnet_rtrim(text, trim_set);
            (void)p;
            p = bacnet_trim(text, trim_set);
            (void)p;
            break;
        }
        case 6: {
            BACNET_ADDRESS addr;
            BACNET_MAC_ADDRESS mac;

            (void)bacnet_address_from_ascii(&addr, text);
            (void)bacnet_address_mac_from_ascii(&mac, text);
            break;
        }
        case 7: {
            BACNET_DESTINATION dest;
            BACNET_RECIPIENT rcpt;
            BACNET_ADDRESS addr;

            memset(&dest, 0, sizeof(dest));
            memset(&rcpt, 0, sizeof(rcpt));
            (void)bacnet_destination_from_ascii(&dest, text);
            (void)bacnet_recipient_from_ascii(&rcpt, text);
            (void)bacnet_recipient_address_from_ascii(&addr, text);
            break;
        }
        case 8: {
            BACNET_HOST_N_PORT hp;
            BACNET_BDT_ENTRY bdt;
            BACNET_FDT_ENTRY fdt;

            memset(&hp, 0, sizeof(hp));
            memset(&bdt, 0, sizeof(bdt));
            memset(&fdt, 0, sizeof(fdt));
            (void)host_n_port_from_ascii(&hp, text);
            (void)bacnet_bdt_entry_from_ascii(&bdt, text);
            (void)bacnet_fdt_entry_from_ascii(&fdt, text);
            break;
        }
        case 9: {
            BACNET_IP_ADDRESS ip;
            BACNET_IP6_ADDRESS ip6;
            char *port_text = strchr(text, ' ');

            (void)bvlc_address_from_ascii(&ip, text);
            if (port_text) {
                *port_text++ = 0;
                (void)bvlc_address_port_from_ascii(&ip, text, port_text);
            }
            (void)bvlc6_address_from_ascii(&ip6, text);
            break;
        }
        case 10: {
            BACNET_CHANNEL_VALUE cv;
            BACNET_ACCESS_RULE ar;
            BACNET_SHED_LEVEL sl;

            memset(&cv, 0, sizeof(cv));
            memset(&ar, 0, sizeof(ar));
            memset(&sl, 0, sizeof(sl));
            (void)bacnet_channel_value_from_ascii(&cv, text);
            (void)bacnet_access_rule_from_ascii(&ar, text);
            (void)bacnet_shed_level_from_ascii(&sl, text);
            break;
        }
        case 11: {
            BACNET_BIT_STRING bs, bs2;

            if (bitstring_init_ascii(&bs, text)) {
                bs2 = bs;
                (void)bitstring_same(&bs, &bs2);
            }
            break;
        }
        case 12: {
            BACNET_XY_COLOR xy;

            (void)xy_color_from_ascii(&xy, text);
            break;
        }
        default: {
            BACNET_ADDRESS_BINDING bind;

            memset(&bind, 0, sizeof(bind));
            (void)bacnet_address_binding_from_ascii(&bind, text);
            break;
        }
    }
    free(text);
    return 0;
}
