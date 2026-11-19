/* APDU service-request / application-data decoders: first byte selects the decoder. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/bacapp.h"
#include "bacnet/bacdcode.h"
#include "bacnet/bacstr.h"
#include "bacnet/alarm_ack.h"
#include "bacnet/arf.h"
#include "bacnet/awf.h"
#include "bacnet/authentication_factor.h"
#include "bacnet/cov.h"
#include "bacnet/create_object.h"
#include "bacnet/dcc.h"
#include "bacnet/delete_object.h"
#include "bacnet/event.h"
#include "bacnet/getevent.h"
#include "bacnet/iam.h"
#include "bacnet/ihave.h"
#include "bacnet/lighting.h"
#include "bacnet/list_element.h"
#include "bacnet/lso.h"
#include "bacnet/ptransfer.h"
#include "bacnet/rd.h"
#include "bacnet/readrange.h"
#include "bacnet/rp.h"
#include "bacnet/rpm.h"
#include "bacnet/timer_value.h"
#include "bacnet/timesync.h"
#include "bacnet/whohas.h"
#include "bacnet/whois.h"
#include "bacnet/wp.h"
#include "bacnet/bacerror.h"
#include "bacnet/abort.h"
#include "bacnet/reject.h"
#include "bacnet/npdu.h"
#include "bacnet/apdu.h"

#define NDECODERS 38

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *buf;
    unsigned len;
    unsigned selector;

    if (size < 1) {
        return -1;
    }
    selector = data[0] % NDECODERS;
    len = (unsigned)(size - 1);
    buf = (uint8_t *)malloc(len ? len : 1);
    if (!buf) {
        return -1;
    }
    memcpy(buf, data + 1, len);

    switch (selector) {
        case 0: {
            BACNET_ALARM_ACK_DATA d;
            memset(&d, 0, sizeof(d));
            (void)alarm_ack_decode_service_request(buf, len, &d);
            break;
        }
        case 1: {
            BACNET_ATOMIC_WRITE_FILE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)awf_decode_service_request(buf, len, &d);
            break;
        }
        case 2: {
            BACNET_ATOMIC_WRITE_FILE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)awf_ack_decode_service_request(buf, len, &d);
            break;
        }
        case 3: {
            BACNET_ATOMIC_READ_FILE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)arf_decode_service_request(buf, len, &d);
            break;
        }
        case 4: {
            BACNET_ATOMIC_READ_FILE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)arf_ack_decode_service_request(buf, len, &d);
            break;
        }
        case 5: {
            BACNET_COV_DATA d;
            BACNET_PROPERTY_VALUE pv[8];
            memset(&d, 0, sizeof(d));
            memset(pv, 0, sizeof(pv));
            bacapp_property_value_list_init(pv, 8);
            d.listOfValues = pv;
            (void)cov_notify_decode_service_request(buf, len, &d);
            break;
        }
        case 6: {
            BACNET_SUBSCRIBE_COV_DATA d;
            memset(&d, 0, sizeof(d));
            (void)cov_subscribe_decode_service_request(buf, len, &d);
            break;
        }
        case 7: {
            BACNET_SUBSCRIBE_COV_DATA d;
            memset(&d, 0, sizeof(d));
            (void)cov_subscribe_property_decode_service_request(buf, len, &d);
            break;
        }
        case 8: {
            BACNET_DELETE_OBJECT_DATA d;
            memset(&d, 0, sizeof(d));
            (void)delete_object_decode_service_request(buf, len, &d);
            break;
        }
        case 9: {
            BACNET_CREATE_OBJECT_DATA d;
            memset(&d, 0, sizeof(d));
            (void)create_object_decode_service_request(buf, len, &d);
            break;
        }
        case 10: {
            BACNET_EVENT_NOTIFICATION_DATA d;
            memset(&d, 0, sizeof(d));
            (void)event_notify_decode_service_request(buf, len, &d);
            break;
        }
        case 11: {
            BACNET_LIST_ELEMENT_DATA d;
            memset(&d, 0, sizeof(d));
            (void)list_element_decode_service_request(buf, len, &d);
            break;
        }
        case 12: {
            BACNET_OBJECT_ID oid;
            memset(&oid, 0, sizeof(oid));
            (void)getevent_decode_service_request(buf, len, &oid);
            break;
        }
        case 13: {
            BACNET_GET_EVENT_INFORMATION_DATA d[4];
            bool more = false;
            memset(d, 0, sizeof(d));
            for (int i = 0; i < 3; i++) {
                d[i].next = &d[i + 1];
            }
            (void)getevent_ack_decode_service_request(buf, (int)len, d, &more);
            break;
        }
        case 14: {
            BACNET_LSO_DATA d;
            memset(&d, 0, sizeof(d));
            (void)lso_decode_service_request(buf, len, &d);
            break;
        }
        case 15: {
            BACNET_I_HAVE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)ihave_decode_service_request(buf, len, &d);
            break;
        }
        case 16: {
            BACNET_PRIVATE_TRANSFER_DATA d;
            memset(&d, 0, sizeof(d));
            (void)ptransfer_decode_service_request(buf, len, &d);
            break;
        }
        case 17: {
            BACNET_REINITIALIZED_STATE st;
            BACNET_CHARACTER_STRING pw;
            memset(&st, 0, sizeof(st));
            memset(&pw, 0, sizeof(pw));
            (void)rd_decode_service_request(buf, len, &st, &pw);
            break;
        }
        case 18: {
            int32_t lo = 0, hi = 0;
            (void)whois_decode_service_request(buf, len, &lo, &hi);
            break;
        }
        case 19: {
            BACNET_WHO_HAS_DATA d;
            memset(&d, 0, sizeof(d));
            (void)whohas_decode_service_request(buf, len, &d);
            break;
        }
        case 20: {
            uint16_t dur = 0;
            BACNET_COMMUNICATION_ENABLE_DISABLE en = COMMUNICATION_ENABLE;
            BACNET_CHARACTER_STRING pw;
            memset(&pw, 0, sizeof(pw));
            (void)dcc_decode_service_request(buf, len, &dur, &en, &pw);
            break;
        }
        case 21: {
            uint32_t id = 0;
            unsigned max_apdu = 0;
            int seg = 0;
            uint16_t vendor = 0;
            /* iam_decode_service_request has no length argument */
            if (len >= 4) {
                (void)bacnet_iam_request_decode(
                    buf, len, &id, &max_apdu, &seg, &vendor);
            }
            break;
        }
        case 22: {
            BACNET_WRITE_PROPERTY_DATA d;
            memset(&d, 0, sizeof(d));
            (void)wp_decode_service_request(buf, len, &d);
            break;
        }
        case 23: {
            BACNET_READ_PROPERTY_DATA d;
            memset(&d, 0, sizeof(d));
            (void)rp_decode_service_request(buf, len, &d);
            break;
        }
        case 24: {
            BACNET_RPM_DATA d;
            memset(&d, 0, sizeof(d));
            (void)rpm_decode_object_id(buf, len, &d);
            (void)rpm_decode_object_property(buf, len, &d);
            break;
        }
        case 25: {
            BACNET_READ_RANGE_DATA d;
            memset(&d, 0, sizeof(d));
            (void)rr_decode_service_request(buf, len, &d);
            break;
        }
        case 26: {
            BACNET_LIGHTING_COMMAND d;
            memset(&d, 0, sizeof(d));
            (void)lighting_command_decode(buf, len, &d);
            break;
        }
        case 27: {
            BACNET_TIMER_STATE_CHANGE_VALUE d;
            memset(&d, 0, sizeof(d));
            (void)bacnet_timer_value_decode(buf, len, &d);
            break;
        }
        case 28: {
            BACNET_AUTHENTICATION_FACTOR d;
            memset(&d, 0, sizeof(d));
            (void)bacnet_authentication_factor_decode(buf, len, &d);
            break;
        }
        case 29: {
            BACNET_APPLICATION_DATA_VALUE v;
            memset(&v, 0, sizeof(v));
            (void)bacapp_decode_application_data(buf, len, &v);
            break;
        }
        case 30:
        case 31: {
            BACNET_APPLICATION_DATA_VALUE v;
            BACNET_OBJECT_TYPE t = (BACNET_OBJECT_TYPE)(len > 1 ? buf[0] % 64 : 0);
            BACNET_PROPERTY_ID p = (BACNET_PROPERTY_ID)(len > 2 ? buf[1] * 3 + buf[2] % 3 : 0);
            memset(&v, 0, sizeof(v));
            if (len > 3) {
                (void)bacapp_decode_known_property(buf + 3, (int)len - 3, &v, t, p);
            }
            break;
        }
        case 32: {
            BACNET_APPLICATION_DATA_VALUE v;
            BACNET_PROPERTY_ID p = (BACNET_PROPERTY_ID)(len > 0 ? buf[0] : 0);
            memset(&v, 0, sizeof(v));
            if (len > 1) {
                (void)bacapp_decode_context_data(buf + 1, len - 1, &v, p);
            }
            break;
        }
        case 33: {
            BACNET_APPLICATION_DATA_VALUE v;
            BACNET_APPLICATION_TAG tag =
                (BACNET_APPLICATION_TAG)(len > 0 ? buf[0] % (MAX_BACNET_APPLICATION_TAG + 1) : 0);
            memset(&v, 0, sizeof(v));
            if (len > 1) {
                (void)bacapp_decode_application_tag_value(buf + 1, len - 1, tag, &v);
            }
            break;
        }
        case 34: {
            BACNET_DATE date;
            BACNET_TIME time;
            (void)timesync_decode_service_request(buf, len, &date, &time);
            break;
        }
        case 35: {
            uint8_t invoke = 0;
            BACNET_CONFIRMED_SERVICE service = SERVICE_CONFIRMED_READ_PROPERTY;
            BACNET_ERROR_CLASS ec = ERROR_CLASS_DEVICE;
            BACNET_ERROR_CODE ecode = ERROR_CODE_OTHER;
            (void)bacerror_decode_service_request(
                buf, len, &invoke, &service, &ec, &ecode);
            break;
        }
        case 36: {
            BACNET_ADDRESS dest, src;
            BACNET_NPDU_DATA npdu;
            memset(&dest, 0, sizeof(dest));
            memset(&src, 0, sizeof(src));
            memset(&npdu, 0, sizeof(npdu));
            (void)bacnet_npdu_decode(buf, len, &dest, &src, &npdu);
            break;
        }
        default: {
            BACNET_APPLICATION_DATA_VALUE v;
            memset(&v, 0, sizeof(v));
            (void)bacapp_decode_application_data_safe(buf, len, &v);
            break;
        }
    }
    free(buf);
    return 0;
}
