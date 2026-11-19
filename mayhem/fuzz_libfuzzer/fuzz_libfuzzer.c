/*
 * Upstream's own libFuzzer harness, apps/fuzz-libfuzzer/main.c (built upstream by
 * `make fuzz-libfuzzer` with -DFUZZING=1), compiled unchanged: it #includes
 * apps/router-mstp/main.c and feeds each input to the router's my_routing_npdu_handler(),
 * which reaches network_control_handler(), routed_apdu_handler() and the routing table.
 *
 * Upstream's entry point is renamed with a #define so this file can wrap it, because the router
 * state lives in `static` variables of that translation unit. The wrapper adds two things:
 *   - Before each input, the two directly connected ports that router-mstp's datalink_init()
 *     configures by default (BACnet/IP network 1, MS/TP network 2, MS/TP MAC 127), without opening
 *     a socket or serial port. Upstream's harness skips datalink_init(), so its routing table is
 *     empty and every route lookup fails; with the ports in place the routing table code runs.
 *   - After each input, a reset of everything a message can change:
 *     - Router_Table_Head, the calloc'd routing table (I-Am-Router-To-Network and routed messages
 *       add DNET entries to it), freed with router-mstp's own cleanup().
 *     - the I-Am address cache (handler_i_am_add) and the DeviceCommunicationControl state.
 * Nothing else a message can change is kept: the time-sync handlers have no callback registered
 * here, and write/reinitialize/COV are upstream's link stubs that change nothing.
 */
#define LLVMFuzzerTestOneInput bacnet_upstream_fuzz_one_input
#include "../../apps/fuzz-libfuzzer/main.c"
#undef LLVMFuzzerTestOneInput

#include "bacnet/dcc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void add_default_ports(void)
{
    BACNET_ADDRESS addr = { 0 };

    /* datalink_init() defaults: BACNET_IP_NET=1, BACNET_MSTP_NET=2, BACNET_MSTP_MAC=127 */
    BIP_Net = 1;
    MSTP_Net = 2;
    addr.mac_len = 6; /* 192.168.0.1:47808 (0xBAC0), the address bip_get_my_address() would give */
    addr.mac[0] = 192;
    addr.mac[1] = 168;
    addr.mac[2] = 0;
    addr.mac[3] = 1;
    addr.mac[4] = 0xBA;
    addr.mac[5] = 0xC0;
    port_add(BIP_Net, &addr);
    memset(&addr, 0, sizeof(addr));
    addr.mac_len = 1;
    addr.mac[0] = 127;
    port_add(MSTP_Net, &addr);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t *copy;

    add_default_ports();

    /* upstream's handler takes a writable buffer; give it a private copy of the input */
    copy = (uint8_t *)malloc(size ? size : 1);
    if (copy) {
        if (size) {
            memcpy(copy, data, size);
        }
        (void)bacnet_upstream_fuzz_one_input(copy, size);
        free(copy);
    }

    cleanup();
    Router_Table_Head = NULL;
    address_init();
    (void)dcc_set_status_duration(COMMUNICATION_ENABLE, 0);
    return 0;
}
