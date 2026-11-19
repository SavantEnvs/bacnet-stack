/*
 * MS/TP datalink (receive + master/slave node state machines) driven by a fake RS-485 driver that
 * replays the fuzz input as the serial byte stream. Byte 0: station address; byte 1 bit 0: slave mode.
 */
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "bacnet/bacdef.h"
#include "bacnet/datalink/mstp.h"
#include "bacnet/datalink/dlmstp.h"

static uint8_t RS485_Rx_Buffer[DLMSTP_MPDU_MAX];
static uint8_t RS485_Tx_Buffer[DLMSTP_MPDU_MAX];
static struct mstp_port_struct_t MSTP_Port;
static struct dlmstp_user_data_t MSTP_User;

static const uint8_t *Stream;
static size_t Stream_Size;
static size_t Stream_Index;
static uint32_t Silence_Ms;

static void drv_init(void)
{
}
static void drv_send(const uint8_t *payload, uint16_t payload_len)
{
    (void)payload;
    (void)payload_len;
}
static bool drv_read(uint8_t *buf)
{
    if (Stream_Index >= Stream_Size) {
        return false;
    }
    if (buf) {
        *buf = Stream[Stream_Index++];
    }
    return true;
}
static bool drv_transmitting(void)
{
    return false;
}
static uint32_t drv_baud_rate(void)
{
    return 38400;
}
static bool drv_baud_rate_set(uint32_t baud)
{
    (void)baud;
    return true;
}
static uint32_t drv_silence_ms(void)
{
    /* deterministic clock: every query advances it, so timeouts expire */
    Silence_Ms += 7;
    return Silence_Ms;
}
static void drv_silence_reset(void)
{
    Silence_Ms = 0;
}

static struct dlmstp_rs485_driver Driver = {
    .init = drv_init,
    .send = drv_send,
    .read = drv_read,
    .transmitting = drv_transmitting,
    .baud_rate = drv_baud_rate,
    .baud_rate_set = drv_baud_rate_set,
    .silence_milliseconds = drv_silence_ms,
    .silence_reset = drv_silence_reset,
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    BACNET_ADDRESS src;
    static uint8_t pdu[DLMSTP_MPDU_MAX];
    size_t iterations, i;

    if (size < 3 || size > 4096) {
        return -1;
    }
    memset(&MSTP_Port, 0, sizeof(MSTP_Port));
    memset(&MSTP_User, 0, sizeof(MSTP_User));
    memset(RS485_Rx_Buffer, 0, sizeof(RS485_Rx_Buffer));
    memset(RS485_Tx_Buffer, 0, sizeof(RS485_Tx_Buffer));
    MSTP_User.RS485_Driver = &Driver;
    MSTP_Port.UserData = &MSTP_User;
    MSTP_Port.InputBuffer = RS485_Rx_Buffer;
    MSTP_Port.InputBufferSize = sizeof(RS485_Rx_Buffer);
    MSTP_Port.OutputBuffer = RS485_Tx_Buffer;
    MSTP_Port.OutputBufferSize = sizeof(RS485_Tx_Buffer);
    Silence_Ms = 0;
    Stream = data + 2;
    Stream_Size = size - 2;
    Stream_Index = 0;

    dlmstp_init((const char *)&MSTP_Port);
    dlmstp_set_mac_address(data[0] & 0x7F);
    dlmstp_set_max_master(127);
    (void)dlmstp_slave_mode_enabled_set((data[1] & 1) != 0);

    iterations = Stream_Size * 2 + 16;
    for (i = 0; i < iterations; i++) {
        (void)dlmstp_receive(&src, pdu, sizeof(pdu), 0);
    }
    return 0;
}
