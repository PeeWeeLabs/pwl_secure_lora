/*
 * Copyright (c) PeeWee Labs All rights reserved.
 * Licensed under the MIT License.
 * See LICENSE file in the project root for full license information.
 */

#ifndef _PWLSecureLora_H
#define _PWLSecureLora_H
#include <pwl_rfm9X.h>

// Timeout and retry values
#define PWL_SL_SEND_RETRY_LIMIT    3
#define PWL_SL_ACKWAIT_TIMEOUT_MS  250

// Care was taken in this code to prevent predictable data in the unencrypted
// packet.  Arbitrary number(s) used to offset new counters so that encrypted
// data isn't repeated.  These can be changed to increase the differences in
// your system vs. another system.
#define PWL_SL_ROLLING_CODE_SEED     8675309  // Jenny's Number
#define PWL_SL_RCODE_OFFSET             5309

/*
About:

    This driver implements a secure communication protocol between LoRa nodes
    with the same key (and within tx/rx distance).  Its original use was to
    implement reliable home automation nodes including temperature sensors,
    garage door openers, contact sensors and more.

    This driver is an extension of (and inherits from) the PeeWee Labs RFM_9X
    HopeRF LoRa driver.

Notes:

    The first 8 bytes of the TX payload are header and are managed by this
    driver.  That leaves about 244 bytes of possible payload available.

    The terms "source" and "sender" are used interchangeably.
    The terms "destination" and "receiver" are used interchangeably.

  Encryption / Security
    This driver uses XXTEA encryption that operates on a block of data that
    must be at least 8 bytes in length and be a multiple of 4 bytes.  i.e. 8,
    12, 16, 20...

    Assumptions
       * An outside party can receive and potentially repeat an encrypted
         packet.
       * The outside observer can not decode the encrypted packet to see the
         cleartext.
       * The outside observer does not know what the cleartext being sent is.

    * A "rolling code" is used to make sure that all packets sent are
      constantly changing even if the actual data is not changing.

    * A CRC is added to the encrypted data.  This serves to make sure the
      encrypted is not a random data attack.  This prevents random data from
      matching enough of the header to be treated as a good packet.

    * The secure destination processor maintains an expected value for the
      rolling code.

    * If an otherwise valid packet comes in from a sender that has an incorrect
      rolling code then the destination will send a NAK back with the correct
      rolling code.  This will allow for a sender to synchronize with the
      receiver.  This is still secure since an outside party can not tell what
      was in either the original packet nor the response.  If the outside party
      tries to send either of the encrypted packets that they observed the
      sender will ignore an unsolicited NAK and the receiver might try to send
      an encrypted NAK.

    Some devices may be fire and forget.  In these cases there is still a
    rolling code, but the receiver ignores it and accepts the data.  There is a
    risk that an outside party could record previous packets and send them as
    bogus data.  However, since this should only used for non-critical data it
    shouldn't matter.  You (the system designer) must use your judgment as to
    whether you want a device to be fire and forget or to have two way, more
    secure, communications.  These fire and forget packets will still look like
    random bytes to an outside party due to the encryption.  Given the
    assumption that the outside party can not determine the plain text of the
    packet their only attack is to re-send already encrypted packets they
    previously sniffed.

    The header described below is pre-pended to the user's send data when the
    packet is transmitted and it is removed from the user's receive data when
    the packet is received.  The source and destination addresses are available
    for the most recently received packet using the API calls.

    Header pre-pended to each packet:
    bits Ofst field description
    ---- ---- --------------------
    24     0  rolling_code
     4     3  flags
              Bit 7 => ACK
              Bit 6 => NACK -> With new rolling code
              Bits 5:4 = Reserved
     4     3  Bits 3:0 = Send retry count
     8     4  source address
     8     5  destination address => 0xFF is broadcast and will not be acked
    16     6  CRC
    ----
    The user's payload goes here.
    ----
*/

#define PWL_SL_FLAG_MASK       0xF0
#define PWL_SL_RC_MASK         0x0F
#define PWL_SL_FLAG_ACK        0x80
#define PWL_SL_FLAG_NAK        0x40

#define PWL_SL_BCAST_ADDR      0xFF

#define PWL_SL_MIN_PKT_LEN     8

struct PWL_SL_PeerInfo
{
    uint8_t   peer_id;
    uint32_t  our_rcode;
    uint32_t  their_rcode;
    PWL_SL_PeerInfo *next;
};


class PWLSecureLora : public PWL_RFM9X
{
private:
    PWL_SL_PeerInfo *_peers;
    const uint32_t * _key;
    uint32_t _rolling_code_seed;
    uint32_t _ackwait_timeout_ms;
    uint32_t _send_timeout;
    uint8_t  _our_addr;
    uint8_t  _last_rx_src_addr;  // May be actual sender or broadcast.
    uint8_t  _last_rx_dst_addr;  // May be our address or other if we are promiscuous.
    uint8_t  _send_retry_limit;
    bool     _rx_broadcast_ok;
    bool     _promiscuous;

    enum {
        PWL_SL_RCODE_IDX_0 = 0,
        PWL_SL_RCODE_IDX_1,
        PWL_SL_RCODE_IDX_2,
        PWL_SL_FLAGS_RC_IDX,
        PWL_SL_SRC_ADDR_IDX,
        PWL_SL_DST_ADDR_IDX,
        PWL_SL_CRC0_IDX,
        PWL_SL_CRC1_IDX,
        PWL_SL_HDR_LEN,
    };

    // Keep a linked list of known peers and the rolling codes for tx and rx.
    void _new_peer(PWL_SL_PeerInfo **ppPeer, uint8_t dst_addr);
    PWL_SL_PeerInfo * _find_peer(uint8_t dst_addr);
    uint16_t _pwl_sl_crc16(uint16_t crc, uint8_t *c_ptr, int len);

public:
    uint8_t  _rcv_src_addr;

    PWLSecureLora(const uint8_t my_address,
                  const uint32_t key[4],
                  pwl_rfm9X_reg_rwr_fptr_t write_function,
                  pwl_rfm9X_reg_rwr_fptr_t read_function,
                  pwl_rfm9X_ms_delay_t     delay_function);

    bool pwl_sl_receive(uint8_t* buf, uint8_t* len);
    bool pwl_sl_send(uint8_t dst_addr, const uint8_t* data, uint8_t len, bool no_ack=false);

    void pwl_sl_set_send_retry_limit(uint8_t send_retry_count) { _send_retry_limit = send_retry_count; }
    void pwl_sl_set_tx_src_address(uint8_t src_addr) { _our_addr = src_addr; }
    void pwl_sl_enable_broadcast_receive(bool enable) { _rx_broadcast_ok = enable; }
    void pwl_sl_enable_promiscuous_receive(bool enable) { _promiscuous = enable; }
    uint8_t pwl_sl_last_rx_src_addr(void) { return _last_rx_src_addr; }
    uint8_t pwl_sl_last_rx_dst_addr(void) { return _last_rx_dst_addr; }

protected:
    virtual void _encrypt(uint32_t const key[4], uint32_t *v, int n);
    virtual void _decrypt(uint32_t const key[4], uint32_t *v, int n);
};

#endif