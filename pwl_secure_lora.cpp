/*
 * Copyright (c) PeeWee Labs All rights reserved.
 * Licensed under the MIT License.
 * See LICENSE file in the project root for full license information.
 */

#include <pwl_secure_lora.h>

// ***************
// Shortcut macros
// ***************
// Packet get and set rolling code macros:
#define PWL_SL_PKT_RCODE() ((uint32_t)(_buffer[PWL_SL_RCODE_IDX_0]) | ((uint32_t)(_buffer[PWL_SL_RCODE_IDX_1]) << 8) | ((uint32_t)(_buffer[PWL_SL_RCODE_IDX_2]) << 16))
#define PWL_SL_SET_PKT_RCODE(rcode) \
    _buffer[PWL_SL_RCODE_IDX_0] = (uint8_t)((rcode) & 0xFF); \
    _buffer[PWL_SL_RCODE_IDX_1] = (uint8_t)(((rcode) >> 8) & 0xFF); \
    _buffer[PWL_SL_RCODE_IDX_2] = (uint8_t)(((rcode) >> 16) & 0xFF);

// Packet ACK/NAK flag macros
#define PWL_SL_PKT_IS_ACK() ((_buffer[PWL_SL_FLAGS_RC_IDX] & PWL_SL_FLAG_ACK) != 0)
#define PWL_SL_PKT_IS_NAK() ((_buffer[PWL_SL_FLAGS_RC_IDX] & PWL_SL_FLAG_NAK) != 0)

// Packet source and destination macros
#define PWL_SL_PKT_SRC() (_buffer[PWL_SL_SRC_ADDR_IDX])
#define PWL_SL_PKT_DST() (_buffer[PWL_SL_DST_ADDR_IDX])


PWLSecureLora::PWLSecureLora(const uint8_t my_address,
                             const uint32_t key[4],
                             pwl_rfm9X_reg_rwr_fptr_t write_function,
                             pwl_rfm9X_reg_rwr_fptr_t read_function,
                             pwl_rfm9X_ms_delay_t     delay_function
                             )
   : PWL_RFM9X(write_function, read_function, delay_function)
{
    _key                = &key[0];
    _rolling_code_seed  = PWL_SL_ROLLING_CODE_SEED;
    _peers              = NULL;
    _ackwait_timeout_ms = PWL_SL_ACKWAIT_TIMEOUT_MS;
    _our_addr           = my_address;
    _rcv_src_addr       = 0xFF;
    _rx_broadcast_ok    = false;
    _promiscuous        = false;
    _send_retry_limit   = PWL_SL_SEND_RETRY_LIMIT;
}


void PWLSecureLora::_new_peer(PWL_SL_PeerInfo **ppPeer, uint8_t dst_addr)
{
    *ppPeer = new PWL_SL_PeerInfo;
    (*ppPeer)->next = NULL;
    (*ppPeer)->peer_id = dst_addr;
    (*ppPeer)->our_rcode = _rolling_code_seed;
    _rolling_code_seed -= PWL_SL_RCODE_OFFSET;
    // Their rcode is arbitrary... it will get fixed on first TX
    (*ppPeer)->their_rcode = (*ppPeer)->our_rcode;
}


PWL_SL_PeerInfo * PWLSecureLora::_find_peer(uint8_t dst_addr)
{
    PWL_SL_PeerInfo ** ppPeer = &_peers;
    while(1)
    {
        if (*ppPeer)
        {
            if ((*ppPeer)->peer_id == dst_addr)
                break;
            ppPeer = &((*ppPeer)->next);
        }
        else
        {
            _new_peer(ppPeer, dst_addr);
            break;
        }
    }
    return *ppPeer;
}


bool PWLSecureLora::pwl_sl_receive(uint8_t* buf, uint8_t* len)
{
    bool is_bcast;
    bool is_to_us;
    bool match = false;
    uint16_t pkt_crc;
    uint16_t calc_crc;
    PWL_SL_PeerInfo * pPeer;

    // rx_data_ready is placed first to make sure it is called.
    // rx_data_ready will put us in RX mode if we aren't already there
    if (rx_data_ready() && buf && len)
    {
        _rx_valid = false; // This message accepted and cleared

        _decrypt(_key, (uint32_t*) _buffer, _rxlength >> 2);

        // Without caring about the CRC yet, is the packet even for us?
        // If not ignore it completely.
        is_to_us = (PWL_SL_PKT_DST() == _our_addr);
        is_bcast = (PWL_SL_PKT_DST() == PWL_SL_BCAST_ADDR) && _rx_broadcast_ok;

        // If the packet is NOT for us, but _promiscuous is set, then
        // treat the packet like it is a broadcast packet.
        is_bcast = is_bcast | (!is_to_us && _promiscuous);

        if (is_to_us || is_bcast)
        {
            pkt_crc = _buffer[PWL_SL_CRC0_IDX] | (_buffer[PWL_SL_CRC1_IDX] << 8);
            // CRC calc requires the CRC fields to be zero.
            _buffer[PWL_SL_CRC0_IDX] = 0;
            _buffer[PWL_SL_CRC1_IDX] = 0;
            calc_crc = _pwl_sl_crc16(0xFFFF, _buffer, _rxlength);
            // Obfuscate the CRC for ack/nak
            _buffer[PWL_SL_CRC0_IDX] = ((uint8_t)(pkt_crc & 0xFF)) ^ _key[3];
            _buffer[PWL_SL_CRC1_IDX] = ((uint8_t)((pkt_crc >> 8) & 0xFF)) ^ _key[5];

            if (pkt_crc == calc_crc)
            {
                if (is_to_us)
                {
                    // Check if the rolling code is the expected value
                    pPeer = _find_peer(PWL_SL_PKT_SRC());
                    match = PWL_SL_PKT_RCODE() == pPeer->our_rcode;
                }

                if (is_bcast || match)
                {
                    // Good packet
                    // Copy fields and data
                    _rcv_src_addr = PWL_SL_PKT_SRC();
                    if (*len > (uint8_t)(_rxlength - PWL_SL_HDR_LEN))
                        *len = (uint8_t)(_rxlength - PWL_SL_HDR_LEN);
                    memcpy(buf, &_buffer[PWL_SL_HDR_LEN], *len);

                    _last_rx_src_addr = PWL_SL_PKT_SRC();
                    _last_rx_dst_addr = PWL_SL_PKT_DST();

                    // If the packet was targeted at us then ACK the packet
                    if (match)
                    {
                        // Send ACK
                        _buffer[PWL_SL_FLAGS_RC_IDX] |= PWL_SL_FLAG_ACK;

                        // Encrypt the packet buffer
                        _encrypt(_key, (uint32_t*) _buffer, PWL_SL_MIN_PKT_LEN >> 2);

                        send(_buffer, PWL_SL_MIN_PKT_LEN);

                        ++pPeer->our_rcode;
                        wait_packet_tx();
                    }

                    return true;
                }
                else
                {
                    // Send NAK along with our_rcode which the sender should
                    // use in future packets to us.
                    _buffer[PWL_SL_FLAGS_RC_IDX] |= PWL_SL_FLAG_NAK;
                    PWL_SL_SET_PKT_RCODE(pPeer->our_rcode);
                    // Encrypt the packet buffer
                    _encrypt(_key, (uint32_t*) _buffer, PWL_SL_MIN_PKT_LEN >> 2);

                    send(_buffer, PWL_SL_MIN_PKT_LEN);
                    wait_packet_tx();
                }
            }
        }
    }

    return false;
}


bool PWLSecureLora::pwl_sl_send(uint8_t dst_addr, const uint8_t* data, uint8_t len, bool no_ack)
{
    int pkt_len = len + PWL_SL_HDR_LEN;
    uint32_t send_retry_count = 0;
    uint32_t tgt_rcode;
    uint16_t crc;
    PWL_SL_PeerInfo * pPeer;
    uint32_t ack_timeout;

    // Force the length to be mod 4
    pkt_len = pkt_len + 3;
    pkt_len = pkt_len & 0x1FC;

    if (pkt_len > (PWL_RFM9X_RX_BUFFER_LEN))
        return false;

    if (pkt_len < PWL_SL_MIN_PKT_LEN)
        return false;

    wait_packet_tx(10);
    set_mode(RFM9X_LORA_MODE_STDBY);

    pPeer = _find_peer(dst_addr);
    tgt_rcode = pPeer->their_rcode;

    while(send_retry_count < _send_retry_limit)
    {
        // Initialize the packet buffer:
        PWL_SL_SET_PKT_RCODE(tgt_rcode);
        _buffer[PWL_SL_FLAGS_RC_IDX] = send_retry_count & PWL_SL_RC_MASK;

        _buffer[PWL_SL_SRC_ADDR_IDX] = _our_addr;
        _buffer[PWL_SL_DST_ADDR_IDX] = dst_addr;
        memcpy(&_buffer[PWL_SL_HDR_LEN], data, len);

        // Calculate the CRC
        _buffer[PWL_SL_CRC0_IDX] = 0;
        _buffer[PWL_SL_CRC1_IDX] = 0;
        crc = _pwl_sl_crc16(0xFFFF, _buffer, pkt_len);
        _buffer[PWL_SL_CRC0_IDX] = (uint8_t)(crc & 0xFF);
        _buffer[PWL_SL_CRC1_IDX] = (uint8_t)((crc >> 8) & 0xFF);

        // Encrypt the packet buffer
        _encrypt(_key, (uint32_t*) _buffer, pkt_len >> 2);

        // Transmit
        send(_buffer, pkt_len);
        wait_packet_tx(1000);

        if (no_ack) return true;

        set_mode(RFM9X_LORA_MODE_RX_CONTINUOUS);
        ack_timeout = millis() + PWL_SL_ACKWAIT_TIMEOUT_MS;

        while (ack_timeout > millis())
        {

            while ( (ack_timeout > millis()) && (!rx_data_ready()) )
            {
                yield();
                poll();
            }

            if (rx_data_ready())
            {
                _rx_valid = false;

                _decrypt(_key, (uint32_t*) _buffer, PWL_SL_MIN_PKT_LEN >> 2);

                if ((PWL_SL_PKT_SRC() == _our_addr) && (PWL_SL_PKT_DST() == dst_addr))
                {
                    uint32_t lrcode = PWL_SL_PKT_RCODE();

                    if (PWL_SL_PKT_IS_ACK() && (lrcode == tgt_rcode))
                    {
                        // Increment the rolling code and store for the next tx
                        pPeer->their_rcode = tgt_rcode + 1;
                        return true;
                    }

                    if (PWL_SL_PKT_IS_NAK())
                    {
                        tgt_rcode = lrcode;
                        pPeer->their_rcode = lrcode;

                        break;
                    }

                }
            }
            else
            {
                set_mode(RFM9X_LORA_MODE_STDBY);
                _rx_valid = false;
                break;
            }
        }
        ++send_retry_count;
        // Delay some amount of time, changing a bit with each retry
        delay((send_retry_count << 3) + (crc & 0x1F));
    }

    return false;
}


// See XXTEA at Wikipedia
#define TEA_ENCRYPT_DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

void PWLSecureLora::_encrypt(uint32_t const key[4], uint32_t *v, int n)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)
    {
        /* Coding Part */
        rounds = 6 + (52 / n);
        sum = 0;
        z = v[n - 1];
        do {
            sum += TEA_ENCRYPT_DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            v[n - 1] += MX;
            z = v[n - 1];
        } while (--rounds);
    }
}


void PWLSecureLora::_decrypt(uint32_t const key[4], uint32_t *v, int n)
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    rounds = 6 + (52 / n);
    sum = rounds * TEA_ENCRYPT_DELTA;
    y = v[0];
    do
    {
        e = (sum >> 2) & 3;
        for (p = n - 1; p > 0; p--)
        {
            z = v[p - 1];
            y = v[p] -= MX;
        }
        z = v[n - 1];
        v[0] -= MX;
        y = v[0];
        sum -= TEA_ENCRYPT_DELTA;
    } while (--rounds);
}


static const uint16_t PROGMEM pwl_sl_crctable[256] =
{
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x0919, 0x1890, 0x2A0B, 0x3B82, 0x4F3D, 0x5EB4, 0x6C2F, 0x7DA6,
    0x8551, 0x94D8, 0xA643, 0xB7CA, 0xC375, 0xD2FC, 0xE067, 0xF1EE,
    0x1232, 0x03BB, 0x3120, 0x20A9, 0x5416, 0x459F, 0x7704, 0x668D,
    0x9E7A, 0x8FF3, 0xBD68, 0xACE1, 0xD85E, 0xC9D7, 0xFB4C, 0xEAC5,
    0x1B2B, 0x0AA2, 0x3839, 0x29B0, 0x5D0F, 0x4C86, 0x7E1D, 0x6F94,
    0x9763, 0x86EA, 0xB471, 0xA5F8, 0xD147, 0xC0CE, 0xF255, 0xE3DC,
    0x2464, 0x35ED, 0x0776, 0x16FF, 0x6240, 0x73C9, 0x4152, 0x50DB,
    0xA82C, 0xB9A5, 0x8B3E, 0x9AB7, 0xEE08, 0xFF81, 0xCD1A, 0xDC93,
    0x2D7D, 0x3CF4, 0x0E6F, 0x1FE6, 0x6B59, 0x7AD0, 0x484B, 0x59C2,
    0xA135, 0xB0BC, 0x8227, 0x93AE, 0xE711, 0xF698, 0xC403, 0xD58A,
    0x3656, 0x27DF, 0x1544, 0x04CD, 0x7072, 0x61FB, 0x5360, 0x42E9,
    0xBA1E, 0xAB97, 0x990C, 0x8885, 0xFC3A, 0xEDB3, 0xDF28, 0xCEA1,
    0x3F4F, 0x2EC6, 0x1C5D, 0x0DD4, 0x796B, 0x68E2, 0x5A79, 0x4BF0,
    0xB307, 0xA28E, 0x9015, 0x819C, 0xF523, 0xE4AA, 0xD631, 0xC7B8,
    0x48C8, 0x5941, 0x6BDA, 0x7A53, 0x0EEC, 0x1F65, 0x2DFE, 0x3C77,
    0xC480, 0xD509, 0xE792, 0xF61B, 0x82A4, 0x932D, 0xA1B6, 0xB03F,
    0x41D1, 0x5058, 0x62C3, 0x734A, 0x07F5, 0x167C, 0x24E7, 0x356E,
    0xCD99, 0xDC10, 0xEE8B, 0xFF02, 0x8BBD, 0x9A34, 0xA8AF, 0xB926,
    0x5AFA, 0x4B73, 0x79E8, 0x6861, 0x1CDE, 0x0D57, 0x3FCC, 0x2E45,
    0xD6B2, 0xC73B, 0xF5A0, 0xE429, 0x9096, 0x811F, 0xB384, 0xA20D,
    0x53E3, 0x426A, 0x70F1, 0x6178, 0x15C7, 0x044E, 0x36D5, 0x275C,
    0xDFAB, 0xCE22, 0xFCB9, 0xED30, 0x998F, 0x8806, 0xBA9D, 0xAB14,
    0x6CAC, 0x7D25, 0x4FBE, 0x5E37, 0x2A88, 0x3B01, 0x099A, 0x1813,
    0xE0E4, 0xF16D, 0xC3F6, 0xD27F, 0xA6C0, 0xB749, 0x85D2, 0x945B,
    0x65B5, 0x743C, 0x46A7, 0x572E, 0x2391, 0x3218, 0x0083, 0x110A,
    0xE9FD, 0xF874, 0xCAEF, 0xDB66, 0xAFD9, 0xBE50, 0x8CCB, 0x9D42,
    0x7E9E, 0x6F17, 0x5D8C, 0x4C05, 0x38BA, 0x2933, 0x1BA8, 0x0A21,
    0xF2D6, 0xE35F, 0xD1C4, 0xC04D, 0xB4F2, 0xA57B, 0x97E0, 0x8669,
    0x7787, 0x660E, 0x5495, 0x451C, 0x31A3, 0x202A, 0x12B1, 0x0338,
    0xFBCF, 0xEA46, 0xD8DD, 0xC954, 0xBDEB, 0xAC62, 0x9EF9, 0x8F70
};


uint16_t PWLSecureLora::_pwl_sl_crc16(uint16_t crc, uint8_t *c_ptr, int len)
{
    uint8_t *c = c_ptr;
    while (len--)
    {
        crc = (crc << 8) ^ pgm_read_word_near(pwl_sl_crctable + (((crc >> 8) ^ *c++)));
    }
    return crc;
}
