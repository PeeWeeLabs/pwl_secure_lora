# Secure LoRa Packet Driver

Copyright © PeeWee Labs, All Rights Reserved.  Licensed under the MIT License, see the LICENSE file in the root of this repository.

## About
This driver implements a (reasonably) secure communication protocol between LoRa nodes with the same key (and within tx/rx distance).  Originally it was used in a home automation environment controlling garage doors, door sensors and environmental sensors.

This driver is an extension of (and inherits from) the PeeWee Labs pwl_rfm9X HopeRF LoRa driver.

Examples are provided for the Arduino platform.

## Notes
### Encryption / Security
This driver uses XXTEA encryption that operates on a block of data that must be at least 8 bytes in length and be a multiple of 4 bytes.  i.e. 8, 12, 16, 20...

#### Assumptions
 - An outside party can receive and potentially repeat an encrypted packet. 
 - The outside observer can not decode the encrypted packet to see the cleartext (without the key). 
 - The outside observer does not know what the cleartext being sent is.

A "rolling code" is used to make sure that all packets sent are constantly changing even if the actual data is not changing. 

A CRC is added to the encrypted data.  This serves to make sure the encrypted is not a random data attack.  This prevents random data from matching enough of the header to be treated as a good packet. 

The secure destination node maintains an expected value for the rolling code.  If an otherwise valid packet is received from a sender that has an incorrect rolling code then the destination will send a NAK back with the correct rolling code.  This allows the a sender to synchronize with the receiver.  It is secure since an outside party can not decode what was in either the original
packet or the response.  If the outside party tries to send either of the encrypted packets that they observed the sender will ignore an unsolicited NAK and the receiver might try to send another encrypted NAK.

Some devices may be fire and forget (broadcast data).  In this case there is still a rolling code and the packet data is encrypted.  The receiver ignores the rolling code for broadcast data.  There is a risk that an outside party could record previous packets and send them as bogus data.  It is suggested that broadcast only be used for non-critical data.  Use your own judgment as to whether this risk is acceptable in your LoRa network.  These broadcast packets still look like random bytes to an outside party due to the encryption.  Given the assumption that the outside party can not determine the plain text of the packet their only attack is to re-send already encrypted packets they previously sniffed without knowing what they do.

### Tested With
This driver has been tested on the following platforms:

 - Arduino Nano + RFM95 module
 - Moteino with RFM95
 - ATTiny 1614 + RFM95w module

# Usage
See the header file for prototypes of these functions.
## Instantiation
### Include the header:

    #include <pwl_secure_lora.h>
### Provide three functions that are used by the driver:

    int spi_read_register(uint8_t reg_addr, uint8_t *reg_data, uint32_t len);
    int spi_write_register(uint8_t reg_addr, uint8_t *reg_data, uint32_t len);
    void delay_milliseconds(uint32_t ms);

### Instantiate the class:
    PWLSecureLora radio_driver(our_address, radio_key, spi_read_register, spi_write_register, delay_milliseconds);
*__our_address__*:  Each node must have a unique address.  This address is provided here during instantiation.
*__radio_key__*:  A user supplied array of 4 32-bit words that are used as a key for encryption.
*__spy_read_register__*, *__spy_write_register__* and  *__delay_milliseconds__* are user supplied functions that this driver uses.

## Initialization
IMPORTANT NOTE:  This driver uses the SPI read write functions provided above.  If you need to initialize your SPI hardware/software, then do so before initializing the radio driver.

    radio_driver.init(uint32_t  RADIO_FREQ,
                      uint8_t   RADIO_POWER,
                      lora_bw_t LORA_BANDWIDTH,
                      lora_cr_t LORA_CODE_RATE,
                      lora_sf_t LORA_SPREADING_FACTOR);
#### The initialization parameters:
##### RADIO_FREQ
The carrier (center) frequency on which the radio will transmit and receive packet data.  Please see your radio's documentation for the valid range of this parameter.
##### RADIO_POWER
The number of dBm boost the power amp should give when transmitting data.  This number must be between 5 and 20 for this driver.
##### LORA_BANDWIDTH
Provide one of the values enumerated by the lora_bw_t type.  See the pwl_rfm9X for the possible values.
##### LORA_CODE_RATE
Provide one of the values enumerated by the lora_cr_t type.  See the pwl_rfm9X for the possible values.
##### LORA_SPREADING_FACTOR
Provide one of the values enumerated by the lora_sf_t type.  See the pwl_rfm9X for the possible values.

---
**NOTE:** For the **LORA_XXX** parameters, see one of numerous LoRa primers on the web.  Generally these will tradeoff between data rate and reliability.
## Transmit
    bool pwl_sl_send(uint8_t dest_addr, uint8_t* data, uint8_t len);
Transmits *__len__* bytes of the given packet __*data*__ to the *__dest_addr__*.

Returns *__true__* if the packet was sent to dest_addr and the destination node acknowledged the reception.  Returns *__false__* for all errors.

This function will retry if the packet is NAKed (due to invalid rolling code) or if the send packet times out.

## Receive

    bool pwl_sl_receive(uint8_t* buf, uint8_t* len);
This function places the radio into receive mode if it is not already in receive mode.  If the radio is in receive mode then this function checks if a packet has been received and copies the packet into the provided buffer.

When this function is called, the *len parameter must contain the length of the provided *buf buffer to prevent overwriting.

If no packet is available when this function is called, the return value is false and the *len field is **not** modified.

If a packet is received and copied, then *len is updated to reflect the number of bytes that were copied into *buf.  

Returns *__true__* if a packet was received, decrypted, CRC matches and it is to us or a broadcast packet (if broadcast RX is enabled).

NOTE:  This function is non-blocking.  It will not wait for a packet to be received.  It must be called repeatedly until it returns a non-zero value.
## Misc
*__pwl_sl_last_rx_src_addr()__*:  Returns the sender's address if called immediately after a good packet is received.
*__pwl_sl_enable_broadcast_receive(bool)__*:  Enable or disable (true/false) reception of broadcast packets.
*__pwl_sl_enable_promiscuous_receive(bool)__*:  Enable or disable (true/false) reception of ALL valid packets on our network.  Used for debug or monitoring.
