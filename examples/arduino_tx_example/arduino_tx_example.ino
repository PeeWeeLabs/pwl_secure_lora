/*
 * Copyright (c) PeeWee Labs All rights reserved.
 * Licensed under the MIT License.
 * See LICENSE file in the project root for full license information.
 */

/*
 * TX Example for pwl_rfm9X library.
 *
 * This exmaple was adapted for for pwl_secure_lora from the pwl_rfm9X 
 * driver examples.
 * 
 */

#include <Arduino.h>
#include <SPI.h>
#include <pwl_secure_lora.h>

#define SERIAL_BAUD   115200

#if defined(__AVR_ATtiny1614__)
  #define RADIO_SLAVE_SELECT  1  // PeeWee Labs Battery Prototype board has SPI Slave Select on PA5
#else
  #define RADIO_SLAVE_SELECT  SS
#endif

// pwl_secure_lora requires a unique address for each node
// 0xFF is reserved for broadcast
// 
#define OUR_ADDR   0x01
#define THEIR_ADDR 0x02

// Define your encryption key (128 bits) here:
const uint32_t radio_key[4] = { 0xB0B11111, 0xB0B22222, 0xB0B33333, 0xB0B44444 };

// Basic radio parameters
#define RADIO_FREQ_HZ    915000000 // US ISM => 902M to 928M
#define RADIO_POWER_dBm  13        // Set between 5 and 20 dBm

// The pwl_rfm9X library requires us to provide the register read
// and write functions.

int rf95_reg_read(uint8_t reg_addr, uint8_t *data, uint32_t len)
{
    uint32_t idx;
    digitalWrite(RADIO_SLAVE_SELECT, LOW);
    SPI.transfer(reg_addr);
    for (idx = 0; idx < len; idx++)
    {
        data[idx] = SPI.transfer(0);
    }
    digitalWrite(RADIO_SLAVE_SELECT, HIGH);
    return 0;
}


int rf95_reg_write(uint8_t reg_addr, uint8_t *data, uint32_t len)
{
    uint32_t idx;
    digitalWrite(RADIO_SLAVE_SELECT, LOW);
    SPI.transfer(reg_addr);
    for (idx = 0; idx < len; idx++)
    {
        SPI.transfer(data[idx]);
    }
    digitalWrite(RADIO_SLAVE_SELECT, HIGH);
    return 0;
}

// Instantiate the RFM9X driver here.  Pass the write/read/delay
// functions.

PWLSecureLora radio_driver(OUR_ADDR, radio_key, rf95_reg_write, rf95_reg_read, delay);

void setup()
{
    delay(1000);

    // Configure the serial port
    Serial.begin(SERIAL_BAUD);
    while (!Serial)
        ;
    Serial.println("It's alive!");

    // Configure the Radio SPI Slave Select pin
    pinMode(RADIO_SLAVE_SELECT, OUTPUT);
    digitalWrite(RADIO_SLAVE_SELECT, HIGH);
    SPI.begin();
    SPI.setClockDivider(SPI_CLOCK_DIV8);

    // Initialize the radio
    radio_driver.init(RADIO_FREQ_HZ,
                      RADIO_POWER_dBm,
                      PWL_RFM9X::RFM9X_LORA_BW_250k,
                      PWL_RFM9X::RFM9X_LORA_CR_4_5,
                      PWL_RFM9X::RFM9X_LORA_SF_128);
}


void loop()
{
    static int x = 0;
    uint8_t radio_data[64];
    int rval;

    ++x;
    Serial.print("TX: ");
    Serial.println(x);

    sprintf((char*)radio_data, "Packet Number: %d", x);

    rval = radio_driver.pwl_sl_send(THEIR_ADDR, radio_data, strlen((char*)radio_data) + 1);
    if (rval) Serial.println("Send Error");

    delay(5000);
}
