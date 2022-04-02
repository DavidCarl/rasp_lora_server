extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

use std::result::Result;

// RANDOM

use rand::{rngs::StdRng, Rng, SeedableRng};

// EDHOC

use oscore::edhoc::{
    api::{Msg1Receiver, Msg2Sender},
    error::{Error, OwnError, OwnOrPeerError},
    util::build_error_message,
    PartyR,
};

use x25519_dalek_ng::{PublicKey, StaticSecret};

// LORA MODULE

use sx127x_lora::LoRa;

const LORA_CS_PIN: u8 = 8;
const LORA_RESET_PIN: u8 = 22;
const FREQUENCY: i64 = 915;

// HAL

use rppal::gpio::{Gpio, OutputPin};
use rppal::hal::Delay;
use rppal::spi::{Bus, Mode, SlaveSelect, Spi};

// JSON AND FILES

use std::collections::HashMap;
use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct Data {
    data: HashMap<String, Device>,
    deveui: Vec<Vec<u8>>,
    appeui: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Device {
    key: Vec<u8>,
}

const R_STATIC_MATERIAL: [u8; 32] = [
    59, 213, 202, 116, 72, 149, 45, 3, 163, 72, 11, 87, 152, 91, 221, 105, 241, 1, 101, 158, 72,
    69, 125, 110, 61, 244, 236, 138, 41, 140, 127, 132,
];

const I_STATIC_PK_MATERIAL: [u8; 32] = [
    205, 223, 6, 18, 99, 214, 239, 8, 65, 191, 174, 86, 128, 244, 122, 17, 32, 242, 101, 159, 17,
    91, 11, 40, 175, 120, 16, 114, 175, 213, 41, 47,
];

fn main() {
    /*let data = load_file(
        "/home/carl/Documents/git/github/davidcarl/rasp_lora_server/testFile.json".to_string(),
    );

    let d: Data = serde_json::from_str(&data).unwrap();
    let sk = [
        16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29,
        68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207,
    ];


    println!("{:?}", d.data[&convert_id_to_string(sk.to_vec())]);
    */
    lora_recieve();

}

fn load_file(path: String) -> String {
    let data = fs::read_to_string(path).expect("Unable to read file");
    //rintln!("{}", data);
    data
}

fn setup_sx127x() -> LoRa<Spi, OutputPin, OutputPin> {
    let spi = Spi::new(Bus::Spi0, SlaveSelect::Ss0, 8_000_000, Mode::Mode0).unwrap();

    let gpio = Gpio::new().unwrap();

    let cs = gpio.get(LORA_CS_PIN).unwrap().into_output();
    let reset = gpio.get(LORA_RESET_PIN).unwrap().into_output();

    sx127x_lora::LoRa::new(spi, cs, reset, FREQUENCY, &mut Delay).unwrap()
}

fn lora_recieve() {
    let mut lora = setup_sx127x();
    loop {
        let poll = lora.poll_irq(None, &mut Delay); //30 Second timeout
        match poll {
            Ok(_size) => {
                println!("with Payload: ");
                let buffer = lora.read_packet().unwrap(); // Received buffer. NOTE: 255 bytes are always returned
                match buffer[0] {
                    0 => {
                        // initialize handshake
                        // respond with message
                        let msg = &buffer[1..];

                        // først når den modtager besked
                        let r_static_priv = StaticSecret::from(R_STATIC_MATERIAL);
                        let r_static_pub = PublicKey::from(&r_static_priv);
                        let i_static_pub = PublicKey::from(I_STATIC_PK_MATERIAL);

                        let r_kid = [0xA3].to_vec();
                        let mut r: StdRng = StdRng::from_entropy();
                        let r_ephemeral_keying = r.gen::<[u8; 32]>();

                        let msg1_receiver = PartyR::new(r_ephemeral_keying, r_static_priv, r_static_pub, r_kid);
                        let res = handle_first_message(msg.to_vec(), msg1_receiver);
                        match res {
                            Ok(msg) => {
                                let (msg_buffer, len) = lora_send(msg);
                                let transmit = lora.transmit_payload_busy(msg_buffer, len);
                                match transmit {
                                    Ok(packet_size) => println!("Sent packet with size: {:?}", packet_size),
                                    Err(_) => println!("Error"),
                                }
                            }
                            Error => {
                                println!("Something in the code died!");
                            }
                        }
                    }
                    2 => {
                        //
                        let msg = &buffer[1..];
                        handle_second_message(msg.to_vec());
                    }
                    _ => {
                        // All other messages
                        let msg = &buffer[1..];
                    }
                }
                //let s = String::from_utf8(buffer.to_vec()).unwrap();

                /*for i in 0..size {
                    println!("{}", buffer[i] as char);
                }*/
                //println!("{:?}", s);
                println!();
            }
            Err(_) => println!("Timeout"),
        }
    }
}

fn handle_first_message(
    msg: Vec<u8>,
    msg1_receiver: PartyR<Msg1Receiver>,
) -> Result<Vec<u8>, Error> {
    println!{"Recieved msg {:?}", msg}
    let (msg2_sender, ad_r, ad_i) = match msg1_receiver.handle_message_1(msg) {
        Err(OwnError(b)) => {
            println!("sending error {:?}, ", b);
            return Ok(b); // we really shoulnt fail on the first message
        }
        Ok(val) => val,
    };

    let (msg2_bytes, msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => return Ok(b),
        Ok(val) => val,
    };

    let mut payload2 = [1].to_vec();
    payload2.extend(msg2_bytes);
    return Ok(payload2)
}

fn handle_second_message(mut msg: Vec<u8>) {}

fn lora_send(message: Vec<u8>) -> ([u8; 255], usize) {
    let mut buffer = [0; 255];
    for (i, byte) in message.iter().enumerate() {
        buffer[i] = *byte;
    }
    (buffer, message.len())
}

fn convert_id_to_string(id: Vec<u8>) -> String {
    serde_json::to_string(&id).unwrap()
}
