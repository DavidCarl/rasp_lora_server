extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

use std::result::Result;

// RANDOM

use rand::{rngs::StdRng, Rng, SeedableRng};

// EDHOC

use oscore::edhoc::{
    api::{Msg1Receiver, Msg2Sender, Msg3Receiver},
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
    let mut msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>> = HashMap::new();//PartyR<Msg3Receiver>> = HashMap::new();
    loop {
        let poll = lora.poll_irq(None, &mut Delay); //30 Second timeout
        match poll {
            Ok(_size) => {
                let buffer = lora.read_packet().unwrap(); // Received buffer. NOTE: 255 bytes are always returned
                match buffer[0] {
                    0 => {
                        // initialize handshake
                        // respond with message
                        //let msg = &buffer[1..];
                        let msg = unpack_edhoc_first_message(buffer);
                        println!("msg1.len {:?}", msg.len());

                        // først når den modtager besked
                        let r_static_priv = StaticSecret::from(R_STATIC_MATERIAL);
                        let r_static_pub = PublicKey::from(&r_static_priv);

                        let r_kid = [0xA3].to_vec();
                        let mut r: StdRng = StdRng::from_entropy();
                        let r_ephemeral_keying = r.gen::<[u8; 32]>();

                        let msg1_receiver = PartyR::new(r_ephemeral_keying, r_static_priv, r_static_pub, r_kid);
                        let res = handle_first_gen_second_message(msg.to_vec(), msg1_receiver);
                        match res {
                            Ok((msg, msg3, devaddr)) => {
                                println!("{:?}", devaddr);
                                msg3_receivers.insert(devaddr, msg3);
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
                        //let msg = &buffer[1..];
                        let (msg, devaddr) = unpack_edhoc_message(buffer);
                        // println!("{:?}", msg3_receivers.contains_key(&devaddr));
                        let msg3rec = msg3_receivers.remove(&devaddr).unwrap();
                        let i_static_pub = PublicKey::from(I_STATIC_PK_MATERIAL);

                        let payload = handle_third_gen_fourth_message(msg.to_vec(), msg3rec, i_static_pub);
                        match payload {
                            Ok(msg) => {
                                let (msg_buffer, len) = lora_send(msg);
                                let transmit = lora.transmit_payload_busy(msg_buffer, len);
                                match transmit {
                                    Ok(packet_size) => println!("Sent packet with size: {:?}", packet_size),
                                    Err(_) => println!("Error"),
                                }
                            }
                            Err(_) => {
                                println!("ERROR IN MESSAGE 3 AND 4")
                            }
                        }
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

fn handle_first_gen_second_message(
    msg: Vec<u8>,
    msg1_receiver: PartyR<Msg1Receiver>,
) -> Result<(Vec<u8>, PartyR<Msg3Receiver>, [u8; 4]), OwnOrPeerError> {
    println!{"Recieved msg {:?}", msg}
    let (msg2_sender, ad_r, ad_i) = match msg1_receiver.handle_message_1(msg) {
        Err(OwnError(b)) => {
            println!("sending error {:?}, ", b);
            return Err(OwnOrPeerError::OwnError(b))//Ok(b); // we really shoulnt fail on the first message
        }
        Ok(val) => val,
    };

    let (msg2_bytes, msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            println!("ERRRRRRRRRRRRRRRRRRRRRRROR");
            return Err(OwnOrPeerError::OwnError(b))
        },
        Ok(val) => val,
    };

    println!("{:?}", msg2_bytes.len());

    let mut payload2 = [1].to_vec();
    // generate dev id, make sure its unique!
    // TODO: Make sure dev_addr is unique!
    let dev_addr: [u8; 4] = rand::random();
    println!("\n DevAddr {:?}\n", dev_addr);
    payload2.extend(dev_addr);
    payload2.extend(msg2_bytes);
    Ok((payload2, msg3_receiver, dev_addr))
}

fn handle_third_gen_fourth_message(mut msg: Vec<u8>, msg3_receiver: PartyR<Msg3Receiver>, i_static_pub: PublicKey) -> Result<Vec<u8>, OwnOrPeerError> {
    println!("Third message {:?}", msg);
    println!("Third message len {:?}", msg.len());

    let tup3 = msg3_receiver.handle_message_3(msg,&i_static_pub.as_bytes().to_vec());

    let (msg4sender, r_sck,r_rck, r_master) = match tup3 {
        Ok(v) => v,
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        },
        Err(OwnOrPeerError::OwnError(b)) =>{
            //stream.write(&b)?;// in this case, return this errormessage
            return Err(OwnOrPeerError::OwnError(b))
        },
    };

    // send message 4

    let msg4_bytes = // fjern den der len imorgen
    match msg4sender.generate_message_4() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            //stream.write(&b)?;// in this case, return this errormessage
            return Err(OwnOrPeerError::OwnError(b))
        }

        Ok(val) => val,
    };

        // sending message 2
        let mut payload4 = [3].to_vec();
        payload4.extend(msg4_bytes);
        return Ok(payload4)
        //stream.write(&payload4)?;
}

fn unpack_edhoc_first_message(msg: Vec<u8>) -> Vec<u8>{
    let msg = &msg[1..]; // fjerne mtype
    let framecounter = &msg[0..2]; // gemme framecounter
    let msg = &msg[2..]; // fjerne frame counter
    msg.to_vec()
}

fn unpack_edhoc_message(msg: Vec<u8>) -> (Vec<u8>, [u8; 4]){
    let msg = &msg[1..]; // fjerne mtype
    let framecounter = &msg[0..2]; // gemme framecounter
    let msg = &msg[2..]; // fjerne frame counter
    let devaddr = msg[0..4].try_into().unwrap();
    let msg = &msg[4..];
    (msg.to_vec(), devaddr)
}

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
