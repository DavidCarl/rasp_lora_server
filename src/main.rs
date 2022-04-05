extern crate linux_embedded_hal as hal;
extern crate sx127x_lora;

use std::result::Result;

// RANDOM

use rand::{rngs::StdRng, Rng, SeedableRng};

// EDHOC

use oscore::edhoc::{
    api::{Msg1Receiver, Msg3Receiver},
    error::{OwnError, OwnOrPeerError},
    PartyR,
};

use x25519_dalek_ng::{PublicKey, StaticSecret};

// Ratchet

use twoRatchet::ratchfuncs::state;

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

static mut FCNTDOWN: u16 = 0;

fn main() {
    /*let data = load_file(
        "/home/carl/Documents/git/github/davidcarl/rasp_lora_server/testFile.json".to_string(),
    );

    let d: Data = serde_json::from_str(&data).unwrap();
    let sk = [
        16, 8, 7, 78, 159, 104, 210, 58, 89, 216, 177, 79, 10, 252, 39, 141, 8, 160, 148, 36, 29,
        68, 31, 49, 89, 67, 233, 53, 16, 210, 28, 207,
    ];


    //println!("{:?}", d.data[&convert_id_to_string(sk.to_vec())]);
    */
    lora_recieve();
}

fn _load_file(path: String) -> String {
    fs::read_to_string(path).expect("Unable to read file")
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
    lora.set_signal_bandwidth(125000);
    lora.set_spreading_factor(7);
    let mut msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>> = HashMap::new(); //PartyR<Msg3Receiver>> = HashMap::new();
    let mut lora_ratchets: HashMap<[u8; 4], state> = HashMap::new();
    loop {
        let poll = lora.poll_irq(None, &mut Delay); //30 Second timeout
        match poll {
            Ok(size) => {
                println!("Recieved packet with size: {:?}", size);
                let buffer = lora.read_packet().unwrap(); // Received buffer. NOTE: 255 bytes are always returned
                match buffer[0] {
                    0 => {
                        let rtn = m_type_zero(buffer, msg3_receivers, lora);
                        msg3_receivers = rtn.msg3_receivers;
                        lora = rtn.lora;
                    }
                    2 => {
                        let rtn = m_type_two(buffer, msg3_receivers, lora_ratchets, lora);
                        msg3_receivers = rtn.msg3_receivers;
                        lora_ratchets = rtn.lora_ratchets;
                        lora = rtn.lora;
                    }
                    5 => {
                        println!("Recieved m type 5");
                        let incoming = &buffer;
                        let rtn = handle_ratchet_message(incoming.to_vec(), lora, lora_ratchets);
                        lora = rtn.lora;
                        lora_ratchets = rtn.lora_ratchets;
                    }
                    7 => {
                        println!("Recieved m type 7");
                        let incoming = &buffer;
                        let rtn = handle_ratchet_message(incoming.to_vec(), lora, lora_ratchets);
                        lora = rtn.lora;
                        lora_ratchets = rtn.lora_ratchets;
                    }
                    _ => {
                        // All other messages
                        let msg = &buffer[1..];
                        println!("other message! {:?}", msg)
                    }
                }
            }
            Err(_) => println!("Timeout"),
        }
    }
}

struct Msg2 {
    msg: Vec<u8>,
    msg3_receiver: PartyR<Msg3Receiver>,
    devaddr: [u8; 4],
}

fn handle_first_gen_second_message(
    msg: Vec<u8>,
    msg1_receiver: PartyR<Msg1Receiver>,
) -> Result<Msg2, OwnOrPeerError> {
    let (msg2_sender, _ad_r, _ad_i) = match msg1_receiver.handle_message_1(msg) {
        Err(OwnError(b)) => {
            return Err(OwnOrPeerError::OwnError(b)); 
        }
        Ok(val) => val,
    };

    let (msg2_bytes, msg3_receiver) = match msg2_sender.generate_message_2() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            return Err(OwnOrPeerError::OwnError(b));
        }
        Ok(val) => val,
    };

    // generate dev id, make sure its unique!
    // TODO: Make sure dev_addr is unique!
    let devaddr: [u8; 4] = rand::random();
    let msg = prepare_message(msg2_bytes, 1, devaddr, false);

    Ok(Msg2 {
        msg,
        msg3_receiver,
        devaddr,
    })
}

struct Msg4 {
    msg4_bytes: Vec<u8>,
    r_sck: Vec<u8>,
    r_rck: Vec<u8>,
    r_master: Vec<u8>,
}

fn handle_third_gen_fourth_message(
    msg: Vec<u8>,
    msg3_receiver: PartyR<Msg3Receiver>,
    i_static_pub: PublicKey,
) -> Result<Msg4, OwnOrPeerError> {
    let (msg3verifier, _r_kid) = match msg3_receiver.handle_message_3(msg) {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Error during  {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            panic!("Send these bytes: {}", hexstring(&b))
        }
        Ok(val) => val,
    };

    // find i_static_pub kommer fra lookup

    let (msg4_sender, r_sck, r_rck, r_master) =
        match msg3verifier.verify_message_3(&i_static_pub.as_bytes().to_vec()) {
            Err(OwnOrPeerError::PeerError(s)) => {
                panic!("Error during  {}", s)
            }
            Err(OwnOrPeerError::OwnError(b)) => {
                panic!("Send these bytes: {}", hexstring(&b))
            }
            Ok(val) => val,
        };

    // send message 4

    let msg4_bytes = // fjern den der len imorgen
    match msg4_sender.generate_message_4() {
        Err(OwnOrPeerError::PeerError(s)) => {
            panic!("Received error msg: {}", s)
        }
        Err(OwnOrPeerError::OwnError(b)) => {
            //stream.write(&b)?;// in this case, return this errormessage
            return Err(OwnOrPeerError::OwnError(b))
        }

        Ok(val) => val,
    };

    Ok(Msg4 {
        msg4_bytes,
        r_sck,
        r_rck,
        r_master,
    })
}

struct RatchetMessage {
    lora: LoRa<Spi, OutputPin, OutputPin>,
    lora_ratchets: HashMap<[u8; 4], state>,
}

fn handle_ratchet_message(
    buffer: Vec<u8>,
    mut lora: LoRa<Spi, OutputPin, OutputPin>,
    mut lora_ratchets: HashMap<[u8; 4], state>,
) -> RatchetMessage {
    let incoming = &buffer;
    let devaddr: [u8; 4] = buffer[14..18].try_into().unwrap();
    let ratchet = lora_ratchets.remove(&devaddr);
    match ratchet {
        Some(mut lora_ratchet) => {
            let (newout, sendnew) = match lora_ratchet.r_receive(&incoming.to_vec()) {
                Some((x, b)) => (x, b),
                None => {
                    println!("error has happened {:?}", incoming);
                    lora_ratchets.insert(devaddr, lora_ratchet);
                    return RatchetMessage {
                        lora,
                        lora_ratchets,
                    }
                }
            };
            if !sendnew {
            } else {
                //println!("sending {:?}", newout);
                let (msg_buffer, len) = lora_send(newout);
                //println!("msg 4 {:?}", msg_buffer);
                let transmit = lora.transmit_payload_busy(msg_buffer, len);
                match transmit {
                    Ok(packet_size) => {
                        println!("Sent packet with size: {:?}", packet_size)
                    }
                    Err(_) => println!("Error"),
                }
            }
            lora_ratchets.insert(devaddr, lora_ratchet);
            //n += 1;
            //println!("n {}", n);
        }
        None => println!("No ratchet on this devaddr"),
    }
    RatchetMessage {
        lora,
        lora_ratchets,
    }
}

fn prepare_message(msg: Vec<u8>, mtype: u8, devaddr: [u8; 4], first_msg: bool) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&mtype.to_be_bytes());
    unsafe {
        buffer.extend_from_slice(&FCNTDOWN.to_be_bytes());
        FCNTDOWN += 1;
    }
    if !first_msg {
        buffer.extend_from_slice(&devaddr);
    }
    buffer.extend_from_slice(&msg);
    buffer
}

struct TypeZero {
    msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>>,
    lora: LoRa<Spi, OutputPin, OutputPin>,
}

fn m_type_zero(
    buffer: Vec<u8>,
    mut msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>>,
    mut lora: LoRa<Spi, OutputPin, OutputPin>,
) -> TypeZero {
    let msg = unpack_edhoc_first_message(buffer);
    let r_static_priv = StaticSecret::from(R_STATIC_MATERIAL);
    let r_static_pub = PublicKey::from(&r_static_priv);

    let r_kid = [0xA3].to_vec();
    let mut r: StdRng = StdRng::from_entropy();
    let r_ephemeral_keying = r.gen::<[u8; 32]>();

    let msg1_receiver = PartyR::new(r_ephemeral_keying, r_static_priv, r_static_pub, r_kid);
    let res = handle_first_gen_second_message(msg.to_vec(), msg1_receiver);
    match res {
        Ok(rtn) => {
            msg3_receivers.insert(rtn.devaddr, rtn.msg3_receiver);
            let (msg_buffer, len) = lora_send(rtn.msg);
            let transmit = lora.transmit_payload_busy(msg_buffer, len);
            match transmit {
                Ok(packet_size) => {
                    println!("Sent packet with size: {:?}", packet_size)
                }
                Err(_) => println!("Error"),
            }
        }
        _ => {
            println!("Something in the code died!");
        }
    }
    TypeZero {
        msg3_receivers,
        lora,
    }
}

struct TypeTwo {
    msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>>,
    lora_ratchets: HashMap<[u8; 4], state>,
    lora: LoRa<Spi, OutputPin, OutputPin>,
}

fn m_type_two(
    buffer: Vec<u8>,
    mut msg3_receivers: HashMap<[u8; 4], PartyR<Msg3Receiver>>,
    mut lora_ratchets: HashMap<[u8; 4], state>,
    mut lora: LoRa<Spi, OutputPin, OutputPin>,
) -> TypeTwo {
    let (msg, devaddr) = unpack_edhoc_message(buffer);
    let msg3rec = msg3_receivers.remove(&devaddr).unwrap();
    let i_static_pub = PublicKey::from(I_STATIC_PK_MATERIAL);

    let payload = handle_third_gen_fourth_message(msg.to_vec(), msg3rec, i_static_pub);
    match payload {
        Ok(msg4) => {
            println!("{:?}", devaddr);
            let msg = prepare_message(msg4.msg4_bytes, 3, devaddr, false);
            let (msg_buffer, len) = lora_send(msg);
            let transmit = lora.transmit_payload_busy(msg_buffer, len);
            match transmit {
                Ok(packet_size) => {
                    println!("Sent packet with size: {:?}", packet_size)
                }
                Err(_) => println!("Error"),
            }
            //Create ratchet
            let r_ratchet = state::init_r(
                msg4.r_master.try_into().unwrap(),
                msg4.r_rck.try_into().unwrap(),
                msg4.r_sck.try_into().unwrap(),
                devaddr.to_vec(),
            );
            lora_ratchets.insert(devaddr, r_ratchet);
        }
        Err(_) => {
            println!("ERROR IN MESSAGE 3 AND 4")
        }
    }
    TypeTwo {
        msg3_receivers,
        lora_ratchets,
        lora,
    }
}

fn unpack_edhoc_first_message(msg: Vec<u8>) -> Vec<u8> {
    let msg = &msg[1..]; // fjerne mtype
    let _framecounter = &msg[0..2]; // gemme framecounter
    let msg = &msg[2..]; // fjerne frame counter
    msg.to_vec()
}

fn unpack_edhoc_message(msg: Vec<u8>) -> (Vec<u8>, [u8; 4]) {
    let msg = &msg[1..]; // fjerne mtype
    let _framecounter = &msg[0..2]; // gemme framecounter
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

fn _convert_id_to_string(id: Vec<u8>) -> String {
    serde_json::to_string(&id).unwrap()
}

fn hexstring(slice: &[u8]) -> String {
    String::from("0x")
        + &slice
            .iter()
            .map(|n| format!("{:02X}", n))
            .collect::<Vec<String>>()
            .join(", 0x")
}
