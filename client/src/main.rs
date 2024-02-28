#![feature(cell_update)]

use num::bigint::BigUint;
use std::io::Read;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::vec;
use std::io::Write;

pub mod rsa;
use rsa::{decrypt_message, generate_rsa_key, run_client, EncryptAbleMessage, Message, RsaKey};

use crate::rsa::{PrivateRSAKey, PublicRSAKey};

fn main() {
    let mode = input(
        "Enter \n\t
        e : to encrypt a message using a public key\n\t
        d : to decrypt a message using a private key\n\t
        gen : to generate a public / private RSA key pair\n\t
        real : To connect to server and set up messageing\n\t
        : ",
    )
    .unwrap();
    match mode.as_str() {
        "real" => handle_real(),
        "e" => handle_encrypt(),
        "d" => handle_dcrypt(),
        "gen" => handle_gen(),
        _ => {
            println!("No command Found, Exiting");
            return;
        }
    }
}
fn handle_gen() {
    let Ok(size) = input("Size of RSA key pair (2048 or 4096): ") else {
        println!("No Such File");
        return;
    };
    let size: u64 = size.parse().unwrap();

    let Ok(file_name) = input("Name of file to save key to: ") else {
        println!("Error");
        return;
    };

    let key = generate_rsa_key(size);
    println!(
        "Public:  {}\nPrivate:  {}",
        key.public.clone().to_string(),
        key.private.clone().to_string()
    );
    std::fs::write(
        file_name.to_owned(),
        key.public.to_string() + "\n" + key.private.to_string().as_str(),
    );
}
fn handle_real() -> () {
    let Ok(key_file) = input("Enter the file with RSA key pair: ") else {
        println!("No Such File");
        return;
    };

    let file = std::fs::read_to_string(key_file).expect("FIle IO Error");
    let mut f: Vec<&str> = file.split("\n").collect();
    let p = PublicRSAKey::from_string(f[0].trim().to_owned()).unwrap();
    let d = PrivateRSAKey::from_string(f[1].trim().to_owned()).unwrap();

    let rsa_key = RsaKey {
        public: p.clone(),
        private: d.clone(),
    };

    let mut s = run_client(rsa_key.clone()).unwrap();

    println!("Connected to Server");

    let Ok(reciever_file) = input("Enter the file with reciever RSA Public Key: ") else {
        println!("No Such File");
        return;
    };
    let file = std::fs::read_to_string(reciever_file.clone()).expect("FIle IO Error");
    let mut f: Vec<&str> = file.split("\n").collect();
    let rec_key = PublicRSAKey::from_string(f[0].trim().to_owned()).unwrap();

    s.set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();

    let mutex_d_socket = Arc::new(Mutex::new(s));
    let cloned_socket = mutex_d_socket.clone();

    let p_c = p.clone();
    let d_c = d.clone();

    std::thread::spawn(move || -> () {
        let mut socket_open = true;

        while socket_open == true {
            std::thread::sleep(Duration::from_millis(100));
            let mut buf = [0; 4096];

            let mut stream = cloned_socket.lock().unwrap();

            let Ok(size) = stream.read(&mut buf) else {
                drop(stream);
                continue;
            };

            if size == 0 {
                socket_open = false;
                stream.shutdown(std::net::Shutdown::Both);
                drop(stream);
                continue;
            }

            let mut big_buffer: Vec<u8> = Vec::with_capacity(4096);
            big_buffer.append(&mut buf.to_vec());

            loop {
                let mut buf = [0; 4096];

                let Ok(num_bytes) = stream.read(&mut buf) else {
                    break;
                };

                if num_bytes == 0 {
                    break;
                }

                let mut trimmed_buffer = buf
                    .iter()
                    .enumerate()
                    .filter(|x| x.0 < num_bytes)
                    .map(|x| *x.1 as u8)
                    .collect();
                big_buffer.append(&mut trimmed_buffer);
            }
            // println!("Raw Data{:?}", big_buffer);
            let fixed = big_buffer
                .into_iter()
                .filter(|b| -> bool {
                    if *b == 0b00000000 {
                        return false;
                    } else {
                        return true;
                    }
                })
                .collect();

            let mut response = String::from_utf8(fixed).unwrap();
            let mut response = response.trim();

            let mut chunks = vec![];
            if response.contains(",") {
                chunks = response
                    .split(",")
                    .map(|x| -> BigUint { BigUint::from_str(x.trim()).unwrap() })
                    .collect();
            } else {
                chunks = vec![BigUint::from_str(response).unwrap()];
            }

            let response = decrypt_message(chunks, d_c.clone(), p_c.clone());
            println!("\n\tRecieving Message: \n{}", response);
            drop(stream);
        }
    });

    loop {
        let message = input(format!("Write your message to {}: ", reciever_file).as_str()).unwrap();

        let message = EncryptAbleMessage {
            sender: rsa_key.public.clone(),
            text: message,
        };

        let message = message.encrypt(&rec_key);

        let message = Message {
            reciever: rec_key.clone(),
            encrypted_part: message,
        };
        let message = message.to_string();

        let mut stream = mutex_d_socket.lock().unwrap();
        stream.write_all(&message.as_bytes());

        println!("Message Written");
        drop(stream);
    }
}

fn handle_dcrypt() -> () {
    let Ok(key_file) = input("Enter the file with public key: ") else {
        println!("No Such File");
        return;
    };

    let file = std::fs::read_to_string(key_file.clone()).expect("FIle IO Error");
    let mut f: Vec<&str> = file.split("\n").collect();
    let p = PublicRSAKey::from_string(f[0].trim().to_owned()).unwrap();
    let d = PrivateRSAKey::from_string(f[1].trim().to_owned()).unwrap();

    let Ok(chunk_file) = input("Enter the file with Big Int Chunks: ") else {
        println!("No Such File");
        return;
    };

    let file = std::fs::read_to_string(chunk_file.clone()).expect("FIle IO Error");
    let response: Vec<BigUint> = file
        .split(",")
        .filter(|x| x.len() > 0)
        .map(|x| -> BigUint {
            let trimmed = x.trim().replace("[", "").replace("]", "");
            BigUint::from_str(trimmed.as_str()).unwrap()
        })
        .collect();

    let response = decrypt_message(response, d, p);

    std::fs::write(chunk_file.to_owned() + ".dec", response.clone());
    println!("{}", response);
}

fn handle_encrypt() -> () {
    let Ok(key_file) = input("Enter the file with Public key: ") else {
        println!("Input Error");
        return;
    };

    let file = std::fs::read_to_string(key_file.clone()).expect("FIle IO Error");
    let mut f: Vec<&str> = file.split("\n").collect();
    let p = PublicRSAKey::from_string(f[0].trim().to_owned()).unwrap();

    let Ok(chunk_file) = input("Enter the file with text to encrypt: ") else {
        println!("Input Error");
        return;
    };

    let file = std::fs::read_to_string(chunk_file.clone()).expect("FIle IO Error");
    let message = EncryptAbleMessage {
        sender: p.clone(),
        text: file,
    };
    let response = message.encrypt(&p);
    let r: Vec<String> = response
        .clone()
        .iter()
        .map(|f| -> String { f.to_string() })
        .collect();

    let file = std::fs::write(chunk_file.clone() + ".enc", b"");
    let mut f = std::fs::File::options()
        .append(true)
        .open(chunk_file.clone() + ".enc")
        .unwrap();

    write!(&mut f, "[").unwrap();
    for (i, s) in r.iter().enumerate() {
        if i < r.len() - 1 {
            write!(&mut f, "{},", s).unwrap();
        } else {
            write!(&mut f, "{}", s).unwrap();
        }
    }
    write!(&mut f, "]").unwrap();

    println!("{:?}", response);
}

fn input(prompt: &str) -> Result<String, std::io::Error> {
    let mut buffer = String::new();
    print!("{}", prompt);
    std::io::stdout().flush();
    std::io::stdin().read_line(&mut buffer)?;
    return Ok(buffer.trim().to_string());
}
