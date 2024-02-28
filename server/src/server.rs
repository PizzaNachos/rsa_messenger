use std::str::FromStr;
use std::sync::Arc;

use crate::types::RsaError;
use num::bigint::BigUint;
use rand::{Rng, SeedableRng};

use crate::types::{PrivateRSAKey, PublicRSAKey};
use log::debug;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::Duration;
// use tokio

pub async fn start_server() -> Result<(), Box<dyn Error>> {
    let socket = TcpListener::bind("127.0.0.1:9012").await?;
    let user_map: Arc<Mutex<HashMap<PublicRSAKey, Arc<Mutex<TcpStream>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    loop {
        let stream = socket.accept().await?;
        println!("Accepted socket {}", stream.1);

        let Ok(data) = verify_user(stream.0).await else {
            println!("User un verifiable");
            continue;
        };

        println!("User Verified!");
        let mut m = user_map.lock().await;

        let wrapped_socket = Arc::new(Mutex::new(data.1));
        (*m).insert(data.0, wrapped_socket.clone());

        let ucp = user_map.clone();

        let _ = tokio::spawn(async move {
            handle_connection(ucp, wrapped_socket.clone(), stream.1).await;
        });
    }
}

async fn verify_user(
    mut socket: TcpStream,
) -> Result<(PublicRSAKey, tokio::net::TcpStream), Box<dyn Error>> {
    // Buffer for reading from the socket
    let mut buf = [0; 4096];

    // Read from the socket
    let num_bytes = socket.read(&mut buf).await?;
    let trimmed_buffer = buf.iter().take(num_bytes).cloned().collect();
    let response = String::from_utf8(trimmed_buffer).map_err(|e| {
        eprintln!("Error converting bytes to string: {}", e);
        Box::new(e) as Box<dyn Error>
    })?;
    debug!("Received response: {}", response);

    // Parse the public key
    let client_pub_key = PublicRSAKey::from_string(response)?;
    println!("CBK\n{:?}", client_pub_key);

    // Generate a random secret
    let mut rng = StdRng::from_entropy();
    let random_secret: u128 = rng.gen();
    println!("Challenge\n{:?}", random_secret);

    // Encrypt the secret
    let encrypted_secret = rsa_encrypt_simple(random_secret.into(), &client_pub_key);
    socket.write_all(&encrypted_secret.to_bytes_le()).await?;
    debug!("Sent encrypted secret");

    // Read the response from the socket
    let num_bytes = socket.read(&mut buf).await?;
    let trimmed_buffer = buf.iter().take(num_bytes).cloned().collect();
    let response = String::from_utf8(trimmed_buffer).map_err(|e| {
        eprintln!("Error converting bytes to string: {}", e);
        Box::new(e) as Box<dyn Error>
    })?;
    debug!("Received response: {}", response);

    // Parse the response
    let test_num = BigUint::from_str(&response)?;
    debug!("Parsed test number: {:?}", test_num);

    // Check if the test number matches the secret
    if test_num == random_secret.into() {
        debug!("Test number matches the secret, user is verified");
        Ok((client_pub_key, socket))
    } else {
        eprintln!("Test number does not match the secret, shutting down the socket");
        socket.shutdown().await?;
        Err(Box::new(RsaError::new()))
    }
}

async fn handle_connection(
    user_map: Arc<Mutex<HashMap<PublicRSAKey, Arc<Mutex<TcpStream>>>>>,
    stream: Arc<Mutex<TcpStream>>,
    id: std::net::SocketAddr,
) {
    let mut socket_open = true;
    while socket_open == true {
        let mut buf = Vec::with_capacity(4096);
        let mut s = stream.lock().await;
        println!("Aquired lock for {} peeking for data", id);

        let in_socket = s.try_read_buf(&mut buf);
        match in_socket {
            Err(_) => {
                println!("\tNo data in buffer, Dropping Lock for {}", id);
                drop(s);
                tokio::time::sleep(Duration::from_millis(1500)).await;
                continue;
            }
            Ok(num_bytes) => {
                if num_bytes == 0 {
                    s.shutdown().await;
                    drop(s);
                    println!("Stream Closed");
                    socket_open = false;
                    break;
                } else {
                    // NOTE NEED TO ADD message end character to end of message, or a message length header
                    // How do we know when the message has finsihed transmitting? what if we read at tcp packet one
                    // but we dont wait for packets 2-5, maybe continuely loop inside here
                    println!("\tData in buffer!");
                    let mut big_buffer: Vec<u8> = Vec::with_capacity(4096);
                    big_buffer.append(&mut buf);

                    // Loop checking until buffer is empty
                    loop {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let in_socket = s.try_read_buf(&mut buf);
                        match in_socket {
                            Ok(num_bytes) => {
                                if num_bytes == 0 {
                                    println!("\tFound no extra bytes");
                                    break;
                                }
                                println!("\tFound {} extra bytes", num_bytes);
                                let mut trimmed_buffer = buf
                                    .iter()
                                    .enumerate()
                                    .filter(|x| x.0 < num_bytes)
                                    .map(|x| *x.1 as u8)
                                    .collect();
                                big_buffer.append(&mut trimmed_buffer);
                            }
                            Err(_) => {
                                println!("\tFound no extra bytes");
                                break;
                            }
                        }
                    }

                    let response = String::from_utf8(big_buffer).unwrap();

                    let i: Vec<&str> = response.split("-").collect();
                    println!("Key + message: {:?}", i);
                    let key_as_string = i[0];
                    // println!("\tkey:{}",key_as_string);
                    let message = i[1];
                    // println!("\tmessage:{}",message);

                    let recv = PublicRSAKey::from_string(key_as_string.to_owned()).unwrap();
                    println!("Public key obj {:?}", recv);
                    let u = user_map.lock().await;
                    println!("User map lock acuired");
                    let recv_stream = (*u).get(&recv).unwrap();
                    println!("Reciever Stream found");
                    let mut recv_stream = recv_stream.lock().await;
                    println!("Reciever stream lock aquired");
                    recv_stream.write(message.as_bytes()).await;
                    println!("Data written");
                }
            }
        }
    }
}

pub fn rsa_encrypt_simple(plaintext: BigUint, public_key: &PublicRSAKey) -> BigUint {
    return plaintext.modpow(&public_key.public_e, &public_key.public_n);
}

pub fn rsa_decrypt_simple(
    ciphertext: BigUint,
    private_key: &PrivateRSAKey,
    public_key: &PublicRSAKey,
) -> BigUint {
    return ciphertext.modpow(&private_key.private_d, &public_key.public_n);
}
