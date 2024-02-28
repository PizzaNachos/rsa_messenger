
use std::cell::Cell;
use std::error::Error;
use std::io::{Read, Write};
use std::mem::swap;
use std::net::TcpStream;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::Neg;
use std::str::FromStr;
use std::string::ParseError;
use std::sync::{mpsc::channel, Arc, Mutex};
use std::time::{Duration, Instant};
use std::{cell, thread};
use std::{hint::black_box, ops::Sub};

use num::bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use rand::{Rng, RngCore, SeedableRng};


pub fn run_client(key: RsaKey) -> Option<TcpStream> {
    let mut s = TcpStream::connect("localhost:9012").unwrap();
    let data = key.public.clone().to_string();
    let data = data.as_bytes();

    let ammount: () = s.write_all(data).unwrap();
    s.flush().unwrap();

    let mut buf = [0; 4096];

    let num_bytes = s.read(&mut buf).unwrap();
    let trimmed_buffer: Vec<u8> = buf
        .to_vec()
        .iter()
        .enumerate()
        .filter(|x| x.0 < num_bytes)
        .map(|x| *x.1 as u8)
        .collect();

    let challenge = BigUint::from_bytes_le(&trimmed_buffer);
    let decrypted = rsa_decrypt_simple(challenge, &key.private, &key.public);
    s.write((decrypted.to_string()).as_bytes()).unwrap();
    return Some(s);
}

pub struct Message {
    pub reciever: PublicRSAKey,
    pub encrypted_part: Vec<BigUint>,
}
impl Message {
    pub fn to_string(self) -> String {
        let mut final_string = String::new();
        let rec = self.reciever.to_string();
        final_string += &rec;
        final_string += "-";
        for (i, p) in self.encrypted_part.iter().enumerate() {
            if i < self.encrypted_part.len() - 1 {
                final_string += &p.to_string();
                final_string += ",";
            } else {
                final_string += &p.to_string();
            }
        }
        return final_string;
    }
}
// Max size 1024bit
pub struct EncryptAbleMessage {
    pub sender: PublicRSAKey,
    pub text: String,
}

impl EncryptAbleMessage {
    pub fn encrypt(self, key: &PublicRSAKey) -> Vec<BigUint> {
        let text = self.text;
        let size_of_chunk = key.public_n.to_bytes_be().len() - 10;
        // println!("BEFORE:\n{}",text);
        let text_as_bytes = text.bytes();
        // 128 bytes per chunk
        let mut chunks: Vec<BigUint> = Vec::new();

        let mut vec_b = Vec::new();
        for c in text_as_bytes.enumerate() {
            vec_b.push(c.1);

            if c.0 % size_of_chunk == 0 && c.0 > 0 {
                let bi = BigUint::from_bytes_le(&vec_b);
                chunks.push(bi);
                vec_b = Vec::new();
            }
        }

        let bi = BigUint::from_bytes_le(&vec_b);
        chunks.push(bi);

        let mut encrypted_chunks = Vec::new();
        for c in chunks {
            encrypted_chunks.push(rsa_encrypt_simple(c, &key))
        }

        return encrypted_chunks;
    }
}
pub fn test() {
    let k = generate_rsa_key(2048);
    let e = EncryptAbleMessage {
        sender: k.public.clone(),
        text: "ABCDEF abcdef this is my super secret message - ".to_owned(),
    };
    let a = e.encrypt(&k.public);
    let d = decrypt_message(a, k.private, k.public);
    println!("{:?}", d);
}

pub fn decrypt_message(
    chunks: Vec<BigUint>,
    private_key: PrivateRSAKey,
    public_key: PublicRSAKey,
) -> String {
    let mut decrypted_chunks = Vec::new();
    for c in chunks {
        decrypted_chunks.push(rsa_decrypt_simple(c, &private_key, &public_key));
    }
    let mut final_string = String::new();
    for c in decrypted_chunks {
        let b = c.to_bytes_le();
        let s = String::from_utf8(b).expect("msg");
        final_string += &s;
    }

    return final_string;
}

#[derive(Debug, Clone)]
pub struct RsaKey {
    pub public: PublicRSAKey,
    pub private: PrivateRSAKey,
}

#[derive(Debug, Clone)]
pub struct PublicRSAKey {
    pub public_n: BigUint,
    pub public_e: BigUint,
}
impl PublicRSAKey {
    pub fn to_string(self) -> String {
        let n = self.public_n.to_string();
        let e = self.public_e.to_string();
        return (n + "," + &e);
    }
    pub fn from_string(s: String) -> Result<PublicRSAKey, ()> {
        let mut p = s.split(",");
        let Some(n) = p.next() else {
            println!("first p isnt some");
            return Err(());
        };
        let Some(e) = p.next() else {
            println!("second p isnt some");
            return Err(());
        };

        let Ok(n) = BigUint::from_str(n) else {
            println!("Unable to parse N");
            return Err(());
        };
        let Ok(e) = BigUint::from_str(e) else {
            println!("Unable to parse E");
            return Err(());
        };

        return Ok(PublicRSAKey {
            public_e: e,
            public_n: n,
        });
    }
}

#[derive(Debug, Clone)]
pub struct PrivateRSAKey {
    pub private_d: BigUint,
}
impl PrivateRSAKey {
    pub fn to_string(self) -> String {
        let e = self.private_d.to_string();
        return e;
    }
    pub fn from_string(s: String) -> Result<PrivateRSAKey, ()> {
        let Ok(n) = BigUint::from_str(&s) else {
            return Err(());
        };
        return Ok(PrivateRSAKey { private_d: n });
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

pub fn generate_rsa_key(bit_size: u64) -> RsaKey {
    // let s = String::new();
    let t1 = Instant::now();
    let one: BigUint = BigUint::from(1_u32);

    let two_primes = generate_big_primes(bit_size / 2, 2);
    let t2 = Instant::now();

    let n: BigUint = &two_primes[0] * &two_primes[1];
    let t3 = Instant::now();

    // Everyone uses 65537 as the exponenet (I dont know why)
    let e: BigUint = BigUint::from(65537_u32);
    let phi_n: BigUint = (&two_primes[0] - &one) * (&two_primes[1] - &one);
    let t4 = Instant::now();
    let phi_n_bi: BigInt = phi_n.clone().into();

    let mut d = inverse_mod_n_biguint(e.clone(), phi_n.clone()).1;
    let t5 = Instant::now();
    while d < BigInt::from(0_i32) {
        d += &phi_n_bi;
    }

    assert!(
        (&e.to_bigint().expect("Weird") * &d) % phi_n_bi == one.to_bigint().expect("What"),
        "E and D wernt modular inverse"
    );
    let t6 = Instant::now();

    RsaKey {
        public: PublicRSAKey {
            public_n: n,
            public_e: e,
        },
        private: PrivateRSAKey {
            private_d: d.to_biguint().expect("error"),
        },
    }
}

/// Generate 100 random numbers and then paralize them into threads to run tests on all the numbers,
/// then filter out the numbers that are not prime and finally return the first element in our primes list
/// with a batch size of 100 the largest number of primes found was 5
pub fn generate_big_primes(bit_size: u64, number_of_primes: usize) -> Vec<BigUint> {
    let mut generator = rand::rngs::StdRng::from_entropy();

    let one = BigUint::from(1 as usize);
    let three = BigUint::from(3_u32);

    let batch_size = 250;
    let av_th: usize = std::thread::available_parallelism().unwrap().into();
    let num_threads = av_th - 2;

    let mut threads = Vec::new();

    let (tx, rx) = channel();

    let total_count: Arc<Mutex<Cell<i32>>> = Arc::new(Mutex::new(Cell::new(0)));

    let start = Instant::now();
    for i in 0..num_threads {
        let send_chanel = tx.clone();
        let start = Instant::now();
        let my_count = total_count.clone();
        let t = thread::spawn(move || -> _ {
            let end1: Instant = Instant::now();
            // println!("Thread {} Started at {:?}",i, end1-start);
            let mut odd_check_counter: usize = 0;

            let mut counter = 0;
            let mut test_nums: Vec<BigUint> = (0..batch_size)
                .map(|_| -> BigUint { generate_random_odd_number(bit_size) })
                .collect();

            loop {
                if solovay_strassen_primality_test(&test_nums[counter], 55) == true {
                    let end2: Instant = Instant::now();
                    // println!("Thread {} of {num_threads} found Prime in {:?}, tried {} nums",i, end2-start, odd_check_counter);
                    // println!("{}",test_nums[counter].clone());
                    let res = send_chanel.send(test_nums[counter].clone());
                    match res {
                        Err(_) => {
                            return ();
                        }
                        Ok(_) => {}
                    }
                }

                counter += 1;
                odd_check_counter += 1;

                if counter == batch_size {
                    test_nums = (0..batch_size)
                        .map(|_| -> BigUint { generate_random_odd_number(bit_size) })
                        .collect();
                    counter = 0;
                }

                let mut c = my_count.lock().unwrap();
                let mut c = c.update(|x| x + 1);
            }
        });
        threads.push(t);
    }

    let mut final_primes = Vec::with_capacity(number_of_primes);
    while final_primes.len() < number_of_primes {
        let prime: BigUint = rx.recv().unwrap();
        if !final_primes.contains(&prime) {
            final_primes.push(prime);
        }
    }
    let end = Instant::now();
    let mut c = total_count.lock().unwrap();
    println!(
        "{number_of_primes} primes found in {:#?} of random Odds tested\n\tTaking {}ms",
        c.get(),
        (end - start).as_millis()
    );
    println!("55 solovay strassen primality tests, 1 in 100 trillion chance each prime is actually composite");
    drop(c);

    return final_primes;
}

pub fn solovay_strassen_primality_test(n: &BigUint, iterations: usize) -> bool {
    let zero = BigUint::from(0_u32);
    let zero_bi = BigInt::from(0_u32);

    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let one_less = n - &two;
    // iterations should be near 55 for 1 in 100 trillion chance we are wrong
    let random_witnesses: Vec<BigUint> = (0..iterations)
        .map(|_| -> BigUint { generate_random_odd_number_range(&three, &one_less) })
        .collect();

    for whiteness in random_witnesses {
        let power = (n - &one) / &two;

        let jac = BigInt::from(jacobi_symbol(&whiteness, n));

        if &jac == &zero_bi {
            return false;
        }

        // Takes over a 1ms and im doing it 55 times per prime so 55ms atleast per prime
        let euloer = whiteness.modpow(&power, &n);
        let neg_euloer: BigInt = &(BigInt::from(euloer.clone())) - BigInt::from(n.clone());

        if jac != euloer.into() && jac != neg_euloer.into() {
            return false;
        }
    }

    return true;
}

pub fn generate_random_odd_number(bit_size: u64) -> BigUint {
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);

    let mut generator = rand::rngs::StdRng::from_entropy();
    let mut test_num: BigUint = generator.gen_biguint(bit_size);

    if &test_num & &one == zero {
        test_num = &test_num + &one;
    }
    return test_num;
}
pub fn generate_random_odd_number_range(lbound: &BigUint, ubound: &BigUint) -> BigUint {
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);

    let mut generator = rand::rngs::StdRng::from_entropy();
    let mut test_num: BigUint = generator.gen_biguint_range(lbound, ubound);

    if &test_num & &one == zero {
        test_num = &test_num + &one;
    }
    return test_num;
}
// Implementing the Jacobi symbol computation in Rust

pub fn bi(n: i32) -> BigInt {
    num::BigInt::from(n)
}
pub fn bu(n: u32) -> BigUint {
    num::BigUint::from(n)
}

pub fn jacobi_symbol(top: &BigUint, bottom: &BigUint) -> i32 {
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    if &(bottom & &one) != &one {
        panic!("bottom must be an odd integer");
    }

    let mut done = false;
    let mut result = 1;

    let mut top = (top % bottom).clone();
    let mut bottom = bottom.clone();

    while &top != &zero {
        // Rule 1
        // println!("|---|");
        // print!("\\{bottom}/");

        let tmp = &top % &bottom;
        top = tmp;
        // println!("{} / {}", top, bottom);

        // Rule 4, pull out the twos and see how it effects the rest of the vibe
        while &top > &zero && &top & BigUint::from(1_u32) == zero {
            top = (&top / &two);
            if n_is_a_mod_p(&bottom, &three, &eight) || n_is_a_mod_p(&bottom, &five, &eight) {
                result = -result;
            }
        }

        // Rule 5
        if is_odd(&top) {
            // Inverse and invert potentally
            swap(&mut top, &mut bottom);
            if n_is_a_mod_p(&top, &three, &four) && n_is_a_mod_p(&bottom, &three, &four) {
                result = -result;
            }
        }
    }
    if &bottom == &one {
        result
    } else {
        0
    }
}

pub fn n_is_a_mod_p(n: &BigUint, a: &BigUint, p: &BigUint) -> bool {
    return &(n % p) == a;
}
pub fn is_odd(n: &BigUint) -> bool {
    return (n & BigUint::from(1_u32)) == BigUint::from(1_u32);
}

fn gcd(num: BigUint, mod_n: BigUint) -> BigUint {
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let mut a = mod_n;
    let mut b = num;

    let mut done = false;
    let mut gcd = zero.clone();

    // From remainter to tuple of scales of mod_n and num

    while !done {
        if &(&a % &b) == &zero || &b == &one {
            gcd = b.clone();
            done = true;
        }

        if (&b < &zero) {
            return one;
        }

        let mut counter = BigUint::from(1_u32);
        let mut dup_a = a.clone();

        while dup_a >= &two * &b {
            dup_a = dup_a - &b;
            let tmp = counter + &one;
            counter = (tmp);
        }
        let remainder = &a - (&b * &counter);

        let a_scale = 1;
        let b_scale = counter;

        a = b;
        b = remainder;
    }

    return gcd;
}

fn inverse_mod_n_biguint(num: BigUint, mod_n: BigUint) -> (BigInt, BigInt) {
    let zero = BigUint::from(0_u32);
    let one = BigUint::from(1_u32);
    let two = &one + &one;
    let three = &two + &one;
    let four = &two + &two;
    let five = &four + &one;
    let eight = &four + &four;

    let mut a = mod_n;
    let mut b = num;

    let mut done = false;
    let mut gcd = zero.clone();

    // From remainter to tuple of scales of mod_n and num
    let mut rem_map: std::collections::HashMap<BigInt, (BigInt, BigInt)> =
        std::collections::HashMap::new();

    rem_map.insert(a.clone().into(), (one.clone().into(), zero.clone().into()));
    rem_map.insert(b.clone().into(), (zero.clone().into(), one.clone().into()));

    while !done {
        if &(&a % &b) == &zero || &b == &one {
            gcd = b.clone();
            done = true;
        }

        if (&b < &zero) {
            return (one.clone().into(), one.clone().into());
        }

        let mut dup_a = a.clone();
        let mut counter = &dup_a / &b;

        let remainder = &a - (&b * &counter);

        let a_scale = &one;
        let b_scale = &counter;

        let known_remainder_a = rem_map.get(&a.into()).expect("Value of A should be in map");
        let known_remainder_b = rem_map
            .get(&(b.clone()).into())
            .expect("Value of B should be in map");

        let tmp1: BigInt = counter.clone().into();
        let tmp2: BigInt = counter.into();

        let first: BigInt = known_remainder_a.0.clone() - (known_remainder_b.0.clone() * tmp1);
        let second: BigInt = known_remainder_a.1.clone() - (known_remainder_b.1.clone() * tmp2);

        let new_tuple = (first, second);
        rem_map.insert(remainder.clone().into(), new_tuple);

        a = b.clone();
        b = remainder.clone();
    }

    if &gcd != &one {
        println!("Not co-prime/no inverse");
        return (zero.clone().into(), zero.clone().into());
    }

    let val = rem_map.get(&one.into()).unwrap();
    return (val.0.clone().into(), val.1.clone().into());
}
