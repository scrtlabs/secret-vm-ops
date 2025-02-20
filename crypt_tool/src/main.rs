extern crate clap;
extern crate getrandom;
extern crate hex;
extern crate sha2;
extern crate x25519_dalek;
extern crate aes_siv;

use clap::{Parser, Subcommand};
use std::convert::TryInto;
use aes_siv::siv::Aes128Siv;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Rand(RandArgs),
    GenerateKey(GenerateKeyArgs),
    Encrypt(EncryptArgs),
    Decrypt(EncryptArgs),
}

#[derive(Parser)]
struct RandArgs {
    #[arg(short = 'n', long, default_value_t = 32)]
    bytes: usize,
}

#[derive(Parser)]
struct GenerateKeyArgs {
    #[arg(short = 's', long)]
    seed: String,
}

#[derive(Parser)]
struct EncryptArgs {
    #[arg(short = 's', long)]
    seed: String,
    #[arg(short = 'd', long)]
    data: String,
    #[arg(short = 'p', long)]
    pubkey: String,
}

fn generate_sk(seed: &String) -> x25519_dalek::StaticSecret {

    let buf = match hex::decode(seed) {
        Ok(buf) => buf,
        Err(e) => {
            panic!("bad key seed: {}", e);
        }
    };

    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(buf);

    let buf: [u8;32] = sha256.finalize().into();
    x25519_dalek::StaticSecret::from(buf)
}

fn sk_to_pk(sk: &x25519_dalek::StaticSecret) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(sk)
}

fn read_pk(pubkey: &String) -> x25519_dalek::PublicKey {
    match hex::decode(pubkey) {
        Ok(d) => {
            let arr: [u8; 32] = d.try_into().expect("wrong pubkey size");
            x25519_dalek::PublicKey::from(arr)
        },
        Err(e) => {
            panic!("bad pubkey: {}", e);
        }
    }
}

fn read_blob(data: &String) -> Vec<u8> {
    match hex::decode(data) {
        Ok(d) => d,
        Err(e) => {
            panic!("bad data: {}", e);
        }
    }
}

fn dh_get_key(args: &EncryptArgs) -> Aes128Siv {
    let sk = generate_sk(&args.seed);
    let pk = read_pk(&args.pubkey);

    let shared_secret = sk.diffie_hellman(&pk);
    Aes128Siv::new(shared_secret.to_bytes().into())
}

fn main() -> () {

    let cli = Cli::parse();

    match cli.command {
        Commands::Rand(rand_args) =>
        {
            let mut data = vec![0u8; rand_args.bytes];
            getrandom::getrandom(&mut data).unwrap();
            println!("{}", hex::encode(data));
        },
        Commands::GenerateKey(args) =>
        {
            let sk = generate_sk(&args.seed);
            let pk = sk_to_pk(&sk);
            println!("{}", hex::encode(pk.to_bytes()));
        },
        Commands::Encrypt(args) =>
        {
            let mut key = dh_get_key(&args);
            let data = read_blob(&args.data);

            let res = key.encrypt([&[]], &data).unwrap();
        
            //println!("{}{}", hex::encode(sk_to_pk(&sk).to_bytes()), hex::encode(res));
            println!("{}", hex::encode(res));
        },
        Commands::Decrypt(args) =>
        {
            let mut key = dh_get_key(&args);
            let data = read_blob(&args.data);

            let res = key.decrypt([&[]], &data).unwrap();
        
            //println!("{}{}", hex::encode(sk_to_pk(&sk).to_bytes()), hex::encode(res));
            println!("{}", hex::encode(res));
        },
    }
}
