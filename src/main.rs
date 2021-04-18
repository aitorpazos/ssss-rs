extern crate base64;
extern crate bip39;
extern crate hex;
extern crate regex;
extern crate shamir;

extern crate clap;
extern crate core;

use bip39::Mnemonic;
use clap::{App, Arg, ArgMatches, SubCommand};
use regex::Regex;
use shamir::SecretData;
use std::io;

/// Defines command line arguments
fn arg_matches<'a>() -> ArgMatches<'a> {
    App::new("ssss-rs")
        .about("Split or recover the secret using Shamir's secret sharing scheme.")
        .subcommand(SubCommand::with_name("split")
            .about("Split secret into shares")
            .arg(Arg::with_name("shares").short("s").takes_value(true)
                .help("The number of shares to split the secret in"))
            .arg(Arg::with_name("threshold").short("t").takes_value(true)
                .help("The number of shares required to recover the secret"))
            .arg(Arg::with_name("secret").short("i").takes_value(true)
                .help("Secret to split. Use - to read secret from standard input")))
        .subcommand(SubCommand::with_name("combine")
            .about("Combine shares to recover a secret")
            .arg(Arg::with_name("short").short("s").long("short").takes_value(false)
                .help("Displays only the combined key"))
            .arg(Arg::with_name("shares")
                .required(true)
                .multiple(true)
                .help("The shares to combine (space separated). Use - to read from stdin (one per line)")))
        .get_matches()
}

/// Reads stdin and normalizes passphrase
fn subcommand_dispatch(app_m: ArgMatches) {
    if let Some(split_match) = app_m.subcommand_matches("split") {
        let secret = match split_match.value_of("secret") {
            Some(s) => {
                if "-".eq(s) {
                    let mut input = String::new();
                    io::stdin()
                        .read_line(&mut input)
                        .expect("Failed to read passphrase");
                    normalize_string(input)
                } else {
                    s.to_string()
                }
            }
            None => panic!("No secret has been provided"),
        };
        let shares_number: u8 = split_match
            .value_of("shares")
            .unwrap()
            .parse()
            .expect("Unable to read shares number");
        let threshold: u8 = split_match
            .value_of("threshold")
            .unwrap()
            .parse()
            .expect("Unable to read thershold number");
        let shares = secret_split(secret, shares_number, threshold);
        for share in shares {
            println!("{}", share);
        }
    }
    if let Some(combine_match) = app_m.subcommand_matches("combine") {
        let shares_str = combine_match
            .values_of("shares")
            .unwrap()
            .collect::<Vec<_>>();
        let mut shares: Vec<String> = vec![];
        if "-".eq(shares_str[0].trim()) {
            let mut input = String::new();
            while io::stdin()
                .read_line(&mut input)
                .expect("Failed to read passphrase")
                > 0
            {
                let normalised_string = normalize_string(input.clone());
                input.clear();
                shares.push(normalised_string);
            }
        } else {
            for share in shares_str {
                shares.push(share.to_string());
            }
        }
        let threshold = shares.len() as u8;
        let secret = combine_shares(shares, threshold);
        if combine_match.is_present("short") {
            short_output(secret);
        } else {
            full_output(secret);
        }
    }
}

/// Program entrypoint
fn main() {
    subcommand_dispatch(arg_matches());
}

/// Performs key split
fn secret_split(secret: String, shares_number: u8, threshold: u8) -> Vec<String> {
    let mut shares: Vec<String> = vec![];
    let shamir_secret = SecretData::with_secret(normalize_string(secret).as_str(), threshold);
    let mut i = 1;
    while i <= shares_number {
        shares.push(hex::encode(shamir_secret.get_share(i).unwrap()));
        i += 1;
    }
    shares
}

/// Performs shares combination
fn combine_shares(shares: Vec<String>, threshold: u8) -> String {
    let mut shares_u8: Vec<Vec<u8>> = vec![];
    for share in shares {
        let share_u8 = hex::decode(normalize_string(share)).unwrap();
        shares_u8.push(share_u8);
    }
    normalize_string(SecretData::recover_secret(threshold, shares_u8).unwrap())
}

/// Minimal output returning the combined key
fn short_output(key: String) {
    println!("{}", key);
}

/// Verbose output for combined key
fn full_output(key: String) {
    println!("Recovered key: {}", key);
    println!("Recovered key in base64: {}", base64::encode(key.clone()));
    let entropy = match hex::decode(normalize_string(key).as_bytes()) {
        Ok(entropy_vec) => entropy_vec,
        Err(e) => {
            println!(
                "Error decoding key to hex (expected for non hexadecimal keys): {:#?}",
                e
            );
            println!("BIP39 words list generation skipped");
            vec![]
        }
    };
    if !entropy.is_empty() {
        match Mnemonic::from_entropy(entropy.as_slice()) {
            Ok(mnemonic) => println!("BIP39 words list representation: {}", mnemonic.to_string()),
            Err(_) => println!("BIP39: Unable to generate words list"),
        };
    }
}

// Utils

/// Normalizes string removing leading and trailing spaces
fn normalize_string(input: String) -> String {
    let re = Regex::new(r"[\s\n]+").unwrap();
    re.replace_all(input.as_str(), " ").trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_secret_test() {
        let secret = "my secret";
        let response = secret_split(secret.to_string(), 4, 2);
        println!("Shares: {:#?}", response);
        let assert_vec = vec![
            hex::decode(response[0].clone()).unwrap(),
            hex::decode(response[1].clone()).unwrap(),
        ];
        assert_eq!(secret, SecretData::recover_secret(2, assert_vec).unwrap());
    }

    #[test]
    fn combine_shares_test() {
        let response = combine_shares(
            vec![
                "01661e9c862f37309602".to_string(),
                "0370d0ff77bb9fb46bee".to_string(),
            ],
            2,
        );
        assert_eq!("my secret", response);
    }

    #[test]
    fn full_output_test() {
        full_output(
            "30edb68cfccf3cd5e1a06a41da4a50ba2c937a732b9fcfca8c5d6a2ba0edf7bd ".to_string(),
        );
        full_output("this is my secret".to_string());
    }
}
