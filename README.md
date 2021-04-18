# ssss-rs

Shamir's secrets sharing scheme CLI that uses rust Nebulosus/shamir library.

This project has been created to replace the use of [ssss](http://point-at-infinity.org/ssss/) command in 
[shamir ISO project](https://github.com/aitorpazos/shamir-iso).

## Usage

This command is organised in two subcommands: one to split a secret in shares and another one to combine the shares to
recover the secret. Both commands accept the secret/shares from command arguments or from stdin.

Currently the project is only released as an x86_64 binary that you can download from [releases](https://github.com/aitorpazos/ssss-rs/releases/latest).

### Split secret

Example of splitting a secret in 4 shares with a threshold of 2:

```
$ ssss-rs split -t2 -s4 -i "this is my secret"
01f92705cb752abb31f9243a692ddb1d3573
0275f6b1188aeff8025ec31447f508acc57a
03f8b9dda0dfac3013ca9e0e5dbdb0c3957d
04764fc2a56f7e7e640b16481b5eb5d53e68
```

### Combine shares

Example for combining the shares in previous split:

```
$ ssss-rs combine - << EOF
0275f6b1188aeff8025ec31447f508acc57a
04764fc2a56f7e7e640b16481b5eb5d53e68
EOF
Recovered key: this is my secret
Recovered key in base64: dGhpcyBpcyBteSBzZWNyZXQ=
Error decoding key to hex (expected for non hexadecimal keys): OddLength
BIP39 words list generation skipped
```

You can pass `-s` to output just the key (useful for use with scripts):

```
$ ssss-rs combine -s 0275f6b1188aeff8025ec31447f508acc57a 04764fc2a56f7e7e640b16481b5eb5d53e68
this is my secret
```
