use codes::crypt::pbkdf2;
use codes::crypt::{AESKey, BlockCipher, AES};
use codes::error::hamming::ErrorDetection;
use std::fs::File;
use std::io::{Read, Write};
use structopt::StructOpt;

#[derive(StructOpt)]
enum Mode {
    #[structopt(name = "encrypt")]
    Encrypt,
    #[structopt(name = "decrypt")]
    Decrypt,
}

#[derive(StructOpt)]
#[structopt(name = "cryptor", about = "Simple CLI encryption tool.")]
struct Cli {
    #[structopt(short, long)]
    input: Option<String>,
    #[structopt(short, long)]
    output: Option<String>,
    #[structopt(short, long)]
    password: String,
    #[structopt(subcommand)]
    mode: Mode,
}

fn run(args: Cli) -> Result<(), std::io::Error> {
    let mut bytes = Vec::new();

    // get password up/down to 256 bit length
    // TODO: better IV creation
    let key_vec = pbkdf2(
        args.password.bytes().collect(),
        (0..16).rev().collect(),
        10000,
        256,
    );
    assert_eq!(key_vec.len(), 32);
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = key_vec[i];
    }

    // read input, either from file or from stdin
    if let Some(filename) = args.input {
        File::open(filename)?.read_to_end(&mut bytes)?;
    } else {
        std::io::stdin().read_to_end(&mut bytes)?;
    }

    let iv = (0..16).collect();

    // initialize the encryption
    let aes = AES::new(AESKey::AES256(key));

    let data = match args.mode {
        Mode::Encrypt => {
            aes.encrypt(&iv, &mut bytes).unwrap();
            bytes.into_iter().encode().collect()
        }
        Mode::Decrypt => {
            bytes = bytes.into_iter().decode().collect();
            while bytes.len() & 15 != 0 {
                bytes.pop();
            }
            aes.decrypt(&iv, &mut bytes).unwrap();
            bytes
        }
    };

    // write the processed data to either a file or to stdout
    if let Some(filename) = args.output {
        File::create(filename)?.write(&data)
    } else {
        std::io::stdout().write(&data)
    }?;

    Ok(())
}

fn main() -> Result<(), std::io::Error> {
    run(Cli::from_args())
}
