// use hush::{Hush, Record, open_existing_file};

use clap::{Parser, Subcommand};
use hush_lib::Hush;

use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// File to operate on
    #[arg(short, long, value_name = "vault", default_value = "vault")]
    file: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Read all records from the file
    Read {},
    /// Append a key-value record to the file
    AppendKv {
        /// Key
        key: String,
        /// Value
        value: String,
    },
    /// Find records by a search term
    Find {
        /// Search term
        term: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let mut hush = Hush::new(&cli.file).unwrap();

    match &cli.command {
        Commands::Read {} => hush
            .read_all()
            .unwrap()
            .iter()
            .for_each(|r| println!("{r}")),
        Commands::AppendKv { key, value } => hush.append_key_value(key, value).unwrap(),
        Commands::Find { term } => hush
            .find(term)
            .unwrap()
            .iter()
            .for_each(|r| println!("{r}")),
    }
}
