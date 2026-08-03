# Hush

An encryption/decryption tool.

It is not meant to be used by anyone, just doodling here for fun.

## Usage
```bash
cd hush-cli
cargo run -- --help

Usage: hush-cli [OPTIONS] <COMMAND>

Commands:
  read       Read all records from the file
  append-kv  Append a key-value record to the file
  find       Find records by a search term
  delete     Mark a record as deleted
  help       Print this message or the help of the given subcommand(s)

Options:
  -f, --file <vault>  File to operate on [default: vault]
  -h, --help          Print help
  -V, --version       Print version  

```

## Repository structure

- `hush-cli` - crate with the CLI utility
- `hush-lib` - lib crate
  - `hush-lib/hush-derive` - crate with the derive macros for serialization, deserialization of the records, etc.

## File format

All integers are big endian, all strings are UTF8.

| Type     | Meaning  |
|----------|----------|
| u64      | Counter for records; is incremented on each record append |
| [u8; 12] | 12 bytes of salt for PBKDF2 |
| u64      | Length of the first encrypted record  |
| [u8]     | Ciphertext of the first encrypted record  |
| u64      | Length of the second encrypted record  |
| [u8]     | Ciphertext of the second encrypted record  |
| ...      | ... |

Each ciphertext contains a serialized record of a record type. Each record type is represented by the enum `Record`.
Here is an example of the serialization the key/value record:

| Type     | Meaning  |
|----------|----------|
| u8       | `0`; ID of the record type; `1` for title/key/value records, discrimanant of the `Record` enum |
| u8       | Deleted flag |
| u64      | ID of the record; counter from the beginning of the file is incremented and stored here on each append |
| u32      | Length of the following string |
| String   | String that conatins the key |
| u32      | Length of the following string |
| String   | String that conatins the value |

Serialization/deserialization is handled in the `hush-derive` macro.

