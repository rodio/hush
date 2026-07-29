// use hush::{Hush, Record, open_existing_file};

use hush_lib::Hush;

const FILE_NAME: &str = "vault";

fn main() {
    let args = std::env::args().collect::<Vec<String>>();
    if args.len() < 2 {
        eprintln!("wrong arguments");
        return;
    }

    match args[1].as_str() {
        "read" => Hush::new(FILE_NAME)
            .unwrap()
            .read_all()
            .unwrap()
            .iter()
            .for_each(|r| println!("record: {:?}", r)),
        "append" => {
            if args.len() != 4 {
                eprintln!("usage: hush-cli append <key> <value>");
                return;
            }
            Hush::new(FILE_NAME)
                .unwrap()
                .append_key_value(&args[2], &args[3])
                .unwrap();
        }
        "find" => {
            if args.len() != 3 {
                eprintln!("usage: hush-cli find <term>");
                return;
            }
            Hush::new(FILE_NAME)
                .unwrap()
                .find(&args[2])
                .unwrap()
                .iter()
                .for_each(|r| println!("record: {:?}", r));
        }
        // "find" => find()?,
        _ => eprintln!("unknown command"),
    }
}
