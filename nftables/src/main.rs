use std::io::Read;

use nftables::schema::Nftables;

fn main() {
    deserialize_stdin();
}

fn deserialize_stdin() {
    use std::io;
    let mut buffer = String::new();
    match io::stdin().read_to_string(&mut buffer) {
        Err(error) => panic!("Problem opening the file: {:?}", error),
        Ok(_) => {
            println!("Document: {}", &buffer);

            let deserializer = &mut serde_json::Deserializer::from_str(&buffer);
            let result: Result<Nftables, _> = serde_path_to_error::deserialize(deserializer);

            match result {
                Ok(_) => println!("Result: {:?}", result),
                Err(err) => {
                    panic!("Deserialization error: {}", err);
                }
            }
        }
    };
}
