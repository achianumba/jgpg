use std::{
    error::Error,
    io::{self, Read},
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;

    let json = jgpg::to_string_pretty(&buffer).map_err(|e| {
        eprintln!("Failed to convert keyrings output to JSON object.");
        e
    })?;

    println!("{json}");

    Ok(())
}
