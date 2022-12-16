use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

use crate::schema::Nftables;

const NFT_EXECUTABLE: &str = "nft"; // search in PATH

pub fn get_current_ruleset(program: Option<&str>, args: Option<Vec<&str>>) -> Nftables {
    let output = get_current_ruleset_raw(program, args);
    let nftables: Nftables = serde_json::from_str(&output).unwrap();
    nftables
}

pub fn get_current_ruleset_raw(program: Option<&str>, args: Option<Vec<&str>>) -> String {
    let nft_executable: &str = program.unwrap_or(NFT_EXECUTABLE);
    let mut nft_cmd = get_command(Some(nft_executable));
    let default_args = ["-j", "list", "ruleset"];
    let args: Vec<&str> = match args {
        Some(mut args) => {
            args.extend_from_slice(&default_args);
            args
        }
        None => default_args.to_vec(),
    };
    let output = nft_cmd
        .args(args)
        .output()
        .expect("nft command failed to start");
    if !output.status.success() {
        panic!("nft failed to show the current ruleset");
    }
    String::from_utf8(output.stdout).expect("failed to decode nft output as utf8")
}

pub fn apply_ruleset(
    nftables: &Nftables,
    program: Option<&str>,
    args: Option<Vec<&str>>,
) -> io::Result<()> {
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw(nftables, program, args)
}

pub fn apply_ruleset_raw(
    payload: String,
    program: Option<&str>,
    args: Option<Vec<&str>>,
) -> io::Result<()> {
    let nft_executable: &str = program.unwrap_or(NFT_EXECUTABLE);
    let mut nft_cmd = get_command(Some(nft_executable));
    let default_args = ["-j", "-f", "-"];
    let args: Vec<&str> = match args {
        Some(mut args) => {
            args.extend_from_slice(&default_args);
            args
        }
        None => default_args.to_vec(),
    };
    let mut process = nft_cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = process.stdin.take().unwrap();
    stdin.write_all(payload.as_bytes())?;
    drop(stdin);

    let result = process.wait_with_output();
    match result {
        Ok(output) => {
            assert!(output.status.success());
            Ok(())
        }
        Err(err) => Err(err),
    }
}

fn get_command(program: Option<&str>) -> Command {
    let nft_executable: &str = program.unwrap_or(NFT_EXECUTABLE);
    Command::new(nft_executable)
}
