extern crate redis;
extern crate repsheet_etl;
extern crate getopts;

use getopts::Options;
use std::env;
use redis::Commands;
use std::collections::HashMap;
use std::collections::hash_map::Entry::{Vacant, Occupied};

fn blacklist(connection: &redis::Connection, actor: &str, reason: &str) -> redis::RedisResult<()> {
    let _ : () = try!(connection.set(format!("{}:repsheet:ip:blacklisted", actor), reason));
    Ok(())
}

fn lookup_or_zero(hash: &mut HashMap<String, i64>, key: &str) -> i64 {
    match hash.entry(key.to_string()) {
        Occupied(v) => return *v.get(),
        Vacant(_) => return 0,
    }
}

fn apply_ruleset(connection: &redis::Connection, actors: &mut HashMap<String, repsheet_etl::actor::Actor>) {
    for (address, actor) in actors {
        if lookup_or_zero(&mut actor.responses, "404") > 10 {
            let _ = blacklist(connection, address, "404 violations");
        }

        let posts   = lookup_or_zero(&mut actor.methods, "POSTS");
        let puts    = lookup_or_zero(&mut actor.methods, "PUT");
        let deletes = lookup_or_zero(&mut actor.methods, "DELETE");
        let heads   = lookup_or_zero(&mut actor.methods, "HEAD");
        let options = lookup_or_zero(&mut actor.methods, "OPTIONS");

        if posts > 0 || puts > 0 || deletes > 0 || heads > 0 || options > 0 {
            let _ = blacklist(connection, address, "Unallowed methods");
        }

        if actor.invalid_request_count > 0 {
            let _ = blacklist(connection, address, "Invalid request");
        }
    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} FILE [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let client = redis::Client::open("redis://127.0.0.1").unwrap();
    let connection = client.get_connection().unwrap();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();

    opts.optopt("i", "infile", "Set input file name", "NAME");
    opts.optflag("h", "help", "Print help");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let input = match matches.opt_str("i") {
        Some(x) => x,
        None => "access.log".to_string(),
    };

    let _ = match repsheet_etl::process(&input) {
        Ok(mut actors) => { apply_ruleset(&connection, &mut actors) },
        Err(e) => println!("{}", e),
    };
}
