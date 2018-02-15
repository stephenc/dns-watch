extern crate getopts;
extern crate mustache;
extern crate serde;
extern crate domain;

use getopts::Options;
use getopts::Matches;
use mustache::Data;
use mustache::Template;
use std::env;
use mustache::MapBuilder;
use std::fs::File;
use std::io;
use std::io::BufWriter;
use std::io::prelude::*;
use std::str::FromStr;
use std::error::Error;
use std::collections::HashMap;
use std::time::Duration;
use domain::bits::DNameBuf;
use domain::resolv::Resolver;
use domain::resolv::conf::ResolvConf;
use domain::resolv::lookup::lookup_host;
use std::process::{Command, Stdio};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE", program);
    println!("{}", opts.usage(&brief));
    println!();
    println!(
        "Writes a file based on a mustache template used to substitute in resolved ip addresses"
    );
}

fn evaluate(matches: &Matches, timeout: u64, debug: bool) -> Data {
    let mut data = MapBuilder::new();
    for const_var in matches.opt_strs("c") {
        let mut splitter = const_var.splitn(2, '=');
        data = data.insert_str(splitter.next().unwrap(), splitter.next().unwrap());
    }
    let mut conf = ResolvConf::default();
    conf.timeout = Duration::from_millis(timeout);
    for host_var in matches.opt_strs("v") {
        let mut splitter = host_var.splitn(2, ':');
        let alias_name: &str = splitter.next().unwrap();
        let host_name: &str = splitter.next().unwrap_or_else(|| alias_name.clone());
        data = data.insert_vec(alias_name, |builder| match Resolver::run_with_conf(
            conf.clone(),
            |resolv| {
                let host = DNameBuf::from_str(host_name.clone()).unwrap();
                lookup_host(resolv, host)
            },
        ) {
            Ok(response) => {
                let mut addrs = response
                    .iter()
                    .filter(|x| x.is_ipv4())
                    .map(|addr| addr.clone().to_string())
                    .collect::<Vec<_>>();
                addrs.sort_by(|a, b| a.cmp(b));
                if debug {
                    println!(
                        "DEBUG: {} = {} => {:?}",
                        alias_name.clone(),
                        host_name.clone(),
                        addrs.clone()
                    )
                }
                let mut b = builder;
                for addr in addrs {
                    b = b.push_str(addr)
                }
                b
            }
            Err(e) => {
                if debug {
                    println!(
                        "DEBUG: {} = {} => [] : {}",
                        alias_name.clone(),
                        host_name.clone(),
                        e
                    )
                }
                builder
            }
        });
    }
    data.build()
}

fn render<'a>(template: &'a Template, ctx: &'a Data, output_file: &'a str) {
    let file = match File::create(output_file) {
        Err(why) => panic!("couldn't create {}: {}", output_file, why.description()),
        Ok(file) => file,
    };
    let mut buffer = BufWriter::new(file);
    match template.render_data(&mut buffer, &ctx) {
        Err(why) => {
            panic!(
                "couldn't render template {}: {}",
                output_file,
                why.description()
            )
        }
        Ok(file) => file,
    };
    match buffer.flush() {
        Err(why) => {
            panic!(
                "couldn't flush template {}: {}",
                output_file,
                why.description()
            )
        }
        Ok(buffer) => buffer,
    };
}

fn as_map(ctx: &Data) -> std::option::Option<&HashMap<String, Data>> {
    match ctx {
        &Data::Map(ref v) => Some(v.clone()),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optmulti(
        "v",
        "var",
        "define a host variable, N, with the value being the resolved A record addresses of HOST. \
            If HOST is omitted then assume N is the same as the hostname, \
            in other words '--var www.example.com' is the same as \
            '--var www.example.com:www.example.com'.",
        "N[:HOST]",
    );
    opts.optmulti(
        "c",
        "const",
        "define a constant, N, with the value VAL",
        "N=VAL",
    );
    opts.optopt(
        "w",
        "watch",
        "run CMD every time the template is updated",
        "CMD",
    );
    opts.optopt(
        "o", 
        "out", 
        "set output file name. Use '--out -' to send the output to standard out. \
            If not specified then the name will be inferred from the input file name: \
            input files with a name ending in '.mustache' will have the '.mustache' removed, \
            otherwise '.out' will be appended to the input file name.", 
        "NAME"
    );
    opts.optopt(
        "t",
        "timeout",
        "set the DNS lookup timeout (default: 1)",
        "SECS",
    );
    opts.optopt(
        "i",
        "interval",
        "specify the interval between rechecking DNS for changes when using --watch (default: 1)",
        "SECS",
    );
    opts.optflag("d", "debug", "enable debug output");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => panic!(f.to_string()),
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    if matches.free.is_empty() {
        print_usage(&program, opts);
        return;
    }
    let debug = matches.opt_present("d");
    let template_file = matches.free[0].clone();
    let mut input_file = File::open(template_file.clone()).expect("Unable to open the file");
    let mut template_contents = String::new();
    input_file.read_to_string(&mut template_contents).expect(
        "Unable to read the file",
    );
    let template = match mustache::compile_str(&template_contents) {
        Ok(t) => t,
        Err(f) => panic!(f.to_string()),
    };
    let output_file = match matches.opt_str("o") {
        Some(x) => x,
        None => {
            let mut name: String = template_file.to_string();
            let len = name.len();
            if name.ends_with(".mustache") {
                name.truncate(len - 9)
            } else {
                name.push_str(".out")
            }
            name
        }
    };
    let timeout: u64 = match matches.opt_str("t") {
        Some(seconds) => {
            match seconds.parse::<u64>() {
                Ok(seconds) => seconds * 1000,
                Err(_) => panic!("Could not parse supplied timeout"),
            }
        }
        None => 1000,
    };
    if matches.opt_present("w") {
        if output_file.eq("-") {
            panic!("Cannot use --watch with output to standard out");
        }
        let interval: u64 = match matches.opt_str("i") {
            Some(seconds) => {
                match seconds.parse::<u64>() {
                    Ok(seconds) => seconds * 1000,
                    Err(_) => panic!("Could not parse supplied interval"),
                }
            }
            None => 1000,
        };
        let cmd = matches.opt_str("w").unwrap().clone();
        loop {
            let m = matches.clone();
            let ctx = &evaluate(&m, timeout, debug);
            let old_ctx = as_map(ctx);
            render(&template, ctx, &output_file);
            if debug {
                println!("DEBUG: {} updated", output_file);
            }
            {
                let child_cmd = cmd.clone();
                let child_debug = debug.clone();
                let mut child = match Command::new(child_cmd.clone())
                    .stdout(Stdio::null())
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn() {
                    Err(why) => {
                        panic!(
                            "couldn't spawn watch process {}: {}",
                            child_cmd,
                            why.description()
                        )
                    }
                    Ok(child) => {
                        if child_debug {
                            println!("DEBUG: watch process pid {} started", child.id());
                        }
                        child
                    }
                };
                std::thread::spawn(move || {
                    let child_id = child.id();
                    match child.wait() {
                        Err(why) => {
                            println!(
                                "watch process failed to terminate {}: {}",
                                child_cmd,
                                why.description()
                            );
                            0
                        }
                        Ok(exit_status) => {
                            if child_debug {
                                println!(
                                    "DEBUG: watch process pid {} terminated with {}",
                                    child_id,
                                    exit_status
                                );
                            }
                            0
                        }
                    }
                });
            }
            while {
                as_map(&evaluate(&m, timeout, debug)).eq(&old_ctx)
            }
            {
                if debug {
                    println!("DEBUG: Sleep {}s", interval / 1000);
                }
                std::thread::sleep(Duration::from_millis(interval.clone()))
            }
        }
    } else {
        let m = matches.clone();
        let ctx = &evaluate(&m, timeout, debug);
        if output_file.eq("-") {
            template.render_data(&mut io::stdout(), ctx).expect(
                "Template failed to render",
            );
        } else {
            render(&template, ctx, &output_file);
        }
    }
}
