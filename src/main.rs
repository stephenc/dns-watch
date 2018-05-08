// Copyright 2018 Stephen Connolly.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE.txt or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT.txt or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate domain;
extern crate getopts;
extern crate handlebars;
extern crate serde;
extern crate serde_json;

use domain::bits::DNameBuf;
use domain::resolv::conf::ResolvConf;
use domain::resolv::lookup::lookup_host;
use domain::resolv::Resolver;
use getopts::Matches;
use getopts::Options;
use handlebars::Handlebars;
use serde_json::map::Map;
use serde_json::Value;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;

fn create_options() -> Options {
    let mut opts = Options::new();
    opts.optmulti(
        "v",
        "var",
        "define a host variable, N, with the value being the resolved A record addresses of HOST. \
            If HOST is omitted then assume N is the same as the hostname, \
            in other words '--var www.example.com' is the same as \
            '--var www.example.com:www.example.com'.",
        "N[:HOST]",
    ).optmulti(
        "c",
        "const",
        "define a constant, N, with the value VAL",
        "N=VAL",
    ).optopt(
        "w",
        "watch",
        "run CMD every time the template is updated",
        "CMD",
    ).optopt(
        "o",
        "out",
        "set output file name. Use '--out -' to send the output to standard out. \
            If not specified then the name will be inferred from the input file name: \
            input files with a name ending in '.hbs' will have the '.hbs' removed, \
            otherwise '.out' will be appended to the input file name.",
        "NAME",
    ).optopt(
        "t",
        "timeout",
        "set the DNS lookup timeout (default: 1)",
        "SECS",
    ).optopt(
        "i",
        "interval",
        "specify the interval between rechecking DNS for changes when using --watch (default: 1)",
        "SECS",
    )
    .optflag("d", "debug", "enable debug output")
    .optflag("h", "help", "print this help menu");
    opts
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE", program);
    println!("{}", opts.usage(&brief));
    println!();
    println!(
        "Writes a file based on a handlebars template used to substitute in resolved ip addresses"
    );
}

fn evaluate(matches: &Matches, timeout: u64, debug: bool) -> Value {
    let mut data = Map::new();
    for const_var in matches.opt_strs("c") {
        let mut splitter = const_var.splitn(2, '=');
        data.insert(
            splitter.next().unwrap().to_string(),
            Value::String(splitter.next().unwrap().to_string()),
        );
    }
    let mut conf = ResolvConf::default();
    conf.timeout = Duration::from_millis(timeout);
    for host_var in matches.opt_strs("v") {
        let mut splitter = host_var.splitn(2, ':');
        let alias_name: &str = splitter.next().unwrap();
        let host_name: &str = splitter.next().unwrap_or_else(|| alias_name.clone());
        data.insert(
            alias_name.to_string(),
            match Resolver::run_with_conf(conf.clone(), |resolv| {
                let host = DNameBuf::from_str(host_name.clone()).unwrap();
                lookup_host(resolv, host)
            }) {
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
                    Value::Array(
                        addrs
                            .iter()
                            .map(|addr| Value::String(addr.to_string()))
                            .collect::<Vec<_>>(),
                    )
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
                    Value::Null
                }
            },
        );
    }
    Value::Object(data)
}

fn render<'a>(handlebars: &'a Handlebars, template: &'a str, ctx: &'a Value, output_file: &'a str) {
    let mut file = match File::create(output_file) {
        Err(why) => panic!("couldn't create {}: {}", output_file, why.description()),
        Ok(file) => file,
    };
    match handlebars.render_to_write(template, &ctx, &mut file) {
        Err(why) => panic!(
            "couldn't render template {}: {}",
            output_file,
            why.description()
        ),
        Ok(file) => file,
    };
}

fn fork_child(cmd: String, debug: bool) {
    let mut child = match Command::new(cmd.clone())
        .stdout(Stdio::null())
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Err(why) => panic!(
            "couldn't spawn watch process {}: {}",
            cmd,
            why.description()
        ),
        Ok(child) => {
            if debug {
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
                    cmd,
                    why.description()
                );
                0
            }
            Ok(exit_status) => {
                if debug {
                    println!(
                        "DEBUG: watch process pid {} terminated with {}",
                        child_id, exit_status
                    );
                }
                0
            }
        }
    });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let opts = create_options();
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

    let mut handlebars = Handlebars::new();
    match handlebars.register_template_file("template", Path::new(&matches.free[0])) {
        Ok(_) => (),
        Err(f) => panic!(f.to_string()),
    };

    let output_file = match matches.opt_str("o") {
        Some(x) => x,
        None => {
            let mut name: String = matches.free[0].to_string();
            let len = name.len();
            if name.ends_with(".hbs") {
                name.truncate(len - 4)
            } else {
                name.push_str(".out")
            }
            name
        }
    };
    let timeout: u64 = match matches.opt_str("t") {
        Some(seconds) => match seconds.parse::<u64>() {
            Ok(seconds) => seconds * 1000,
            Err(_) => panic!("Could not parse supplied timeout"),
        },
        None => 1000,
    };
    if matches.opt_present("w") {
        if output_file.eq("-") {
            panic!("Cannot use --watch with output to standard out");
        }
        let interval: u64 = match matches.opt_str("i") {
            Some(seconds) => match seconds.parse::<u64>() {
                Ok(seconds) => seconds * 1000,
                Err(_) => panic!("Could not parse supplied interval"),
            },
            None => 1000,
        };
        let cmd = matches.opt_str("w").unwrap().clone();
        loop {
            let m = matches.clone();
            let ctx = &evaluate(&m, timeout, debug);
            let old_ctx = ctx.clone();
            render(&handlebars, "template", ctx, &output_file);
            if debug {
                println!("DEBUG: {} updated", output_file);
            }
            fork_child(cmd.clone(), debug);
            while evaluate(&m, timeout, debug).eq(&old_ctx) {
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
            handlebars
                .render_to_write("template", &ctx, &mut io::stdout())
                .expect("Template failed to render");
        } else {
            render(&handlebars, "template", ctx, &output_file);
        }
    }
}
