// Copyright 2018-2019 Stephen Connolly.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE.txt or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT.txt or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate domain;
extern crate getopts;
extern crate handlebars;
extern crate meval;
extern crate regex;
extern crate serde;
extern crate serde_json;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::string::String;
use std::thread;
use std::time::Duration;

use domain::core::bits::name::Dname;
use domain::resolv::lookup::lookup_addr;
use domain::resolv::lookup::lookup_host;
use domain::resolv::stub::conf::ResolvConf;
use domain::resolv::stub::resolver::StubResolver;
use getopts::Matches;
use getopts::Options;
use handlebars::{Context, Handlebars, Helper, HelperResult, Output, RenderContext};
use handlebars::JsonRender;
use handlebars::RenderError;
use regex::Regex;
use serde_json::map::Map;
use serde_json::Value;

fn create_options() -> Options {
    let mut opts = Options::new();
    opts.optmulti(
        "v",
        "var",
        "define a host variable, N, with the value being the resolved A record addresses of \
         HOST. If HOST is omitted then assume N is the same as the hostname, \
         in other words '--var www.example.com' is the same as \
         '--var www.example.com:www.example.com'. Appending ':hn' or `:fqdn' to the host \
         requests that a hostname lookup is performed on the returned IP addresses. For ':hn'\
         only the hostname portion of successful lookups is used while ':fqdn' uses the \
         fully qualified domain name. If reverse lookups are enabled but fail, the IP address \
         will be used.",
        "N[:HOST[:(hn)|(fqdn)]",
    )
    .optmulti(
        "c",
        "const",
        "define a constant, N, with the value VAL",
        "N=VAL",
    )
    .optmulti(
        "l",
        "list",
        "define a '=' separated list, N, with the values VAL1, VAL2, etc",
        "N=VAL1=VAL2...",
    )
    .optopt(
        "w",
        "watch",
        "run CMD every time the template is updated",
        "CMD",
    )
    .optopt(
        "o",
        "out",
        "set output file name. Use '--out -' to send the output to standard out. \
         If not specified then the name will be inferred from the input file name: \
         input files with a name ending in '.hbs' will have the '.hbs' removed, \
         otherwise '.out' will be appended to the input file name.",
        "NAME",
    )
    .optopt(
        "t",
        "timeout",
        "set the DNS lookup timeout (default: 1)",
        "SECS",
    )
    .optopt(
        "i",
        "interval",
        "specify the interval between rechecking DNS for changes when using --watch (default: 1)",
        "SECS",
    )
    .optopt(
        "",
        "attempts",
        "specify the number of attempts to retry DNS lookups (default: 1)",
        "ATTEMPTS",
    )
    .optopt(
        "",
        "ndots",
        "Number of dots before an initial absolute query is made. (default: 0)",
        "NDOTS",
    )
    .optflag("", "recurse", "use recursive DNS queries")
    .optflag(
        "f",
        "fast-start",
        "render empty DNS results first and then start DNS resolution (when using --watch)",
    )
    .optflag(
        "",
        "use-millis",
        "all times are expressed in milliseconds not seconds",
    )
    .optflag("d", "debug", "enable debug output")
    .optflag("h", "help", "print this help menu")
    .optflag("V", "version", "print the version and exit");
    opts
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options] FILE", program);
    println!("{}", opts.usage(&brief));
    println!();
    println!(
        "Writes a file based on a handlebars template used to substitute in resolved ip addresses."
    );
    println!();
    println!("NOTE: handlebars support is provided by handlebars-rs");
    println!("  * Mustache blocks are not supported, use if/each instead");
    println!("  * Chained else is not supported");
    println!();
    println!("Custom helpers:");
    println!("  * {{eval ...}} evaluates basic integer numeric expressions and return the result");
    println!("    for example {{#each foo}}{{eval @index \"+100\"}},{{/each}} will add 100 to the");
    println!("    @index values inside the loop");
}

fn evaluate_empty(matches: &Matches) -> Value {
    let mut data = Map::new();
    for const_var in matches.opt_strs("c") {
        let mut splitter = const_var.splitn(2, '=');
        data.insert(
            splitter.next().unwrap().to_string(),
            Value::String(splitter.next().unwrap().to_string()),
        );
    }
    for list_var in matches.opt_strs("l") {
        let mut splitter = list_var.splitn(2, '=');
        data.insert(
            splitter.next().unwrap().to_string(),
            Value::Array(
                splitter
                    .next()
                    .unwrap()
                    .to_string()
                    .split('=')
                    .map(|val| Value::String(val.to_string()))
                    .collect::<Vec<_>>(),
            ),
        );
    }
    for host_var in matches.opt_strs("v") {
        let mut splitter = host_var.splitn(2, ':');
        let alias_name: &str = splitter.next().unwrap();
        data.insert(alias_name.to_string(), Value::Null);
    }
    Value::Object(data)
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
    for list_var in matches.opt_strs("l") {
        let mut splitter = list_var.splitn(2, '=');
        data.insert(
            splitter.next().unwrap().to_string(),
            Value::Array(
                splitter
                    .next()
                    .unwrap()
                    .to_string()
                    .split('=')
                    .map(|val| Value::String(val.to_string()))
                    .collect::<Vec<_>>(),
            ),
        );
    }
    let mut conf = ResolvConf::default();
    conf.options.timeout = Duration::from_millis(timeout);
    conf.options.ndots = matches
        .opt_str("ndots")
        .map_or(0, |a| match a.parse::<usize>() {
            Ok(v) => v,
            Err(_) => 0,
        });
    conf.options.attempts = matches
        .opt_str("attempts")
        .map_or(1, |a| match a.parse::<usize>() {
            Ok(v) => v,
            Err(_) => 0,
        });
    conf.options.recurse = matches.opt_present("recurse");
    conf.finalize();
    let mut threads = Vec::new();
    let host_vars = matches.opt_strs("v");
    for host_var in host_vars {
        let conf = conf.clone();
        let debug = debug.clone();
        let mut splitter = host_var.splitn(3, ':');
        let alias_name = splitter.next().unwrap().to_string().clone();
        let host_name = splitter
            .next()
            .unwrap_or_else(|| alias_name.as_str())
            .to_string()
            .clone();
        let reverse_lookup = match splitter.next() {
            Some(reverse) => match reverse.to_lowercase().as_str() {
                "hn" => 1,
                "fqdn" => 2,
                _ => 0,
            },
            None => 0,
        };
        threads.push(thread::spawn(move || {
            let alias_value = resolve(
                debug,
                conf,
                alias_name.as_str(),
                host_name.as_str(),
                reverse_lookup,
            );
            (alias_name, alias_value)
        }));
    }
    for res in threads {
        match res.join() {
            Ok((alias_name, alias_value)) => {
                data.insert(alias_name, alias_value);
            }
            Err(e) => {
                if debug {
                    println!("DEBUG: Join failed: {:?}", e);
                }
            }
        }
    }
    Value::Object(data)
}

fn resolve(
    debug: bool,
    conf: ResolvConf,
    alias_name: &str,
    host_name: &str,
    reverse_lookup: i32,
) -> Value {
    let host = Dname::from_str(host_name.clone()).unwrap();
    match StubResolver::run_with_conf(conf.clone(), move |resolv| lookup_host(&resolv, &host)) {
        Ok(response) => {
            let ip_or_names = response
                .iter()
                .filter(|x| x.is_ipv4())
                .map(|addr| {
                    let conf = conf.clone();
                    let reverse_lookup = reverse_lookup;
                    thread::spawn(move || reverse_resolve(conf, reverse_lookup, addr))
                })
                .collect::<Vec<_>>();
            let mut addrs = Vec::new();
            for res in ip_or_names {
                match res.join() {
                    Ok(ip_or_name) => addrs.push(ip_or_name),
                    Err(_) => (),
                }
            }
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
    }
}

fn reverse_resolve(conf: ResolvConf, reverse_lookup: i32, addr: IpAddr) -> String {
    match reverse_lookup {
        2 => {
            match StubResolver::run_with_conf(conf.clone(), move |resolv| {
                lookup_addr(&resolv, addr)
            }) {
                Ok(fqdn) => match fqdn.iter().next() {
                    Some(fqdn) => fqdn.clone().to_string(),
                    None => addr.clone().to_string(),
                },
                Err(_) => addr.clone().to_string(),
            }
        }
        1 => {
            match StubResolver::run_with_conf(conf.clone(), move |resolv| {
                lookup_addr(&resolv, addr)
            }) {
                Ok(fqdn) => match fqdn.iter().next() {
                    Some(fqdn) => match fqdn.clone().to_string().split('.').next() {
                        Some(hn) => hn.clone().to_string(),
                        None => fqdn.clone().to_string(),
                    },
                    None => addr.clone().to_string(),
                },
                Err(_) => addr.clone().to_string(),
            }
        }
        _ => addr.clone().to_string(),
    }
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

fn eval_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output,
) -> HelperResult {
    let expr = h
        .params()
        .iter()
        .map(|v| v.value().render())
        .collect::<Vec<String>>()
        .join(" ");
    let res = match meval::eval_str(expr)
        .map(|v| v as i64)
        .map(|v| format!("{}", v)) {
        Ok(r) => r,
        Err(e) => return Err(RenderError::with(e)),
    };
    match out.write(&res) {
        Err(e) => Err(RenderError::with(e)),
        Ok(_) => Ok(()),
    }
}

fn replace_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output,
) -> HelperResult {
    let value = match h.param(0) {
        Some(v) => v.value().render(),
        None => return Err(RenderError::new("value param not found")),
    };
    let regex = match Regex::new(
        match h.param(1) {
            Some(v) => v.value().render(),
            None => return Err(RenderError::new("regex param not found")),
        }
        .as_str(),
    ) {
        Ok(r) => r,
        Err(e) => return Err(RenderError::with(e)),
    };
    let replacement = match h.param(2) {
        Some(v) => v.value().render(),
        None => "".to_string(),
    };
    match out.write(
        regex
            .replace(&value, replacement.as_str())
            .to_string()
            .as_str(),
    ) {
        Err(e) => Err(RenderError::with(e)),
        Ok(_) => Ok(()),
    }
}

fn matches_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output,
) -> HelperResult {
    let value = match h.param(0) {
        Some(v) => v.value().render(),
        None => return Err(RenderError::new("value param not found")),
    };
    let regex = match Regex::new(
        match h.param(1) {
            Some(v) => v.value().render(),
            None => return Err(RenderError::new("regex param not found")),
        }
            .as_str(),
    ) {
        Ok(r) => r,
        Err(e) => return Err(RenderError::with(e)),
    };
    match out.write(
        match regex.find(&value) {
            Some(_) => "true",
            None => ""
        }.to_string()
            .as_str(),
    ) {
        Err(e) => Err(RenderError::with(e)),
        Ok(_) => Ok(()),
    }
}

fn replace_all_helper(
    h: &Helper,
    _: &Handlebars,
    _: &Context,
    _: &mut RenderContext,
    out: &mut Output,
) -> HelperResult {
    let value = match h.param(0) {
        Some(v) => v.value().render(),
        None => return Err(RenderError::new("value param not found")),
    };
    let regex = match Regex::new(
        match h.param(1) {
            Some(v) => v.value().render(),
            None => return Err(RenderError::new("regex param not found")),
        }
        .as_str(),
    ) {
        Ok(r) => r,
        Err(e) => return Err(RenderError::with(e)),
    };
    let replacement = match h.param(2) {
        Some(v) => v.value().render(),
        None => "".to_string(),
    };
    match out.write(
        regex
            .replace_all(&value, replacement.as_str())
            .to_string()
            .as_str(),
    ) {
        Err(e) => Err(RenderError::with(e)),
        Ok(_) => Ok(()),
    }
}

fn main() {
    const VERSION: &'static str = env!("CARGO_PKG_VERSION");
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
    if matches.opt_present("V") {
        println!("{}", VERSION);
        return;
    }
    if matches.free.is_empty() {
        print_usage(&program, opts);
        return;
    }
    let debug = matches.opt_present("d");

    let mut handlebars = Handlebars::new();
    handlebars.register_helper("eval", Box::new(eval_helper));
    handlebars.register_helper("replace", Box::new(replace_helper));
    handlebars.register_helper("replace_all", Box::new(replace_all_helper));
    handlebars.register_helper("matches", Box::new(matches_helper));
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
    let time_multiplier = match matches.opt_present("use-millis") {
        true => 1,
        false => 1000,
    };
    let timeout: u64 = match matches.opt_str("t") {
        Some(seconds) => match seconds.parse::<u64>() {
            Ok(seconds) => seconds * time_multiplier,
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
                Ok(seconds) => seconds * time_multiplier,
                Err(_) => panic!("Could not parse supplied interval"),
            },
            None => 1000,
        };
        let mut first = matches.opt_present("f");
        let cmd = matches.opt_str("w").unwrap().clone();
        loop {
            let m = matches.clone();
            let ctx = &match first {
                true => evaluate_empty(&m),
                false => evaluate(&m, timeout, debug),
            };
            first = false;
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
            match handlebars.render_to_write("template", &ctx, &mut io::stdout()) {
                Err(why) => panic!(
                    "couldn't render template {}: {}",
                    output_file,
                    why.description()
                ),
                Ok(_) => (),
            }
        } else {
            render(&handlebars, "template", ctx, &output_file);
        }
    }
}
