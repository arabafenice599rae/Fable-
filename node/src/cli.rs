//! A small command-line parser shared by `fable` and `fable-tools`: positional words, `--name value`
//! (or `--name=value`) options, and the flags listed in `FLAGS`.

use std::result::Result;

/// Options without a value; every other `--name` takes the next argument (or `--name=value`).
pub const FLAGS: &[&str] = &["verbose", "no-sigs", "snapshot-sync", "dry-run", "help"];

pub struct Args {
    pub pos: Vec<String>,
    pub opts: Vec<(String, String)>,
}

impl Args {
    pub fn parse(it: impl Iterator<Item = String>) -> Result<Args, String> {
        let (mut pos, mut opts) = (vec![], vec![]);
        let mut it = it.peekable();
        while let Some(a) = it.next() {
            let name = match a.as_str() {
                "-v" => "verbose".to_string(),
                "-h" => "help".to_string(),
                _ => match a.strip_prefix("--") {
                    Some(n) => n.to_string(),
                    None => {
                        pos.push(a);
                        continue;
                    }
                },
            };
            if let Some((n, v)) = name.split_once('=') {
                opts.push((n.to_string(), v.to_string()));
            } else if FLAGS.contains(&name.as_str()) {
                opts.push((name, String::new()));
            } else {
                let v = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                opts.push((name, v));
            }
        }
        Ok(Args { pos, opts })
    }

    /// Refuse options the command does not know.
    pub fn allow(&self, known: &[&str]) -> Result<(), String> {
        match self.opts.iter().find(|(n, _)| !known.contains(&n.as_str()) && !FLAGS.contains(&n.as_str())) {
            Some((n, _)) => Err(format!("unknown option --{n} (see --help)")),
            None => Ok(()),
        }
    }

    pub fn get(&self, name: &str) -> Option<String> {
        self.opts.iter().rev().find(|(n, _)| n == name).map(|(_, v)| v.clone())
    }

    pub fn all(&self, name: &str) -> Vec<String> {
        self.opts.iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
    }

    pub fn flag(&self, name: &str) -> bool {
        self.opts.iter().any(|(n, _)| n == name)
    }

    pub fn num<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        self.get(name).map_or(Ok(default), |v| v.parse().map_err(|_| format!("--{name}: not a number: {v}")))
    }

    pub fn parsed<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, String> {
        self.get(name).map(|v| v.parse().map_err(|_| format!("--{name}: cannot read {v}"))).transpose()
    }

    pub fn words(&self) -> Result<String, String> {
        self.get("words").or_else(|| std::env::var("FABLE_WORDS").ok()).ok_or_else(|| "--words (or FABLE_WORDS) is needed".into())
    }

    pub fn rpc(&self) -> String {
        self.get("rpc").unwrap_or_else(|| "127.0.0.1:17172".into())
    }
}
