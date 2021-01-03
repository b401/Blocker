#[macro_use]
extern crate lazy_static;

pub mod config {
    use serde::Deserialize;
    use std::path::Path;

    #[derive(Debug, Deserialize)]
    pub struct Blocklist {
        pub domain: Option<String>,
        pub file: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Blocker {
        pub blocklist: Option<Vec<String>>,
        pub sinkhole: String,
        pub sinkhole6: String,
        pub path: String,
        pub reset: bool,
        pub named_path: String,
        pub onlinelists: Option<Vec<String>>,
    }

    impl Blocker {
        pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Blocker, std::io::Error> {
            let path = path.as_ref();
            let config_content = match std::fs::File::open(path) {
                Err(e) => return Err(e),
                Ok(file) => file,
            };
            Ok(serde_yaml::from_reader(config_content).expect("error"))
        }
    }
}

pub mod lists {
    use curl::easy::Easy;
    use regex::{Regex, RegexBuilder};
    use url::ParseError;
    use url::Url;

    #[derive(Debug)]
    pub struct Lists {
        entries: Vec<String>,
        curl_handler: Easy,
    }

    impl Lists {
        pub fn new(entries: Vec<String>) -> Lists {
            Lists {
                entries,
                curl_handler: Easy::new(),
            }
        }

        pub fn check_if_url(&self, res: Vec<u8>) -> Result<Vec<String>, ParseError> {
            lazy_static! {
                static ref RE: Regex = RegexBuilder::new(
                    r"(^[a-zA-Z][^#]*)|^0\.0\.0\.0 ([^#]|[^\n]*)$|^127\.0\.0\.1 ([^#]|[^\n]*)$"
                )
                .multi_line(true)
                .build()
                .unwrap();
            }

            let base = String::from_utf8(res.to_vec()).unwrap();
            let x = base.lines();
            let mut hosts: Vec<String> = Vec::new();
            for i in x {
                for ii in RE.captures_iter(i) {
                    // check groups
                    for c in 0..3 {
						if let Ok(h) = Url::parse(&format!(
                            "https://{}",
                            ii.get(c).map_or("", |m| m.as_str())
						)) {hosts.push(h.domain().unwrap().to_string()) }
                    };
                }
            }

            Ok(hosts)
        }

        pub fn get_entries(&mut self) -> Vec<u8> {
            let mut dst = Vec::new();
            for i in &self.entries {
                self.curl_handler.url(&i).unwrap();

                let mut transfer = self.curl_handler.transfer();
                transfer
                    .write_function(|data| {
                        dst.extend_from_slice(data);
                        Ok(data.len())
                    })
                    .unwrap();
                transfer.perform().unwrap();
            }

            dst
        }
    }
}

pub mod create {
    use std::error;
    use std::fs::{create_dir_all, OpenOptions, remove_file};
    use std::io::Write;
    use std::path::Path;

    #[derive(Debug)]
    pub struct Zone {
        named_path: String,
        sinkhole: String,
        sinkhole6: String,
        path: String,
        pub zone: String,
        zonetype: String,
    }

    impl Zone {
        pub fn new(
            named_path: String,
            path: String,
            sinkhole: String,
            sinkhole6: String,
        ) -> Result<Zone, Box<dyn error::Error>> {
            Ok(Zone {
                named_path,
                path,
                zone: String::new(),
                sinkhole,
                sinkhole6,
                zonetype: "master".to_string(),
            })
        }
        // check if path exist and create if not
        fn _check_blockpath(&self) -> std::io::Result<()> {
            create_dir_all(&self.path)?;
			if Path::new(&self.named_path).exists() {
				remove_file(&self.named_path)?;
			};
            Ok(())
        }

        fn _zone_declaration(&self) -> String {
            format! {"zone \"{}\"{{\n\ttype {};\n\tfile \"{}blocker.zone\";\n\tcheck-names ignore;\n}};\n\n",&self.zone,self.zonetype,self.path}
        }

        // Write zone declaration in named.conf.blocklist
        pub fn zone_declaration(&mut self) -> std::io::Result<()> {
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .append(true)
                .open(&self.named_path)?;

            f.write_all(self._zone_declaration().as_bytes())?;
            Ok(())
        }

        // zonefile for each domain
        fn _zone_file(&self) -> String {
            let mut zone = "$TTL 604800\n@ IN SOA localhost. admin.localhost. (\n\t1\n\t3H\n\t15M\n\t1W\n\t1D\n);\n\n".to_string();

            zone.push_str("\tIN\tNS\tlocalhost.\n");

            for i in &["A", "TXT"] {
                zone.push_str(&format!("\tIN {} {}\n", i, self.sinkhole));
            }

            zone.push_str(
                // TODO: Add ipv6 sinkhole option
                &format!("\tIN AAAA {}\n",self.sinkhole6)
            );

            zone
        }

        pub fn create_zonefile(&mut self) -> std::io::Result<()> {
            match self._check_blockpath() {
                Ok(_) => {
                    if !Path::new(&format!("{}/blocker.zone", &self.path)).exists() {
                        let mut f = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(format!("{}/blocker.zone", &self.path))?;
                        f.write_all(self._zone_file().as_bytes())?;
                    };
                    Ok(())
                }
                Err(e) => {
                    println!("{}", e);
                    Err(e)
                }
            }
        }
    }
}
