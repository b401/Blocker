use binder::{config,create,lists};
use std::error;
use std::process::Command;

fn main() -> Result<(),Box<dyn error::Error>> {
	let yaml_settings = "/etc/blocker/config.yml".to_string();

	// Load settings from config.yml
	let settings: Option<config::Blocker> = match config::Blocker::from_file(yaml_settings) {
		Ok(settings) => Some(settings),
		Err(e) => {
			println!("{}",e);
			None
		}
	};

	let (mut blocklist,named_path,path,sinkhole,sinkhole6,onlinelists) = match settings {
		Some(s) => (
			s.blocklist.unwrap_or_default(),
			s.named_path,
			s.path,
			s.sinkhole,
			s.sinkhole6,
			s.onlinelists),
		None => {
			panic!("No settings found?!");
		}
	};

	if let Some(lists) = onlinelists {
		println!("Lists: {:?}",&lists);
		let mut func_online = lists::Lists::new(lists);
		let entries = func_online.get_entries();
		if let Ok(mut ii) = func_online.check_if_url(entries) {
			blocklist.append(&mut ii);
		};
	};

	// set default settings for zonefiles
	let mut zone = create::Zone::new(
		named_path,
		path,
		sinkhole,
		sinkhole6,
	)?;

	// create blocker zonefile
	zone.create_zonefile()?;

	// sort and remove duplicates
	blocklist.sort();
	blocklist.dedup();
	// iterate over blocklists
	for i in blocklist {
		zone.zone = i;
		zone.zone_declaration()?;
	};
	
	// check bind9 config && restart bind9
	Command::new("systemctl")
		.arg("reload")
		.arg("bind9")
		.output()
		.expect("Failed to reload bind9");


	Ok(())

}
