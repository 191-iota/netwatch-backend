use std::io;

use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::datalink::interfaces;
use pnet::packet::ethernet::EthernetPacket;

fn main() -> Result<(), io::Error> {
    let interfaces = interfaces();

    let default_interfaces = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    let found_interface = default_interfaces.unwrap();

    let ch = pnet::datalink::channel(found_interface, Config::default())?;

    let mut rx = match ch {
        Channel::Ethernet(_, rx) => rx,
        _ => panic!("Not an ethernet channel"),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let wrapped_packet = EthernetPacket::new(packet);

                println!("got packet: {} bytes", packet.len());
                if let Some(p) = wrapped_packet {
                    println!(
                        "packet source: {} -- packet dest: {}",
                        p.get_source(),
                        p.get_destination()
                    );
                }
            }
            Err(e) => eprintln!("error: {}", e),
        }
    }
}
