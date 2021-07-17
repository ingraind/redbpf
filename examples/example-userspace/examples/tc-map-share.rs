/// This example demonstrates how to interact with BPF program loaded by tc
/// utility. A BPF program that is loaded by tc also can get values from or set
/// values to BPF maps. And tc pins maps to specific paths. Maps are pinned to
/// `/sys/fs/bpf/tc/globals/<map symbol name>`. In userspace, we can load pinned
/// BPF maps using `Map::from_pin_file` function. By this method, our userspace
/// programs are able to interact with BPF programs loaded by tc utility.
///
/// Usage: sudo -Es (which cargo) run --example tc-map-share 8080 8081 8082
///
/// And try running `nc localhost 8080`. nc will not succeed to connect to 8080
/// because tc BPF program blocks packets of which port number is 8080
use redbpf::{HashMap, Map};
use std::{
    env, fs,
    process::{self, Command},
    time::Duration,
};
use tokio::{select, signal::ctrl_c, time::sleep};
use tracing::{debug, error, Level};
use tracing_subscriber::FmtSubscriber;

const TC_BLOCKED_PACKETS_MAP: &str = "/sys/fs/bpf/tc/globals/blocked_packets";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::getuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }

    let ports = env::args()
        .skip(1)
        .map(|s| {
            s.parse::<u16>()
                .expect(format!("Unable to convert {} to u16", s).as_str())
        })
        .collect::<Vec<u16>>();
    if ports.is_empty() {
        error!("Specify port numbers to block");
        process::exit(1);
    }

    let bpf_elf = concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/tc-map-share/tc-map-share.elf"
    );
    // remove .BTF.ext and .eh_frame in order to remove .text
    // remove .text section because tc filter does not work if .text exists
    // remove .BTF section because it contains invalid names of BTF types
    // (currently kernel only allows valid symbol names of C)
    for sec in &[".BTF.ext", ".eh_frame", ".text", ".BTF"] {
        if !Command::new("llvm-strip-12")
            .arg("--no-strip-all")
            .arg("--remove-section")
            .arg(sec)
            .arg(&bpf_elf)
            .status()
            .expect("error on running command llvm-strip-12")
            .success()
        {
            error!("error on removing section `{}' using llvm-strip-12", sec);
            return;
        }
    }
    let new_clsact = Command::new("tc")
        .args("qdisc add dev lo clsact".split(" "))
        .status()
        .expect("error on tc qdisc add")
        .success();

    debug!("Attaching tc BPF program to `lo' interface as direct action");
    Command::new("tc")
        .args("filter add dev lo ingress bpf direct-action".split(" "))
        .arg("object-file")
        .arg(bpf_elf)
        .args("section tc_action/block_ports".split(" "))
        .status()
        .expect("error on tc filter add");

    // Load map from pinned file that is just created by tc
    let map = Map::from_pin_file(TC_BLOCKED_PACKETS_MAP).expect("error on Map::from_pin_file");
    let blocked_packets = HashMap::<u16, u64>::new(&map).expect("error on HashMap::new");

    // Set port numbers to block
    // Then port numbers are read by tc BPF program and it will block packets
    // of which port numbers are found at the `HashMap`.
    for port in ports {
        blocked_packets.set(port, 0);
    }

    println!("Hit Ctrl-C to quit");
    println!("port => blocked packet count");
    loop {
        select! {
            _ = sleep(Duration::from_secs(1)) => {}
            _ = ctrl_c() => break

        }
        for (port, blocked_cnt) in blocked_packets.iter() {
            println!("{} => {}", port, blocked_cnt);
        }
    }

    if new_clsact {
        let _ = Command::new("tc")
            .args("qdisc del dev lo clsact".split(" "))
            .status();
    } else {
        let _ = Command::new("tc")
            .args("filter del dev lo ingress protocol all pref 49152 bpf direct-action".split(" "))
            .arg("object-file")
            .arg(bpf_elf)
            .args("section tc_action/block_ports".split(" "))
            .status();
    }

    let _ = fs::remove_file(TC_BLOCKED_PACKETS_MAP);
}
