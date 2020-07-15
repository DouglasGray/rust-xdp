#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;

use socket_filter::Config;

program!(0xFFFFFFFE, "GPL");

// User program should update this map with the connection's local port
// and the server's bound port
#[map("config")]
static mut config: HashMap<u32, Config> = HashMap::with_max_entries(1);

#[map("packets")]
static mut packets: PerfMap<()> = PerfMap::with_max_entries(4096);

#[xdp("filter")]
pub extern "C" fn filter(ctx: XdpContext) -> XdpResult {
    let key = 0;

    let (source, dest) = match unsafe { config.get(&key) } {
        Some(cfg) => (cfg.server_port, cfg.conn_port),
        None => return Ok(XdpAction::Pass),
    };

    let t = ctx.transport()?;

    if t.source() != source || t.dest() != dest {
        return Ok(XdpAction::Pass);
    }

    let data = ctx.data()?;

    let map_data = MapData::with_payload(
        (),
        data.offset() as u32,
        (data.len() + data.offset()) as u32,
    );

    unsafe {
        packets.insert(&ctx, &map_data);
    };

    Ok(XdpAction::Pass)
}
