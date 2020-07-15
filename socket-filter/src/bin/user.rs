use chrono::offset::Utc;
use chrono::DateTime;
use clap::{App, Arg};
use futures::future::join_all;
use redbpf::load::{Loaded, Loader};
use redbpf::xdp;
use redbpf::xdp::MapData;
use redbpf::HashMap;
use std::net::{Shutdown, SocketAddr};
use std::time::SystemTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::stream::StreamExt;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::oneshot;
use tokio::time::{self, Duration, Instant};
use tokio::{join, select};

use socket_filter::Config;

async fn close_and_drain_receiver<T>(mut r: Receiver<T>) {
    r.close();
    let mut r = r.fuse();
    while let Some(_) = r.next().await {}
}

async fn ticker(
    mut send_to: Sender<DateTime<Utc>>,
    interval: Duration,
    mut shutdown_signal: Receiver<()>,
) {
    let mut delay = time::delay_for(interval);

    loop {
        select! (
            _ = &mut delay => {
                if let Err(_) = send_to.send(SystemTime::now().into()).await {
                    break;
                }
                delay.reset(Instant::now() + interval);
            },
            _ = shutdown_signal.next() => {
                break;
            }
        )
    }

    drop(send_to);
    close_and_drain_receiver(shutdown_signal).await;
}

async fn handle_connection(mut conn: TcpStream, mut shutdown_signal: Receiver<()>) {
    let (mut stop_ticker_w, stop_ticker_r) = mpsc::channel(1);
    let (ticker_w, mut ticker_r) = mpsc::channel(1);

    let ticker_handle = tokio::spawn(async move {
        ticker(ticker_w, Duration::from_secs(1), stop_ticker_r).await;
    });

    loop {
        select! (
            time = ticker_r.next() => match time {
                Some(time) => {
                    if let Err(_) = conn.write_all(time.to_string().as_bytes()).await {
                        break;
                    }
                    if let Err(_) = conn.flush().await {
                        break;
                    };
                },
                None => {
                    break;
                }
            },
            _ = shutdown_signal.next() => {
                break;
            }
        )
    }

    let _ = stop_ticker_w.send(()).await;

    if let Err(e) = conn.shutdown(Shutdown::Both) {
        println!("Error occurred while closing client connection: {:?}", e)
    }

    let _ = join!(
        ticker_handle,
        close_and_drain_receiver(ticker_r),
        close_and_drain_receiver(shutdown_signal)
    );
}

async fn start_server(
    addr: SocketAddr,
    connect_event: oneshot::Sender<()>,
    mut shutdown_signal: Receiver<()>,
) {
    let mut listener = TcpListener::bind(addr).await.unwrap();
    let mut incoming = listener.incoming();

    let mut conn_shutdown_ws = Vec::new();
    let mut conn_tasks = Vec::new();

    println!("Server running on {:?}", addr);

    connect_event.send(()).unwrap();

    loop {
        select!(
            conn_attempt = incoming.next() => match conn_attempt {
                Some(conn_attempt) => match conn_attempt {
                     Ok(socket) => {
                         let (shutdown_w, shutdown_r) = mpsc::channel(1);

                         let conn_task = tokio::spawn(async move {
                             handle_connection(socket, shutdown_r).await;
                         });

                         conn_shutdown_ws.push(shutdown_w);
                         conn_tasks.push(conn_task);
                    }
                    Err(err) => {
                        println!("Connection accept error: {:?}", err);
                    }
                },
                None => {
                    break;
                }
            },
            _ = shutdown_signal.next() => {
                break;
            }
        )
    }

    for w in conn_shutdown_ws.iter_mut() {
        let _ = w.send(()).await;
    }

    let _ = join!(
        close_and_drain_receiver(shutdown_signal),
        join_all(conn_tasks)
    );

    println!("Stopping server");
}

async fn process_xdp_packets(mut loaded_prog: Loaded, mut shutdown_signal: Receiver<()>) {
    loop {
        select!(
            event = loaded_prog.events.next() => match event {
                Some((map_name, events)) => {
                    if map_name == "packets" {
                        for event in events {
                            let map_data = unsafe { &*(event.as_ptr() as *const MapData<()>) };
                            let payload = String::from_utf8_lossy(map_data.payload());
                            println!("Payload: {}", payload);
                        }
                    }
                },
                None => {
                    break;
                }
            },
            _ = shutdown_signal.next() => {
                break;
            }
        )
    }

    close_and_drain_receiver(shutdown_signal).await;

    println!("Unloading XDP program");
}

async fn drain_tcp_stream(s: &mut TcpStream) {
    let mut buffer = [0; 10];

    while let Ok(n) = s.read(&mut buffer[..]).await {
        if n == 0 {
            break;
        }
    }
}

#[tokio::main]
async fn main() {
    let matches = App::new("XDP payload filter")
        .version("1.0")
        .about("Simple example filtering packets with payloads on the loopback interface")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Path to the XDP filter program ELF file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("INT")
                .help("Port the TCP server should attempt to bind to")
                .takes_value(true),
        )
        .get_matches();

    let interface = "lo";

    let file = matches
        .value_of("file")
        .unwrap_or("target/bpf/programs/filter/filter.elf");

    let server_port: u16 = matches
        .value_of("port")
        .unwrap_or("8080")
        .parse()
        .expect("Failed to parse 'port' argument");

    // Load the XDP program
    let mut xdp_prog: Loaded = Loader::load_file(file).expect("Error loading XDP program file");

    for prog in xdp_prog.xdps_mut() {
        prog.attach_xdp(&interface, xdp::Flags::default())
            .expect("Error attaching XDP program");
    }

    let config_map: HashMap<u32, Config> = HashMap::new(
        xdp_prog
            .map("config")
            .expect("Could not locate the 'config' map within the XDP program"),
    )
    .expect("Failed to build the XDP map, likely due to mismatching key or value sizes");

    // Start the TCP server
    let (connect_event_w, connect_event_r) = oneshot::channel();
    let (mut shutdown_server_w, shutdown_server_r) = mpsc::channel(1);

    let addr = SocketAddr::from(([127, 0, 0, 1], server_port));
    let server_handle = tokio::spawn(async move {
        start_server(addr, connect_event_w, shutdown_server_r).await;
    });

    if let Err(e) = connect_event_r.await {
        println!("Error while waiting for server to bind: {:?}", e);

        let _ = shutdown_server_w.send(()).await;
        if let Err(e) = server_handle.await {
            println!("Error during server shutdown: {:?}", e)
        };

        return;
    }

    // Connect to the server
    let mut tcp_stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(err) => {
            println!("Error connecting to server: {:?}", err);

            let _ = shutdown_server_w.send(()).await;
            if let Err(e) = server_handle.await {
                println!("Error during server shutdown: {:?}", e)
            };

            return;
        }
    };

    // Get the connection's port and update the XDP map
    let conn_port = tcp_stream.local_addr().unwrap().port();

    let config = Config {
        server_port,
        conn_port,
    };

    println!("XDP filter config: {:?}", config);

    config_map.set(0u32, config);

    let (mut shutdown_xdp_w, shutdown_xdp_r) = mpsc::channel(1);

    let xdp_prog_handle =
        tokio::spawn(async move { process_xdp_packets(xdp_prog, shutdown_xdp_r).await });

    // Also need to drain the actual TCP stream
    tokio::spawn(async move {
        drain_tcp_stream(&mut tcp_stream).await;
    });

    // Wait on interrupt and then shut down
    if let Err(e) = signal::ctrl_c().await {
        println!("Error while waiting on exit signal: {:?}", e);
    }

    println!("Close signal received, shutting down");

    let _ = shutdown_xdp_w.send(()).await;
    let _ = shutdown_server_w.send(()).await;

    let _ = join!(server_handle, xdp_prog_handle);
}
