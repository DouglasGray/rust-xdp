### Socket filter

Passes packets with a payload from a specified TCP/UDP connection to userspace.

The XDP program itself is located at ```src/bin/kern.rs```. It merely checks whether incoming packets have the 
required source port and destination port, and if so, forwards the payload to userspace. The userspace program needs 
to let the XDP program know what the right source/destination ports to filter on are. This can be done by accessing 
the XDP program's ```config``` map from the program and setting an instance of ```src/lib/Config``` at key ```0```.

An example can be found at ```src/bin/user.rs``` where a TCP server sends the time every second.  To run it first 
make sure you have ```cargo-bpf``` installed.  Then, in the ```rust-xdp/socket-filter``` directory, run:

    cargo bpf build filter
    sudo env PATH=$PATH cargo run --bin example

Press ```ctrl+c``` to exit.
