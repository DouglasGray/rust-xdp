#![no_std]

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Config {
    pub server_port: u16,
    pub conn_port: u16,
}
