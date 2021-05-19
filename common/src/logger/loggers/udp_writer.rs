// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::{io, net};

pub struct UdpWriter {
    destination: net::SocketAddr,
    socket: std::net::UdpSocket,
    buf: Vec<u8>,
}

impl UdpWriter {
    pub fn new(destination_host_port: String) -> Self {
        let socket = net::UdpSocket::bind("0.0.0.0:0").expect("failed to bind host socket");
        let destination = destination_host_port
            .parse()
            .expect("failed parsing destination_host_port");

        Self {
            destination,
            socket,
            buf: Vec::with_capacity(65507), /* Max UDP packet size (65,535 − 8 byte UDP header −
                                             * 20 byte IP header). */
        }
    }
}

impl io::Write for UdpWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Don't send packets that are too big since that's guaranteed to fail.
        // The field size sets a theoretical limit of 65,535 bytes (8 byte header +
        // 65,527 bytes of data) for a UDP datagram. However the actual limit
        // for the data length, which is imposed by the underlying
        // IPv4 protocol, is 65,507 bytes (65,535 − 8 byte UDP header − 20 byte IP
        // header).
        if self.buf.len() > 65507 {
            self.buf.clear();
            return Ok(());
        }

        let result = self.socket.send_to(&self.buf, self.destination);
        self.buf.clear();
        result.map(|_| ())
    }
}
