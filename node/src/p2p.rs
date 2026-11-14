//! P2P messages (spec 9): frames `length (4) ‖ type (1) ‖ content` over TCP, no encryption.
//! The spec names the eight messages; their contents are defined here and in `node/PROTOCOL.md`.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::consensus::{Hash, Header, OutPoint, Reader, UTXO_ENTRY_LEN, UtxoEntry, parse_utxo_entry, utxo_entry};

pub const PROTOCOL_VERSION: u32 = 1;
/// Largest content accepted. A block is at most about 0.65 MB; headers replies are 160 kB.
pub const MAX_MESSAGE: usize = 1 << 21;
pub const MAX_HEADERS: usize = 2_000;
pub const MAX_INV: usize = 1_000;
pub const MAX_PEERS_MSG: usize = 100;

pub const INV_TX: u8 = 1;
pub const INV_BLOCK: u8 = 2;
pub const GET_HEADERS: u8 = 3;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Hello {
        version: u32,
        chain_id: Hash,
        height: u32,
        tip: Hash,
        port: u16,
        nonce: u64,
    },
    /// An empty list asks the peer for addresses.
    Peers(Vec<SocketAddr>),
    Inv {
        kind: u8,
        hashes: Vec<Hash>,
    },
    /// kind 1 or 2: send these transactions or blocks; kind 3: send headers after this locator.
    Get {
        kind: u8,
        hashes: Vec<Hash>,
    },
    Tx(Vec<u8>),
    Block(Vec<u8>),
    Headers(Vec<Header>),
    SnapRequest {
        height: u32,
        chunk: u32,
    },
    SnapChunk {
        height: u32,
        chunk: u32,
        total: u32,
        entries: Vec<(OutPoint, UtxoEntry)>,
        proof: Vec<Hash>,
    },
    SnapMissing {
        height: u32,
        chunk: u32,
    },
}

impl Msg {
    pub fn kind(&self) -> u8 {
        match self {
            Msg::Hello { .. } => 0,
            Msg::Peers(_) => 1,
            Msg::Inv { .. } => 2,
            Msg::Get { .. } => 3,
            Msg::Tx(_) => 4,
            Msg::Block(_) => 5,
            Msg::Headers(_) => 6,
            Msg::SnapRequest { .. } | Msg::SnapChunk { .. } | Msg::SnapMissing { .. } => 7,
        }
    }

    pub fn name(&self) -> &'static str {
        ["hello", "peers", "inv", "get", "tx", "block", "headers", "snap"][self.kind() as usize]
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut c = Vec::new();
        match self {
            Msg::Hello { version, chain_id, height, tip, port, nonce } => {
                c.extend(version.to_le_bytes());
                c.extend(chain_id);
                c.extend(height.to_le_bytes());
                c.extend(tip);
                c.extend(port.to_le_bytes());
                c.extend(nonce.to_le_bytes());
            }
            Msg::Peers(addrs) => {
                c.extend((addrs.len() as u16).to_le_bytes());
                for a in addrs {
                    let ip = match a.ip() {
                        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                        IpAddr::V6(v6) => v6,
                    };
                    c.extend(ip.octets());
                    c.extend(a.port().to_le_bytes());
                }
            }
            Msg::Inv { kind, hashes } | Msg::Get { kind, hashes } => {
                c.push(*kind);
                c.extend((hashes.len() as u16).to_le_bytes());
                for h in hashes {
                    c.extend(h);
                }
            }
            Msg::Tx(raw) | Msg::Block(raw) => c.extend(raw),
            Msg::Headers(hs) => {
                c.extend((hs.len() as u16).to_le_bytes());
                for h in hs {
                    c.extend(h.serialize());
                }
            }
            Msg::SnapRequest { height, chunk } => {
                c.push(0);
                c.extend(height.to_le_bytes());
                c.extend(chunk.to_le_bytes());
            }
            Msg::SnapChunk { height, chunk, total, entries, proof } => {
                c.push(1);
                c.extend(height.to_le_bytes());
                c.extend(chunk.to_le_bytes());
                c.extend(total.to_le_bytes());
                c.extend((entries.len() as u16).to_le_bytes());
                for (k, e) in entries {
                    c.extend(utxo_entry(k, e));
                }
                c.push(proof.len() as u8);
                for h in proof {
                    c.extend(h);
                }
            }
            Msg::SnapMissing { height, chunk } => {
                c.push(2);
                c.extend(height.to_le_bytes());
                c.extend(chunk.to_le_bytes());
            }
        }
        let mut f = (c.len() as u32).to_le_bytes().to_vec();
        f.push(self.kind());
        f.extend(c);
        f
    }

    pub fn decode(kind: u8, c: &[u8]) -> Option<Msg> {
        let mut r = Reader::new(c);
        let m = match kind {
            0 => Msg::Hello {
                version: r.u32().ok()?,
                chain_id: r.arr().ok()?,
                height: r.u32().ok()?,
                tip: r.arr().ok()?,
                port: r.u16().ok()?,
                nonce: r.u64().ok()?,
            },
            1 => {
                let n = r.u16().ok()? as usize;
                if n > MAX_PEERS_MSG {
                    return None;
                }
                let mut v = Vec::with_capacity(n);
                for _ in 0..n {
                    let ip = Ipv6Addr::from(r.arr::<16>().ok()?);
                    let port = r.u16().ok()?;
                    let ip = ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4);
                    v.push(SocketAddr::new(ip, port));
                }
                Msg::Peers(v)
            }
            2 | 3 => {
                let k = r.u8().ok()?;
                let n = r.u16().ok()? as usize;
                if n > MAX_INV.max(64) {
                    return None;
                }
                let hashes = (0..n).map(|_| r.arr().ok()).collect::<Option<Vec<Hash>>>()?;
                if kind == 2 { Msg::Inv { kind: k, hashes } } else { Msg::Get { kind: k, hashes } }
            }
            4 => {
                r.o = c.len();
                Msg::Tx(c.to_vec())
            }
            5 => {
                r.o = c.len();
                Msg::Block(c.to_vec())
            }
            6 => {
                let n = r.u16().ok()? as usize;
                if n > MAX_HEADERS {
                    return None;
                }
                Msg::Headers((0..n).map(|_| r.take(80).ok().map(Header::parse)).collect::<Option<_>>()?)
            }
            7 => match r.u8().ok()? {
                0 => Msg::SnapRequest { height: r.u32().ok()?, chunk: r.u32().ok()? },
                1 => {
                    let (height, chunk, total) = (r.u32().ok()?, r.u32().ok()?, r.u32().ok()?);
                    let n = r.u16().ok()? as usize;
                    let entries = (0..n).map(|_| r.take(UTXO_ENTRY_LEN).ok().and_then(parse_utxo_entry)).collect::<Option<_>>()?;
                    let m = r.u8().ok()? as usize;
                    let proof = (0..m).map(|_| r.arr().ok()).collect::<Option<_>>()?;
                    Msg::SnapChunk { height, chunk, total, entries, proof }
                }
                2 => Msg::SnapMissing { height: r.u32().ok()?, chunk: r.u32().ok()? },
                _ => return None,
            },
            _ => return None,
        };
        r.done().then_some(m)
    }
}

pub fn read_msg(s: &mut impl Read) -> std::io::Result<Option<Msg>> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head)?;
    let n = u32::from_le_bytes(head[..4].try_into().unwrap()) as usize;
    if n > MAX_MESSAGE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
    }
    let mut c = vec![0u8; n];
    s.read_exact(&mut c)?;
    Ok(Msg::decode(head[4], &c))
}

pub fn write_msg(s: &mut impl Write, m: &Msg) -> std::io::Result<()> {
    s.write_all(&m.encode())
}

/// The /16 (IPv4) or /32 (IPv6) network an address belongs to, for picking outbound peers.
pub fn netgroup(a: &SocketAddr) -> Vec<u8> {
    match a.ip() {
        IpAddr::V4(v) => v.octets()[..2].to_vec(),
        IpAddr::V6(v) => v.to_ipv4_mapped().map_or_else(|| v.octets()[..4].to_vec(), |x| x.octets()[..2].to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let e = (OutPoint { txid: [7; 32], index: 2 }, UtxoEntry { amount: 5, addr: [9; 32], height: 3, coinbase: true });
        let msgs = vec![
            Msg::Hello { version: 1, chain_id: [1; 32], height: 9, tip: [2; 32], port: 8333, nonce: 77 },
            Msg::Peers(vec!["1.2.3.4:5".parse().unwrap(), "[2001:db8::1]:7".parse().unwrap()]),
            Msg::Peers(vec![]),
            Msg::Inv { kind: INV_BLOCK, hashes: vec![[3; 32]] },
            Msg::Get { kind: GET_HEADERS, hashes: vec![[3; 32], [4; 32]] },
            Msg::Tx(vec![1, 2, 3]),
            Msg::Block(vec![4, 5]),
            Msg::Headers(vec![Header { version: 1, prev: [1; 32], merkle: [2; 32], time32: 3, bits: 4, nonce: 5 }]),
            Msg::SnapRequest { height: 1440, chunk: 0 },
            Msg::SnapChunk { height: 1440, chunk: 1, total: 5000, entries: vec![e], proof: vec![[5; 32]] },
            Msg::SnapMissing { height: 1, chunk: 2 },
        ];
        for m in msgs {
            let f = m.encode();
            assert_eq!(read_msg(&mut &f[..]).unwrap(), Some(m));
        }
    }
}
