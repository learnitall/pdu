/*
   Copyright (c) 2019 Alex Forster <alex@alexforster.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   SPDX-License-Identifier: Apache-2.0
*/

use core::convert::TryInto;

use crate::{Error, Result};

/// Provides constants representing various EtherTypes supported by this crate
#[allow(non_snake_case)]
pub mod EtherType {
    pub const ARP: u16 = 0x0806;
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const DOT1Q: u16 = 0x8100;
    pub const QINQ: u16 = 0x88A8;
    pub const TEB: u16 = 0x6558;
}

/// Represents an Ethernet header and payload
#[derive(Debug, Copy, Clone)]
pub struct EthernetPdu<'a> {
    buffer: &'a [u8],
    ihl: usize,
}

/// Contains the inner payload of an [`EthernetPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Ethernet<'a> {
    Raw(&'a [u8]),
    Arp(super::ArpPdu<'a>),
    Ipv4(super::Ipv4Pdu<'a>),
    Ipv6(super::Ipv6Pdu<'a>),
}

impl<'a> EthernetPdu<'a> {
    /// Constructs an [`EthernetPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 14 {
            return Err(Error::Truncated);
        }
        if u16::from_be_bytes(buffer[12..14].try_into().unwrap()) < 0x0600 {
            // we don't support 802.3 (LLC) frames
            return Err(Error::Malformed);
        }
        let pos = 12;
        let ethertype = u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap());
        match ethertype {
            EtherType::DOT1Q => Self::dot1q(buffer, pos + 2),
            EtherType::QINQ => Self::qinq(buffer, pos + 2),
            _ => Ok(EthernetPdu { buffer, ihl: 14 }),
        }
    }

    fn dot1q(buffer: &'a [u8], pos: usize) -> Result<Self> {
        // buffer needs the tag + ether len/tag
        if buffer.len() < pos + 4 {
            return Err(Error::Truncated);
        }

        Ok(EthernetPdu { buffer, ihl: pos + 4 })
    }

    fn qinq(buffer: &'a [u8], mut pos: usize) -> Result<Self> {
        // buffer needs to contain tag + dot1q tag
        if buffer.len() < pos + 4 {
            return Err(Error::Truncated);
        }

        pos += 2;
        let ethertype = u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap());
        if ethertype != EtherType::DOT1Q {
            return Err(Error::Malformed);
        }

        Self::dot1q(buffer, pos + 2)
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Consumes this object and returns a reference to the entire underlying buffer that was provided during
    /// construction
    pub fn into_buffer(self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.clone().into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Ethernet<'a>> {
        self.clone().into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Ethernet<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(match self.ethertype() {
            EtherType::ARP => Ethernet::Arp(super::ArpPdu::new(rest)?),
            EtherType::IPV4 => Ethernet::Ipv4(super::Ipv4Pdu::new(rest)?),
            EtherType::IPV6 => Ethernet::Ipv6(super::Ipv6Pdu::new(rest)?),
            _ => Ethernet::Raw(rest),
        })
    }

    pub fn computed_ihl(&'a self) -> usize {
        self.ihl
    }

    pub fn source_address(&'a self) -> [u8; 6] {
        let mut source_address = [0u8; 6];
        source_address.copy_from_slice(&self.buffer[6..12]);
        source_address
    }

    pub fn destination_address(&'a self) -> [u8; 6] {
        let mut destination_address = [0u8; 6];
        destination_address.copy_from_slice(&self.buffer[0..6]);
        destination_address
    }

    pub fn tpid(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[12..=13].try_into().unwrap())
    }

    pub fn ethertype(&'a self) -> u16 {
        match self.tpid() {
            EtherType::DOT1Q => u16::from_be_bytes(self.buffer[16..=17].try_into().unwrap()),
            ethertype => ethertype,
        }
    }

    pub fn computed_ethertype(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[(self.ihl - 2)..self.ihl].try_into().unwrap())
    }

    pub fn vlan(&'a self) -> Option<u16> {
        match self.tpid() {
            EtherType::DOT1Q => Some(u16::from_be_bytes(self.buffer[14..=15].try_into().unwrap()) & 0x0FFF),
            _ => None,
        }
    }

    pub fn vlan_pcp(&'a self) -> Option<u8> {
        match self.tpid() {
            EtherType::DOT1Q => Some((self.buffer[14] & 0xE0) >> 5),
            _ => None,
        }
    }

    pub fn vlan_dei(&'a self) -> Option<bool> {
        match self.tpid() {
            EtherType::DOT1Q => Some(((self.buffer[14] & 0x10) >> 4) > 0),
            _ => None,
        }
    }

    pub fn vlan_tags(&'a self) -> Option<VlanTagIterator<'a>> {
        match self.tpid() {
            EtherType::DOT1Q | EtherType::QINQ => Some(VlanTagIterator { buffer: self.buffer, pos: 12, eol: false }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers to build minimal Ethernet frames as byte vecs.
    // Layout: dst(6) + src(6) + [vlan tags] + ethertype(2) + payload

    // Minimal valid IPv4 header (20 bytes, no payload): version=4, ihl=5,
    // total_length=20, protocol=0 (reserved/raw), src=1.2.3.4, dst=5.6.7.8
    const IPV4_HDR: [u8; 20] = [
        0x45, 0x00, 0x00, 0x14, // version/ihl, dscp/ecn, total_length
        0x00, 0x00, 0x00, 0x00, // identification, flags/fragment_offset
        0x40, 0x00, 0x00, 0x00, // ttl, protocol, checksum
        0x01, 0x02, 0x03, 0x04, // src
        0x05, 0x06, 0x07, 0x08, // dst
    ];

    fn untagged_frame() -> Vec<u8> {
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x08, 0x00, // ethertype: IPv4
        ];
        f.extend_from_slice(&IPV4_HDR);
        f
    }

    fn dot1q_frame(vlan_id: u16) -> Vec<u8> {
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x81, 0x00, // TPID: DOT1Q
        ];
        f.extend_from_slice(&vlan_id.to_be_bytes()); // TCI: PCP=0, DEI=0, VID
        f.extend_from_slice(&[0x08, 0x00]); // inner ethertype: IPv4
        f.extend_from_slice(&IPV4_HDR);
        f
    }

    fn qinq_frame(outer_vid: u16, inner_vid: u16) -> Vec<u8> {
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src
            0x88, 0xa8, // TPID: QINQ
        ];
        f.extend_from_slice(&outer_vid.to_be_bytes()); // outer TCI
        f.extend_from_slice(&[0x81, 0x00]); // inner TPID: DOT1Q
        f.extend_from_slice(&inner_vid.to_be_bytes()); // inner TCI
        f.extend_from_slice(&[0x08, 0x00]); // ethertype: IPv4
        f.extend_from_slice(&IPV4_HDR);
        f
    }

    #[test]
    fn test_untagged() {
        let frame = untagged_frame();
        let pdu = EthernetPdu::new(&frame).unwrap();

        assert_eq!(pdu.computed_ihl(), 14);
        assert_eq!(pdu.tpid(), EtherType::IPV4);
        assert_eq!(pdu.ethertype(), EtherType::IPV4);
        assert_eq!(pdu.computed_ethertype(), EtherType::IPV4);
        assert!(pdu.vlan_tags().is_none());
        assert_eq!(pdu.as_bytes(), &frame[..14]);
        assert!(matches!(pdu.into_inner().unwrap(), Ethernet::Ipv4(_)));
    }

    #[test]
    fn test_dot1q() {
        let frame = dot1q_frame(0x0064); // VLAN 100
        let pdu = EthernetPdu::new(&frame).unwrap();

        assert_eq!(pdu.computed_ihl(), 18);
        assert_eq!(pdu.tpid(), EtherType::DOT1Q);
        assert_eq!(pdu.ethertype(), EtherType::IPV4);
        assert_eq!(pdu.computed_ethertype(), EtherType::IPV4);
        assert_eq!(pdu.vlan(), Some(0x0064));

        let tags: Vec<VlanTag> = pdu.vlan_tags().unwrap().collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].protocol_id, EtherType::DOT1Q);
        assert_eq!(tags[0].id, 0x0064);

        assert_eq!(pdu.as_bytes(), &frame[..18]);
        assert!(matches!(pdu.into_inner().unwrap(), Ethernet::Ipv4(_)));
    }

    #[test]
    fn test_qinq() {
        let frame = qinq_frame(0x000a, 0x0064); // outer VLAN 10, inner VLAN 100
        let pdu = EthernetPdu::new(&frame).unwrap();

        assert_eq!(pdu.computed_ihl(), 22);
        assert_eq!(pdu.tpid(), EtherType::QINQ);
        assert_eq!(pdu.computed_ethertype(), EtherType::IPV4);

        let tags: Vec<VlanTag> = pdu.vlan_tags().unwrap().collect();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].protocol_id, EtherType::QINQ);
        assert_eq!(tags[0].id, 0x000a);
        assert_eq!(tags[1].protocol_id, EtherType::DOT1Q);
        assert_eq!(tags[1].id, 0x0064);

        assert_eq!(pdu.as_bytes(), &frame[..22]);
        // into_inner() dispatches on tpid() not computed_ethertype(), so a QinQ
        // frame with an unrecognised outer TPID (0x88A8) yields Ethernet::Raw
        assert!(matches!(pdu.into_inner().unwrap(), Ethernet::Raw(_)));
    }

    #[test]
    fn test_qinq_payload_offset() {
        // Verify that into_inner() slices from byte 22 onward, not byte 14 or 18
        let frame = qinq_frame(0x000a, 0x0064);
        let pdu = EthernetPdu::new(&frame).unwrap();
        let payload = &frame[22..]; // ethertype(2) already consumed, rest is IPv4 onward
                                    // into_inner slices from computed_ihl which is 22
        assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], payload);
    }

    #[test]
    fn test_truncated_untagged() {
        // 13 bytes - one short of minimum
        let frame = &untagged_frame()[..13];
        assert_eq!(EthernetPdu::new(frame).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn test_truncated_dot1q() {
        // Has DOT1Q TPID but not enough bytes for the tag
        let frame = &dot1q_frame(0x0064)[..15];
        assert_eq!(EthernetPdu::new(frame).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn test_truncated_qinq() {
        // Has QINQ TPID but not enough bytes for both tags
        let frame = &qinq_frame(0x000a, 0x0064)[..17];
        assert_eq!(EthernetPdu::new(frame).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn test_malformed_qinq_no_dot1q() {
        // QINQ outer tag not followed by DOT1Q - should be Malformed
        let mut frame = qinq_frame(0x000a, 0x0064);
        // Overwrite the inner TPID (bytes 16..18) with something that is not DOT1Q
        frame[16] = 0x08;
        frame[17] = 0x00;
        assert_eq!(EthernetPdu::new(&frame).unwrap_err(), Error::Malformed);
    }

    #[test]
    fn test_malformed_llc_frame() {
        // ethertype < 0x0600 signals an 802.3 LLC frame, which is not supported
        let mut frame = untagged_frame();
        frame[12] = 0x05;
        frame[13] = 0xff;
        assert_eq!(EthernetPdu::new(&frame).unwrap_err(), Error::Malformed);
    }
}

/// Represents a VLAN tag
#[derive(Debug, Copy, Clone)]
pub struct VlanTag {
    pub protocol_id: u16,
    pub priority_codepoint: u8,
    pub drop_eligible: bool,
    pub id: u16,
}

#[derive(Debug, Copy, Clone)]
pub struct VlanTagIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    eol: bool,
}

impl<'a> Iterator for VlanTagIterator<'a> {
    type Item = VlanTag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.eol {
            return None;
        }
        let tpid = u16::from_be_bytes(self.buffer[self.pos..self.pos + 2].try_into().unwrap());
        if tpid != EtherType::DOT1Q && tpid != EtherType::QINQ {
            return None;
        }
        if tpid == EtherType::DOT1Q {
            self.eol = true;
        }
        let vlan_tag = VlanTag {
            protocol_id: tpid,
            priority_codepoint: (self.buffer[self.pos + 2] & 0xE0) >> 5,
            drop_eligible: ((self.buffer[self.pos + 2] & 0x10) >> 4) > 0,
            id: u16::from_be_bytes([self.buffer[self.pos + 2] & 0x0F, self.buffer[self.pos + 3]]),
        };
        self.pos += 4;
        Some(vlan_tag)
    }
}
