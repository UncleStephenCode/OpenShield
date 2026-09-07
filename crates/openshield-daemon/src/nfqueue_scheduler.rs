//! Bounded scheduling hints for pending OUTPUT packets, not authorization.
//!
//! Users rotate first, then their flows. A process that creates many endpoint
//! tuples cannot obtain extra turns ahead of another socket UID. These keys
//! never identify a process or replace packet parsing / owner attribution.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Instant;

use anyhow::{Result, ensure};
use openshield_core::TransportProtocol;

use super::{MAX_PACKET_BATCH_SIZE, QueuedPacketWork};

const MAX_PENDING_PACKETS: usize = 128;
const FLOW_QUANTUM: usize = 4;

#[derive(Debug)]
pub(super) struct PendingPacket {
    pub work: QueuedPacketWork,
    pub received: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserKey {
    SocketUid(u32),
    Unparsed,
}

#[derive(Debug, Eq, PartialEq)]
enum FlowKey {
    Network {
        protocol: TransportProtocol,
        source: IpAddr,
        destination: IpAddr,
        source_port: Option<u16>,
        destination_port: Option<u16>,
    },
    Unparsed(u32),
}

impl FlowKey {
    fn for_packet(work: &QueuedPacketWork) -> (UserKey, Self) {
        work.packet.as_ref().map_or_else(
            |_| (UserKey::Unparsed, Self::Unparsed(work.packet_id)),
            |packet| {
                let connection = &packet.connection;
                (
                    UserKey::SocketUid(connection.socket_uid),
                    Self::Network {
                        protocol: connection.protocol,
                        source: connection.source_address,
                        destination: connection.destination_address,
                        source_port: connection.source_port,
                        destination_port: connection.destination_port,
                    },
                )
            },
        )
    }
}

#[derive(Debug)]
struct FlowQueue {
    key: FlowKey,
    packets: VecDeque<PendingPacket>,
}

#[derive(Debug)]
struct UserQueue {
    key: UserKey,
    flows: VecDeque<FlowQueue>,
}

#[derive(Debug, Default)]
pub(super) struct FairQueue {
    users: VecDeque<UserQueue>,
    pending: usize,
}

impl FairQueue {
    pub(super) fn len(&self) -> usize {
        self.pending
    }

    /// A failed insertion consumes `packet` without altering this queue. The
    /// caller must preserve its packet ID and issue a fail-closed verdict (or
    /// close the owning NFQUEUE socket), never silently abandon kernel work.
    pub(super) fn push(&mut self, packet: PendingPacket) -> Result<()> {
        ensure!(
            self.pending < MAX_PENDING_PACKETS,
            "pending application packet scheduler exceeds its fixed bound"
        );
        let (user_key, flow_key) = FlowKey::for_packet(&packet.work);
        if let Some(user) = self.users.iter_mut().find(|user| user.key == user_key) {
            if let Some(flow) = user.flows.iter_mut().find(|flow| flow.key == flow_key) {
                flow.packets.push_back(packet);
            } else {
                user.flows.push_back(FlowQueue {
                    key: flow_key,
                    packets: VecDeque::from([packet]),
                });
            }
        } else {
            self.users.push_back(UserQueue {
                key: user_key,
                flows: VecDeque::from([FlowQueue {
                    key: flow_key,
                    packets: VecDeque::from([packet]),
                }]),
            });
        }
        self.pending += 1;
        Ok(())
    }

    /// Fill a complete bounded attribution batch by repeating fair rounds.
    /// In particular, one busy flow can fill all 32 slots; its quantum limits
    /// competition with other waiting flows, not the batch's utilization.
    pub(super) fn take_batch(&mut self) -> Vec<PendingPacket> {
        let mut batch = Vec::with_capacity(self.pending.min(MAX_PACKET_BATCH_SIZE));
        while batch.len() < MAX_PACKET_BATCH_SIZE {
            let Some(mut user) = self.users.pop_front() else {
                break;
            };
            if let Some(mut flow) = user.flows.pop_front() {
                let quantum = FLOW_QUANTUM.min(MAX_PACKET_BATCH_SIZE - batch.len());
                for _ in 0..quantum {
                    let Some(packet) = flow.packets.pop_front() else {
                        break;
                    };
                    self.pending -= 1;
                    batch.push(packet);
                }
                if !flow.packets.is_empty() {
                    user.flows.push_back(flow);
                }
            }
            if !user.flows.is_empty() {
                self.users.push_back(user);
            }
        }
        batch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::OutboundConnection;
    use crate::nfqueue::QueuedPacket;
    use openshield_core::InterfaceName;
    use std::net::Ipv4Addr;

    fn packet(id: u32, uid: u32, flow: u16) -> Result<PendingPacket> {
        Ok(PendingPacket {
            work: QueuedPacketWork {
                packet_id: id,
                packet: Ok(QueuedPacket {
                    connection: OutboundConnection {
                        source_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                        source_port: Some(10_000 + flow),
                        destination_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                        destination_port: Some(443),
                        protocol: TransportProtocol::Tcp,
                        output_interface: InterfaceName::new("eth0")?,
                        socket_uid: uid,
                    },
                    packet_mark: 123,
                    initial_observation: false,
                }),
            },
            received: Instant::now(),
        })
    }

    fn ids(batch: &[PendingPacket]) -> Vec<u32> {
        batch.iter().map(|packet| packet.work.packet_id).collect()
    }

    #[test]
    fn one_flow_fills_every_batch_and_retains_fifo_timestamps() -> Result<()> {
        let mut queue = FairQueue::default();
        let start = Instant::now();
        for id in 0..70 {
            let mut packet = packet(id, 1000, 1)?;
            packet.received = start + std::time::Duration::from_micros(u64::from(id));
            queue.push(packet)?;
        }
        let mut collected = Vec::new();
        for expected in [32, 32, 6] {
            let batch = queue.take_batch();
            assert_eq!(batch.len(), expected);
            for packet in &batch {
                assert_eq!(
                    packet.received,
                    start + std::time::Duration::from_micros(u64::from(packet.work.packet_id))
                );
            }
            collected.extend(ids(&batch));
        }
        assert_eq!(collected, (0..70).collect::<Vec<_>>());
        assert_eq!(queue.len(), 0);
        assert!(queue.take_batch().is_empty());
        assert!(queue.users.is_empty());
        Ok(())
    }

    #[test]
    fn many_flows_cannot_buy_extra_turns_against_another_uid() -> Result<()> {
        let mut queue = FairQueue::default();
        for flow in 0..40_u16 {
            queue.push(packet(u32::from(flow), 1000, flow)?)?;
        }
        for id in 100..140 {
            queue.push(packet(id, 2000, 1)?)?;
        }
        let batch = queue.take_batch();
        assert_eq!(batch.len(), MAX_PACKET_BATCH_SIZE);
        assert_eq!(
            &ids(&batch)[..10],
            &[0, 100, 101, 102, 103, 1, 104, 105, 106, 107]
        );
        assert_eq!(queue.len(), 48);
        Ok(())
    }

    #[test]
    fn each_uid_rotates_its_flows_and_keeps_each_flow_fifo() -> Result<()> {
        let mut queue = FairQueue::default();
        for id in 0..12 {
            queue.push(packet(id, 1000, 1)?)?;
            queue.push(packet(100 + id, 1000, 2)?)?;
        }
        let batch = queue.take_batch();
        assert_eq!(
            ids(&batch),
            [
                0, 1, 2, 3, 100, 101, 102, 103, 4, 5, 6, 7, 104, 105, 106, 107, 8, 9, 10, 11, 108,
                109, 110, 111
            ]
        );
        assert_eq!(queue.len(), 0);
        Ok(())
    }

    #[test]
    fn newly_arriving_flows_and_uids_join_the_tail() -> Result<()> {
        let mut queue = FairQueue::default();
        for id in 0..40 {
            queue.push(packet(id, 1000, 1)?)?;
            queue.push(packet(100 + id, 1000, 2)?)?;
        }
        let initial = queue.take_batch();
        assert_eq!(initial.len(), 32);
        for flow in 3..20_u16 {
            queue.push(packet(200 + u32::from(flow), 1000, flow)?)?;
        }
        queue.push(packet(300, 1, 1)?)?;
        let batch = queue.take_batch();
        // Lower numeric UIDs do not jump the established round-robin order.
        // The older second flow is served before any newly created flow.
        assert_eq!(
            &ids(&batch)[..10],
            &[16, 17, 18, 19, 300, 116, 117, 118, 119, 203]
        );
        Ok(())
    }

    #[test]
    fn admission_is_bounded_and_does_not_evict_existing_packets() -> Result<()> {
        let mut queue = FairQueue::default();
        for id in 0..u32::try_from(MAX_PENDING_PACKETS)? {
            queue.push(packet(id, 1000, 1)?)?;
        }
        assert!(queue.push(packet(999, 2000, 2)?).is_err());
        assert_eq!(queue.len(), MAX_PENDING_PACKETS);
        let mut collected = Vec::new();
        while queue.len() > 0 {
            collected.extend(ids(&queue.take_batch()));
        }
        assert_eq!(
            collected,
            (0..u32::try_from(MAX_PENDING_PACKETS)?).collect::<Vec<_>>()
        );
        queue.push(packet(1000, 2000, 2)?)?;
        assert_eq!(ids(&queue.take_batch()), [1000]);
        Ok(())
    }

    #[test]
    fn malformed_packets_have_bounded_separate_flow_keys_without_authorization() -> Result<()> {
        let mut queue = FairQueue::default();
        for id in 0..16 {
            queue.push(PendingPacket {
                work: QueuedPacketWork {
                    packet_id: id,
                    packet: Err("unparsed packet".to_owned()),
                },
                received: Instant::now(),
            })?;
        }
        for id in 100..108 {
            queue.push(packet(id, 1000, 1)?)?;
        }
        let batch = queue.take_batch();
        assert_eq!(
            &ids(&batch)[..10],
            &[0, 100, 101, 102, 103, 1, 104, 105, 106, 107]
        );
        assert_eq!(
            batch
                .iter()
                .filter(|packet| packet.work.packet.is_err())
                .count(),
            16
        );
        assert_eq!(queue.len(), 0);
        Ok(())
    }
}
