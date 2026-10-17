//! `CommandAck` 构造的离线单测（从 `pulsar/tests.rs` 拆出，见该文件的模块说明）。
#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used, clippy::match_wildcard_for_single_variants)]

use super::*;

/// Individual ack：`ack_type` 必须是 0 且**显式编码**，message_id 逐条带出（含 entryId=0）。
#[test]
fn individual_ack_encodes_zero_ack_type_and_entry_zero() {
    let ack = individual_ack(77, vec![MessageIdData::new(1, 0, -1), MessageIdData::new(1, 5, -1)]);
    assert_eq!(ack.ack_type, Some(ack_type::INDIVIDUAL));
    assert_eq!(ack.message_id.len(), 2);
    let frame_bytes = encode_command_frame(&BaseCommand::ack(ack));
    match decode_frame(&frame_bytes).expect("decode") {
        DecodedFrame::Command(command) => {
            let ack = command.ack.expect("ack");
            assert_eq!(ack.consumer_id, Some(77));
            assert_eq!(ack.ack_type, Some(ack_type::INDIVIDUAL));
            assert_eq!(ack.validation_error, None);
            assert_eq!(ack.message_id.len(), 2);
            assert_eq!(ack.message_id[0].coord(), (1, 0), "entryId=0 必须编码出来");
            assert_eq!(ack.message_id[1].coord(), (1, 5));
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
}

/// Cumulative ack：`ack_type = 1`，只带最新一条 id。
#[test]
fn cumulative_ack_encodes_ack_type_one() {
    let ack = cumulative_ack(3, MessageIdData::new(2, 9, -1));
    assert_eq!(ack.ack_type, Some(ack_type::CUMULATIVE));
    let bytes = ack.encode_to_vec();
    assert!(bytes.windows(2).any(|pair| pair == [0x10, 0x01]), "ack_type=1 必须显式编码");
    assert_eq!(ack.message_id.len(), 1);
}

/// FLOW 帧：`consumer_id` / `messagePermits` 都要在（字段 1/2）。
#[test]
fn flow_frame_roundtrip() {
    let flow = BaseCommand::flow(CommandFlow { consumer_id: Some(4), message_permits: Some(1000) });
    let bytes = encode_command_frame(&flow);
    match decode_frame(&bytes).expect("decode") {
        DecodedFrame::Command(command) => {
            let flow = command.flow.expect("flow");
            assert_eq!(flow.consumer_id, Some(4));
            assert_eq!(flow.message_permits, Some(1000));
        }
        other => panic!("期望命令帧，得到 {other:?}"),
    }
}
