use bytes::BytesMut;
use wolf_mqtt::protocol::{decode_variable_byte_integer, encode_variable_byte_integer};
use wolf_mqtt::routing::TopicTrie;

#[test]
fn test_integration_routing_and_vbi() {
    // 1. Test topic router
    let mut trie = TopicTrie::new();
    trie.subscribe("devices/+/telemetry", "client_cloud_01");
    trie.subscribe("devices/#", "client_logger_all");

    let matches = trie.matches("devices/motor12/telemetry");
    assert!(matches.contains("client_cloud_01"));
    assert!(matches.contains("client_logger_all"));

    // 2. Test VBI serialization
    let payload_len = 1048576; // 1 MB payload test
    let mut buf = BytesMut::new();
    encode_variable_byte_integer(payload_len, &mut buf).expect("Encode must succeed");

    let mut read_buf = &buf[..];
    let decoded = decode_variable_byte_integer(&mut read_buf).expect("Decode must succeed");
    assert_eq!(decoded, payload_len);
}
