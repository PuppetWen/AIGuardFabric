//! 解析 macOS `lsof -Fpcfn` 的进程/文件分组输出。

use crate::payload::ListeningPort;

pub(super) fn parse_lsof_fields(text: &str, protocol: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    let mut pid = None;
    let mut process = None;
    let mut file_open = false;
    for line in text.lines() {
        let mut chars = line.chars();
        let Some(field) = chars.next() else { continue };
        let value = chars.as_str();
        match field {
            'p' => {
                pid = value.parse::<u32>().ok();
                process = None;
                file_open = false;
            }
            'c' => process = Some(value.to_string()),
            'f' => file_open = true,
            'n' if file_open && !value.contains("->") => {
                let address = value.split_whitespace().next().unwrap_or_default();
                let Some((local_addr, port)) = super::ports::split_endpoint(address) else { continue };
                ports.push(ListeningPort {
                    protocol: protocol.to_string(),
                    local_addr,
                    port,
                    pid,
                    process: process.clone(),
                });
            }
            _ => {}
        }
    }
    ports.sort_by(|a, b| {
        (a.protocol.as_str(), a.local_addr.as_str(), a.port, a.pid).cmp(&(
            b.protocol.as_str(),
            b.local_addr.as_str(),
            b.port,
            b.pid,
        ))
    });
    ports.dedup_by(|a, b| {
        a.protocol == b.protocol && a.local_addr == b.local_addr && a.port == b.port && a.pid == b.pid
    });
    ports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_groups_keep_listeners_and_process_identity() {
        let sample = "p41\nclsof\nf7u\nn127.0.0.1:11434\nf8u\nn[::1]:8080\np51\ncmodel server\nf4u\nn*:8000\nf5u\nn127.0.0.1:9000->127.0.0.1:443\n";
        let ports = parse_lsof_fields(sample, "tcp");
        assert_eq!(ports.len(), 3);
        assert!(ports.iter().any(|item| item.local_addr == "127.0.0.1" && item.port == 11434 && item.pid == Some(41)));
        assert!(ports.iter().any(|item| item.local_addr == "::1" && item.port == 8080));
        assert!(ports.iter().any(|item| item.local_addr == "*"
            && item.port == 8000
            && item.process.as_deref() == Some("model server")));
    }

    #[test]
    fn duplicate_file_descriptors_collapse_but_distinct_pids_remain() {
        let sample = "p1\ncfirst\nf3u\nn*:5353\nf4u\nn*:5353\np2\ncsecond\nf5u\nn*:5353\n";
        let ports = parse_lsof_fields(sample, "udp");
        assert_eq!(ports.len(), 2);
        assert!(ports.iter().all(|item| item.protocol == "udp"));
        assert!(parse_lsof_fields("invalid\np5\nf3u\nnnot-an-address\n", "tcp").is_empty());
    }
}
