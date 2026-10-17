use super::*;
use std::{collections::BTreeMap, fmt::Write as _, sync::Mutex};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

#[derive(Debug, Clone)]
pub(super) struct Captured {
    pub(super) method: String,
    pub(super) target: String,
    pub(super) headers: BTreeMap<String, String>,
    pub(super) body: String,
}
#[derive(Debug)]
pub(super) struct Reply {
    pub(super) raw: Vec<u8>,
    pub(super) delay: Duration,
}
impl Reply {
    pub(super) fn json(status: u16, body: serde_json::Value, headers: &[(&str, String)]) -> Self {
        let body = body.to_string();
        let mut extra = String::new();
        for (key, value) in headers {
            writeln!(extra, "{key}: {value}\r").unwrap();
        }
        Self { raw: format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).into_bytes(), delay: Duration::ZERO }
    }
}
pub(super) struct Server {
    pub(super) origin: String,
    pub(super) requests: Arc<Mutex<Vec<Captured>>>,
    task: JoinHandle<()>,
}
impl Server {
    pub(super) async fn start(handler: impl Fn(&Captured) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = tokio::time::timeout(Duration::from_secs(3), read(&mut stream)).await.unwrap();
                let reply = handler(&request);
                captured.lock().unwrap().push(request);
                tokio::time::sleep(reply.delay).await;
                let _ = stream.write_all(&reply.raw).await;
            }
        });
        Self { origin, requests, task }
    }
    pub(super) fn count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
    pub(super) fn client(&self, limits: Limits) -> NacosConfigClient {
        NacosConfigClient::new(
            EngineEndpoint::literal_loopback_for_test(&self.origin).unwrap(),
            Arc::new(Provider { delay: Duration::ZERO, credential: tests::credential() }),
            limits,
        )
        .unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read(stream: &mut TcpStream) -> Captured {
    let mut bytes = Vec::new();
    let boundary = loop {
        let mut chunk = [0_u8; 1024];
        let size = stream.read(&mut chunk).await.unwrap();
        assert!(size > 0, "client ended before request headers");
        bytes.extend_from_slice(&chunk[..size]);
        assert!(bytes.len() <= 1024 * 1024);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let head = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    let method = first.next().unwrap().into();
    let target = first.next().unwrap().into();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().into()))
        .collect();
    let length = headers.get("content-length").map_or(0, |value| value.parse::<usize>().unwrap());
    assert!(length <= 1024 * 1024);
    while bytes.len() < boundary + length {
        let mut chunk = [0_u8; 1024];
        let size = stream.read(&mut chunk).await.unwrap();
        assert!(size > 0);
        bytes.extend_from_slice(&chunk[..size]);
    }
    Captured { method, target, headers, body: String::from_utf8(bytes[boundary..boundary + length].to_vec()).unwrap() }
}
#[derive(Debug)]
pub(super) struct Provider {
    pub(super) delay: Duration,
    pub(super) credential: CloudCredential,
}
#[derive(Debug)]
pub(super) struct ExpiringProvider;
#[async_trait]
impl NacosCredentialProvider for ExpiringProvider {
    async fn credentials(&self) -> DomainResult<CloudCredential> {
        let mut credential = tests::credential();
        credential.expires_at = Some(Timestamp::now().offset_secs(2));
        Ok(credential)
    }
}
#[derive(Debug)]
pub(super) struct BlockingProvider;
#[async_trait]
impl NacosCredentialProvider for BlockingProvider {
    async fn credentials(&self) -> DomainResult<CloudCredential> {
        // Deliberately model a misbehaving provider which does not yield to the timeout timer.
        std::thread::sleep(Duration::from_millis(80));
        Ok(tests::credential())
    }
}
#[async_trait]
impl NacosCredentialProvider for Provider {
    async fn credentials(&self) -> DomainResult<CloudCredential> {
        tokio::time::sleep(self.delay).await;
        Ok(self.credential.clone())
    }
}
#[derive(Debug)]
pub(super) struct Guard {
    pub(super) delay: Duration,
    pub(super) reject: bool,
}
#[async_trait]
impl NacosSendGuard for Guard {
    async fn validate(&self) -> DomainResult<()> {
        tokio::time::sleep(self.delay).await;
        if self.reject {
            return Err(DomainError::Forbidden("owned guard rejection".into()));
        }
        Ok(())
    }
}
pub(super) fn allow() -> Guard {
    Guard { delay: Duration::ZERO, reject: false }
}
pub(super) fn parsed_pairs(value: &str) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(value.as_bytes()).map(|(key, value)| (key.into_owned(), value.into_owned())).collect()
}
