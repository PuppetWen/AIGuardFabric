//! 对象存储数据源抽象：`ObjectMeta` / `ObjectSource` 与 S3（兼容 OSS/MinIO）实现 `S3ObjectSource`。

use super::*;

/// 对象元数据（列表结果的最小集）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectMeta {
    /// 对象键。
    pub key: String,
    /// ETag（已去掉引号）；`None` 表示后端未给出。
    pub etag: Option<String>,
    /// 最后修改时间（`epoch_secs.nanos` 文本；`None` 表示后端未给出）。
    pub last_modified: Option<String>,
    /// 对象字节数。
    pub size: u64,
}

/// 对象存储抽象（真实实现走 aws-sdk-s3；测试注入内存实现，**测试不依赖 docker**）。
#[async_trait]
pub trait ObjectSource: Send + Sync + std::fmt::Debug {
    /// 列出前缀下的对象（按后端顺序；调用方自行排序）。
    ///
    /// # Errors
    /// 网络/鉴权/权限失败。
    async fn list(&self, prefix: &str, max: usize) -> DomainResult<Vec<ObjectMeta>>;

    /// 取对象内容。
    ///
    /// # Errors
    /// 对象不存在或读取失败。
    async fn get(&self, key: &str) -> DomainResult<Vec<u8>>;

    /// 描述（`/readyz` 与日志用）。
    fn describe(&self) -> String;
}

/// 基于 `aws-sdk-s3` 的真实实现（MinIO / AWS S3 / 阿里云 OSS 的 S3 兼容端点）。
#[derive(Debug)]
pub struct S3ObjectSource {
    client: aws_sdk_s3::Client,
    bucket: String,
    endpoint: String,
}

impl S3ObjectSource {
    /// 由显式配置构造（`force_path_style` 对 MinIO 必须为 `true`）。
    ///
    /// # Errors
    /// 端点/凭据缺失。
    pub fn new(
        endpoint: &str,
        region: &str,
        access_key: &str,
        secret_key: &str,
        bucket: &str,
        force_path_style: bool,
    ) -> DomainResult<Self> {
        if endpoint.is_empty() || access_key.is_empty() || secret_key.is_empty() || bucket.is_empty() {
            return Err(DomainError::Config(
                "对象存储拉取需要 AGF_S3_ENDPOINT / AGF_S3_ACCESS_KEY / AGF_S3_SECRET_KEY / bucket".to_string(),
            ));
        }
        let credentials = aws_sdk_s3::config::Credentials::new(
            access_key.to_string(),
            secret_key.to_string(),
            None,
            None,
            "agf-ingest-object-pull",
        );
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new(region.to_string()))
            .credentials_provider(credentials)
            .force_path_style(force_path_style)
            .endpoint_url(endpoint.to_string())
            .build();
        Ok(Self {
            client: aws_sdk_s3::Client::from_conf(config),
            bucket: bucket.to_string(),
            endpoint: endpoint.to_string(),
        })
    }

    /// 桶名。
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

#[async_trait]
impl ObjectSource for S3ObjectSource {
    async fn list(&self, prefix: &str, max: usize) -> DomainResult<Vec<ObjectMeta>> {
        let max_keys = i32::try_from(max.clamp(1, 1000)).unwrap_or(1000);
        let output =
            self.client.list_objects_v2().bucket(&self.bucket).prefix(prefix).max_keys(max_keys).send().await.map_err(
                |e| DomainError::DependencyUnavailable {
                    dependency: "s3".to_string(),
                    cause: format!("列举 {}/{} 失败: {e}", self.endpoint, self.bucket),
                },
            )?;
        let mut out = Vec::new();
        for object in output.contents() {
            let key = object.key().unwrap_or_default().to_string();
            if key.is_empty() {
                continue;
            }
            out.push(ObjectMeta {
                key,
                etag: object.e_tag().map(|tag| tag.trim_matches('"').to_string()),
                last_modified: object.last_modified().map(|t| format!("{}.{:09}", t.secs(), t.subsec_nanos())),
                size: u64::try_from(object.size().unwrap_or(0)).unwrap_or(0),
            });
        }
        Ok(out)
    }

    async fn get(&self, key: &str) -> DomainResult<Vec<u8>> {
        let output = self.client.get_object().bucket(&self.bucket).key(key).send().await.map_err(|e| {
            DomainError::DependencyUnavailable {
                dependency: "s3".to_string(),
                cause: format!("读取 s3://{}/{key} 失败: {e}", self.bucket),
            }
        })?;
        let body = output.body.collect().await.map_err(|e| DomainError::Internal(format!("读取对象体失败: {e}")))?;
        Ok(body.into_bytes().to_vec())
    }

    fn describe(&self) -> String {
        format!("s3://{} @ {}", self.bucket, self.endpoint)
    }
}
