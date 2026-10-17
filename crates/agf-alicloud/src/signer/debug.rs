//! Signing structures contain credentials or signed tokens; Debug exposes only safe metadata.
use super::*;
impl std::fmt::Debug for RpcSignInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcSignInput")
            .field("method", &self.method)
            .field("parameter_count", &self.params.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for RpcSigned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcSigned").field("query_bytes", &self.final_query.len()).finish_non_exhaustive()
    }
}
impl std::fmt::Debug for V3SignInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3SignInput")
            .field("method", &self.method)
            .field("host", &self.host)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Debug for V3Signed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V3Signed").field("header_names", &self.signed_headers.keys()).finish_non_exhaustive()
    }
}
