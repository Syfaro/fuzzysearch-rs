use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub use types::*;

mod types;

/// FuzzySearch is a collection of methods to get information from fuzzysearch.net.
pub struct FuzzySearch {
    api_key: String,
    client: reqwest::Client,
}

/// How to match against FuzzySearch.
#[derive(Debug, PartialEq)]
pub enum MatchType {
    /// Start by looking at only exact items, then expand if no results.
    Close,
    /// Only look at exact items.
    Exact,
    /// Force matching expanded set of results.
    Force,
}

impl FuzzySearch {
    pub const API_ENDPOINT: &'static str = "https://api.fuzzysearch.net";

    /// Create a new FAUtil instance. Requires the API key.
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
        }
    }

    /// Makes a request against the API. It deserializes the JSON response.
    /// Generally not used as there are more specific methods available.
    async fn make_request<T: Default + DeserializeOwned>(
        &self,
        endpoint: &str,
        params: &HashMap<&str, String>,
    ) -> reqwest::Result<T> {
        let url = format!("{}{}", Self::API_ENDPOINT, endpoint);

        let req = self
            .client
            .get(&url)
            .header("X-Api-Key", self.api_key.as_bytes())
            .query(params);

        let req = Self::trace_headers(req);

        req.send().await?.json().await
    }

    /// Attempt to look up an image by its URL. Note that URLs should be https.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self)))]
    pub async fn lookup_url(&self, url: &str) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("url", url.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to look up an image by its original name on FA.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self)))]
    pub async fn lookup_filename(&self, filename: &str) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("name", filename.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to lookup multiple hashes.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self)))]
    pub async fn lookup_hashes(&self, hashes: Vec<i64>) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert(
            "hashes",
            hashes
                .iter()
                .map(|hash| hash.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );

        self.make_request("/hashes", &params).await
    }

    /// Attempt to reverse image search.
    ///
    /// Requiring an exact match will be faster, but potentially leave out results.
    #[cfg_attr(feature = "trace", tracing::instrument(skip(self, data)))]
    pub async fn image_search(&self, data: &[u8], exact: MatchType) -> reqwest::Result<Matches> {
        use reqwest::multipart::{Form, Part};

        let url = format!("{}/image", Self::API_ENDPOINT);

        let part = Part::bytes(Vec::from(data));
        let form = Form::new().part("image", part);

        let query = match exact {
            MatchType::Exact => vec![("type", "exact".to_string())],
            MatchType::Force => vec![("type", "force".to_string())],
            _ => vec![("type", "close".to_string())],
        };

        let req = self
            .client
            .post(&url)
            .query(&query)
            .header("X-Api-Key", self.api_key.as_bytes())
            .multipart(form);

        let req = Self::trace_headers(req);

        req.send().await?.json().await
    }

    #[cfg(feature = "trace")]
    fn trace_headers(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        use opentelemetry::api::HttpTextFormat;
        use std::convert::TryInto;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = tracing::Span::current().context();

        let mut carrier = std::collections::HashMap::new();
        let propagator = opentelemetry::api::B3Propagator::new(true);
        propagator.inject_context(&context, &mut carrier);

        let headers: reqwest::header::HeaderMap = (&carrier)
            .try_into()
            .expect("generated headers contained invalid data");

        req.headers(headers)
    }

    #[cfg(not(feature = "trace"))]
    fn trace_headers(req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req
    }
}

#[cfg(feature = "local_hash")]
pub use image::ImageError;

#[cfg(feature = "local_hash")]
/// Create an img_hash instance with the same parameters that FuzzySearch uses.
pub fn get_hasher() -> img_hash::Hasher<[u8; 8]> {
    img_hash::HasherConfig::with_bytes_type::<[u8; 8]>()
        .hash_alg(img_hash::HashAlg::Gradient)
        .hash_size(8, 8)
        .preproc_dct()
        .to_hasher()
}

#[cfg(feature = "local_hash")]
/// Hash an image into a 64 bit number that's compatible with FuzzySearch.
pub fn hash_bytes(b: &[u8]) -> Result<i64, image::ImageError> {
    let hasher = get_hasher();

    let image = image::load_from_memory(&b)?;
    let hash = hasher.hash_image(&image);
    drop(image);

    let mut buf = [0u8; 8];
    buf.copy_from_slice(hash.as_bytes());

    Ok(i64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_api() -> FuzzySearch {
        FuzzySearch::new("eluIOaOhIP1RXlgYetkcZCF8la7p3NoCPy8U0i8dKiT4xdIH".to_string())
    }

    #[tokio::test]
    async fn test_lookup() {
        let api = get_api();

        let no_filenames = api.lookup_filename("nope").await;
        println!("{:?}", no_filenames);

        assert!(no_filenames.is_ok());
        assert_eq!(no_filenames.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_image() {
        let api = get_api();

        let images = api
            .image_search(
                &[
                    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49,
                    0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06,
                    0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44,
                    0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01, 0x0D,
                    0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42,
                    0x60, 0x82,
                ],
                MatchType::Exact,
            )
            .await;

        println!("{:?}", images);

        assert!(images.is_ok());
        assert_eq!(images.unwrap().matches.len(), 2);
    }
}
