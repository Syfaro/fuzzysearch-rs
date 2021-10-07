use serde::de::DeserializeOwned;
use std::collections::HashMap;

pub use types::*;

mod types;

/// FuzzySearch is a collection of methods to get information from fuzzysearch.net.
pub struct FuzzySearch {
    endpoint: String,
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

pub struct FuzzySearchOpts {
    pub endpoint: Option<String>,
    pub client: Option<reqwest::Client>,
    pub api_key: String,
}

impl FuzzySearch {
    pub const API_ENDPOINT: &'static str = "https://api.fuzzysearch.net";

    /// Create a new FuzzySearch instance. Requires the API key.
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: reqwest::Client::new(),
            endpoint: Self::API_ENDPOINT.to_string(),
        }
    }

    /// Create a new FuzzySearch instance with a custom client or endpoint.
    pub fn new_with_opts(opts: FuzzySearchOpts) -> Self {
        Self {
            api_key: opts.api_key,
            client: opts.client.unwrap_or_else(reqwest::Client::new),
            endpoint: opts
                .endpoint
                .unwrap_or_else(|| Self::API_ENDPOINT.to_string()),
        }
    }

    /// Makes a request against the API. It deserializes the JSON response.
    /// Generally not used as there are more specific methods available.
    async fn make_request<T: Default + DeserializeOwned>(
        &self,
        endpoint: &str,
        params: &HashMap<&str, String>,
    ) -> reqwest::Result<T> {
        let url = format!("{}{}", self.endpoint, endpoint);

        let req = self
            .client
            .get(&url)
            .header("X-Api-Key", self.api_key.as_bytes())
            .query(params);

        let req = Self::trace_headers(req);

        req.send().await?.json().await
    }

    /// Attempt to look up an image by its URL. Note that URLs should be https.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self)))]
    pub async fn lookup_url(&self, url: &str) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("url", url.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to look up an image by its original name on FA.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self)))]
    pub async fn lookup_filename(&self, filename: &str) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("name", filename.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to look up an image by its file ID on FA.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self)))]
    pub async fn lookup_file_id(&self, file_id: i64) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("id", file_id.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to look up an image by its ID on FA.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self)))]
    pub async fn lookup_id(&self, id: i32) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert("site_id", id.to_string());

        self.make_request("/file", &params).await
    }

    /// Attempt to lookup multiple hashes.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self)))]
    pub async fn lookup_hashes(
        &self,
        hashes: &[i64],
        distance: Option<i64>,
    ) -> reqwest::Result<Vec<File>> {
        let mut params = HashMap::new();
        params.insert(
            "hashes",
            hashes
                .iter()
                .map(|hash| hash.to_string())
                .collect::<Vec<_>>()
                .join(","),
        );
        if let Some(distance) = distance {
            params.insert("distance", distance.to_string());
        }

        self.make_request("/hashes", &params).await
    }

    /// Attempt to reverse image search.
    ///
    /// Requiring an exact match will be faster, but potentially leave out results.
    #[cfg_attr(feature = "trace", tracing::instrument(err, skip(self, data)))]
    pub async fn image_search(
        &self,
        data: &[u8],
        exact: MatchType,
        distance: Option<i64>,
    ) -> reqwest::Result<Matches> {
        use reqwest::multipart::{Form, Part};

        let url = format!("{}/image", self.endpoint);

        let part = Part::bytes(Vec::from(data));
        let form = Form::new().part("image", part);

        let mut query = match exact {
            MatchType::Exact => vec![("type", "exact".to_string())],
            MatchType::Force => vec![("type", "force".to_string())],
            _ => vec![("type", "close".to_string())],
        };
        if let Some(distance) = distance {
            query.push(("distance", distance.to_string()));
        }

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
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let context = tracing::Span::current().context();

        let mut headers: reqwest::header::HeaderMap = Default::default();
        opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.inject_context(
                &context,
                &mut opentelemetry_http::HeaderInjector(&mut headers),
            )
        });

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
                None,
            )
            .await;

        assert!(images.is_ok());
        assert!(images.unwrap().matches.len() > 0);
    }

    #[tokio::test]
    async fn test_bad_question_mark() {
        let api = get_api();

        let hashes = [
            -2556732020129704400,
            -2561236014356413000,
            -2547724682899139000,
            -2547706523777382000,
            -2581468986813360600,
            -2545472262588508700,
            -3700347395489575400,
            -7303508297210637000,
            -5425665582294280000,
        ];

        let results_dist0 = api.lookup_hashes(&hashes, None).await.unwrap();
        let results_dist1 = api.lookup_hashes(&hashes, Some(1)).await.unwrap();

        assert_ne!(results_dist0.len(), results_dist1.len());
    }
}
