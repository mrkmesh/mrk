pub const EXPLORER_BASE_PATH: &str = "/explorer";

const INDEX_HTML: &[u8] = include_bytes!("../ui/dist/index.html");
const APP_JS: &[u8] = include_bytes!("../ui/dist/assets/app.js");
const APP_CSS: &[u8] = include_bytes!("../ui/dist/assets/app.css");

pub struct Asset {
    pub content_type: &'static str,
    pub cache_control: &'static str,
    pub body: &'static [u8],
}

pub fn asset(path: &str) -> Option<Asset> {
    match path {
        "/explorer/assets/app.js" => Some(Asset {
            content_type: "text/javascript; charset=utf-8",
            cache_control: "no-cache",
            body: APP_JS,
        }),
        "/explorer/assets/app.css" => Some(Asset {
            content_type: "text/css; charset=utf-8",
            cache_control: "no-cache",
            body: APP_CSS,
        }),
        path if path.starts_with("/explorer/assets/") => None,
        path if path == EXPLORER_BASE_PATH || path.starts_with("/explorer/") => Some(Asset {
            content_type: "text/html; charset=utf-8",
            cache_control: "no-cache",
            body: INDEX_HTML,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_routes_fall_back_to_index() {
        let asset = asset("/explorer/blocks/42").expect("history route");
        assert_eq!(asset.content_type, "text/html; charset=utf-8");
        assert!(asset.body.starts_with(b"<!doctype html>"));
    }

    #[test]
    fn unknown_assets_do_not_fall_back_to_index() {
        assert!(asset("/explorer/assets/missing.js").is_none());
    }
}
