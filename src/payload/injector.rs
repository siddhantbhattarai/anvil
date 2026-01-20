use url::Url;

pub fn inject_query_param(
    base: &Url,
    param: &str,
    payload: &str,
) -> anyhow::Result<Url> {
    let mut url = base.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut found = false;

    for (k, v) in pairs.iter_mut() {
        if k == param {
            *v = payload.to_string();
            found = true;
        }
    }

    if !found {
        pairs.push((param.to_string(), payload.to_string()));
    }

    url.query_pairs_mut().clear().extend_pairs(pairs);
    Ok(url)
}
