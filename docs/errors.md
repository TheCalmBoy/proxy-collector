# Subscription Worker errors

`GET /sub` returns errors as JSON: `{"error":"<code>"}`. Invalid request inputs
normally use HTTP 400; format and entrypoint incompatibilities use HTTP 406.

| Code | HTTP status | Cause | Fix |
|---|---:|---|---|
| `method_not_allowed` | 405 | The request method is not GET. | Send a GET request. |
| `not_found` | 404 | The path is not a supported subscription route. | Use `/sub`. |
| `country_must_be_two_letter_iso_code_or_ALL` | 400 | `country` is not a two-letter code or `ALL`. | Pass a two-letter country code or omit the option. |
| `protocol_must_be_a_comma_separated_list_of_supported_protocols` | 400 | `protocol` is empty or contains an unsupported protocol. | Use one or more supported protocol names. |
| `exclude_must_be_a_comma_separated_list_of_two_letter_country_codes` | 400 | An `exclude` item is not a two-letter country code. | Pass comma-separated two-letter codes. |
| `invalid_entry64` | 400 | An `entry64` value is empty or is not valid base64. | Encode a proxy URI as URL-safe base64 and pass it as `entry64`. |
| `unsupported_entry_scheme` | 400 | The decoded entry URI uses an unsupported scheme. | Use a supported proxy URI scheme. |
| `entry_parse_failed` | 400 | The entry URI is malformed or lacks required fields. | Correct the URI fields and encode it again. |
| `format_must_be_mihomo_sing_box_xray_or_links` | 400 | `format` names an unsupported output format. | Use `mihomo`, `sing-box`, `xray`, or `links`. |
| `client_format_not_detected_use_format_override` | 406 | The client format could not be inferred for an entrypoint request. | Set `format=` explicitly. |
| `wireguard_entry_requires_mihomo_xray_or_links_format` | 406 | The selected format cannot express a WireGuard entrypoint. | Use `mihomo`, `xray`, or `links`. |
| `masque_entry_requires_mihomo_format` | 406 | The selected format cannot express a MASQUE entrypoint. | Use `format=mihomo`. |
| `quic_or_anytls_entry_requires_mihomo_or_sing_box_format` | 406 | Xray cannot express the selected QUIC or AnyTLS entrypoint. | Use `mihomo` or `sing-box`. |
| `country_feed_not_found` | 404 | The requested country feed does not exist. | Choose a country with a published feed or use `country=ALL`. |
| `country_feed_unavailable` | 502 | The upstream feed returned an unsuccessful response. | Retry after the published feed is available. |
| `no_proxies_match_protocol_filter` | 404 | The feed contains no supported proxy matching `protocol`. | Broaden or remove the protocol filter. |
| `feed_has_no_supported_proxies` | 404 | The feed contains no proxy URI this Worker can render. | Retry after the feed contains supported proxies. |
| `no_tls_exits_in_feed` | 503 | `secure=1` removed every exit because none use TLS. | Remove `secure=1` or choose a feed with TLS exits. |
| `no_recently_verified_proxies` | 503 | No feed exits join to the recent health index. | Retry after the next successful egress-health probe. |
| `no_proxies_match_filters` | 404 | The country and protocol filters removed every exit. | Broaden or remove one of the filters. |
