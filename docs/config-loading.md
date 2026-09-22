# YAML loading for v1.0.0

`LoadConfig(path)` starts with `NewConfig()` defaults. To supply dependencies or
defaults yourself, use `cfg := NewConfig()`, set them, then `cfg.LoadFile(path)`.
Loading applies supplied keys; omitted settings and dependencies are retained.
Explicit zero/false values override earlier values. Loading is not transactional:
discard a config after a loading error.

- Omitted `unsafe_allow_private_ranges`, `support_proxy_protocol`, and
  `allow_missing_role` retain caller values instead of resetting to false.
  Set these keys explicitly when the file must determine the security posture.
- Either `allow_ranges` or `allow_addresses` replaces **all combined allow rules**;
  the equivalent deny keys replace all combined deny rules. `[]` clears the list.
  For example, caller addresses added before loading are removed when the file
  supplies `allow_ranges`. To extend file rules, call the append-only
  `SetAllow*`/`SetDeny*` methods after loading. CLI rule flags still append afterward.
- A supplied `max_request_burst` is retained even without a rate/concurrency key;
  burst alone does not enable limiting. Omitted rate settings retain their values.
- Invalid `stats_socket_file_mode` returns an error instead of exiting the process.

Set `cfg.Log` before loading to capture configuration/ACL diagnostics. The CLI
also installs its supplied logger before loading the file.
