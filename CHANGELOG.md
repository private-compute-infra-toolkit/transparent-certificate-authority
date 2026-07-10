# Changelog

All notable changes to this project will be documented in this file. See [commit-and-tag-version](https://github.com/absolute-version/commit-and-tag-version) for commit guidelines.

## 0.6.0 (2026-07-10)


### Dependencies

* **deps:** Update DevKit to release-3.10.0


### Features

* Change MBS metrics from counter to gauge
* Expose main certificate validity metric
* Remove support for legacy claim types
* Rename main certificate to root certificate in metrics
* Update root cert validity to 180 days
* use regex Oak verifier

## 0.5.0 (2026-06-30)


### Features

* Add custom metrics - certificate issuance by clientId
* Add metrics for failure cases
* Add missing processing status to metrics
* Add support for Policy v2 textproto parsing
* Add timeout for OidcDiscoveryFetcher.fetchJwksUri
* Copy policy/v1 related files as policy/v2 without modification
* Delegate processing from Event Loop to Blocking Pool
* Integrate MBS metrics
* Rename AuthorizationCounter to AuthenticationCounter
* represent name constraints polymorphically in domain model
* Update container-tools to fix enclave watcher resets
* Use TCA's trust domain to construct client's SPIFFE ID


### Bug Fixes

* Fix metric cloudwatch filter name
* **kokoro:** manually tag copied AMIs to bypass launch permission errors
* return 403 Forbidden on OIDC audience validation failure

## 0.4.0 (2026-06-25)


### Dependencies

* **deps:** Update DevKit to release-3.9.0


### Features

* Add metrics-exporter configuration
* Cache policy files fetched from s3 for 5 minutes
* Disable prometheus relabeling
* Propagate GOB commit and RAPID pipeline URLs to AMI tags
* Update container-tools
* Update MBS. Set SKI in root cert. Set cache-control on backup
* Use issuer cert's SKI as issued cert's AKI


### Bug Fixes

* map IncorrectEndorsementFormatException to INVALID_ARGUMENT

## 0.3.0 (2026-06-03)


### Features

* Dynamic OIDC audience binding validation
* feat: Add support for new claims .md location

## 0.2.0 (2026-05-29)


### Dependencies

* **deps:** Update DevKit to release-3.6.0
* **deps:** Update DevKit to release-3.7.0
* **deps:** Update DevKit to release-3.8.0


### Features

* add ServiceRegion annotation and bindings
* add TrustDomain annotation and provider
* Align SPIFFE ID publisher format for TCA client workloads
* Bump api, use certificate subject from policy
* enclave log forwarding to CloudWatch with FluentBit
* Introduce metrics module and endpoint
* Introduce Metrics module to support custom metrics
* issueCertificate returns complete cert chain
* Set spiffe ID in TCA root cert
* Update operator/ part of TCA's root cert spiffe_id
* Update publisher/ part of TCA's root cert spiffe_id


### Bug Fixes

* Bump submodule mbs to store root_cert as PEM format


### Documentation

* Update GEMINI.md according to jetski suggestions

## 0.1.0 (2026-05-13)


### Features

* Initial release
