.PHONY: test test-rust test-js test-wasm test-production \
	test-production-fast test-e2e verify-dev verify-release verify

test: test-rust test-js

test-rust:
	cargo test --workspace --all-targets --locked

test-js:
	npm --prefix steve-js-sdk test

test-wasm:
	$(MAKE) -C steve-js-sdk test-wasm

test-production:
	./scripts/test-production-exclusions.sh release

test-production-fast:
	./scripts/test-production-exclusions.sh fast

test-e2e:
	./scripts/test-e2e.sh

verify-dev:
	$(MAKE) test-rust
	$(MAKE) test-production-fast
	$(MAKE) test-e2e

verify-release:
	$(MAKE) test-rust
	$(MAKE) test-production
	$(MAKE) test-e2e

verify: verify-release
