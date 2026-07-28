.PHONY: test test-rust test-js test-wasm test-production test-e2e verify

test: test-rust test-js

test-rust:
	cargo test --workspace --all-targets --locked

test-js:
	npm --prefix steve-js-sdk test

test-wasm:
	$(MAKE) -C steve-js-sdk test-wasm

test-production:
	./scripts/test-production-exclusions.sh

test-e2e:
	./scripts/test-e2e.sh

verify:
	$(MAKE) test-rust
	$(MAKE) test-production
	$(MAKE) test-e2e
