CONTAINER_ENGINE ?= docker
BUILD_PLATFORM ?= linux/amd64
BUILD_CONTEXT ?= ..
STAGE_OUTPUT ?= .stagex-output

PRODUCTION_IMAGE ?= enclave-service-worker-build
WASM_IMAGE ?= enclave-service-worker-wasm
WASM_TEST_IMAGE ?= enclave-service-worker-wasm-test
E2E_IMAGE ?= enclave-service-worker-e2e

.PHONY: build build-wasm build-e2e test-wasm clean clean-e2e

build:
	rm -rf "$(STAGE_OUTPUT)/production"
	mkdir -p "$(STAGE_OUTPUT)/production"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target output -t "$(PRODUCTION_IMAGE)" "$(BUILD_CONTEXT)" --no-cache
	container_id=$$($(CONTAINER_ENGINE) create "$(PRODUCTION_IMAGE)" true) && \
		$(CONTAINER_ENGINE) cp "$$container_id:/build/dist/." "$(STAGE_OUTPUT)/production/" && \
		$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	rm -rf dist
	mv "$(STAGE_OUTPUT)/production" dist
	@echo "Canonical StageX build complete:"
	@ls -la dist/

build-wasm:
	rm -rf "$(STAGE_OUTPUT)/wasm"
	mkdir -p "$(STAGE_OUTPUT)/wasm"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target wasm-output -t "$(WASM_IMAGE)" "$(BUILD_CONTEXT)"
	container_id=$$($(CONTAINER_ENGINE) create "$(WASM_IMAGE)" true) && \
		$(CONTAINER_ENGINE) cp "$$container_id:/build/wasm-pkg/." "$(STAGE_OUTPUT)/wasm/" && \
		$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	rm -rf wasm-pkg
	mv "$(STAGE_OUTPUT)/wasm" wasm-pkg
	@echo "StageX WASM bindings complete:"
	@ls -la wasm-pkg/

test-wasm:
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target wasm-test -t "$(WASM_TEST_IMAGE)" "$(BUILD_CONTEXT)"

build-e2e:
	rm -rf "$(STAGE_OUTPUT)/e2e"
	mkdir -p "$(STAGE_OUTPUT)/e2e"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target e2e-output -t "$(E2E_IMAGE)" "$(BUILD_CONTEXT)"
	container_id=$$($(CONTAINER_ENGINE) create "$(E2E_IMAGE)" true) && \
		$(CONTAINER_ENGINE) cp "$$container_id:/build/e2e/." "$(STAGE_OUTPUT)/e2e/" && \
		$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	rm -f ../tests/e2e/public/enclave-sw.js ../tests/e2e/public/register.js
	rm -rf ../tests/e2e/public/xwing
	mv "$(STAGE_OUTPUT)/e2e/enclave-sw.js" ../tests/e2e/public/enclave-sw.js
	mv "$(STAGE_OUTPUT)/e2e/register.js" ../tests/e2e/public/register.js
	mv "$(STAGE_OUTPUT)/e2e/xwing" ../tests/e2e/public/xwing
	rmdir "$(STAGE_OUTPUT)/e2e"
	@echo "StageX E2E assets complete"

clean-e2e:
	rm -f ../tests/e2e/public/enclave-sw.js ../tests/e2e/public/register.js
	rm -rf ../tests/e2e/public/xwing

clean: clean-e2e
	rm -rf dist wasm-pkg "$(STAGE_OUTPUT)"
