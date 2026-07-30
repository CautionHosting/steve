CONTAINER_ENGINE ?= docker
BUILD_PLATFORM ?= linux/amd64
BUILD_CONTEXT ?= ..
STAGE_OUTPUT ?= .stagex-output
PRODUCTION_OUTPUT ?= dist
PRODUCTION_NO_CACHE ?= 1

PRODUCTION_IMAGE ?= enclave-service-worker-build
WASM_IMAGE ?= enclave-service-worker-wasm
WASM_TEST_IMAGE ?= enclave-service-worker-wasm-test
E2E_IMAGE ?= enclave-service-worker-e2e

.PHONY: build build-cached build-wasm build-e2e build-test-assets \
	test-wasm clean clean-e2e

build:
	@tmp_root=$${TMPDIR:-/tmp}; \
	while [ "$${tmp_root%/}" != "$$tmp_root" ]; do tmp_root=$${tmp_root%/}; done; \
	case "$$tmp_root" in ""|/) \
		echo "TMPDIR must identify a bounded temporary directory" >&2; exit 2 ;; \
	esac; \
	case "$(PRODUCTION_NO_CACHE)" in 0|1) ;; \
		*) echo "PRODUCTION_NO_CACHE must be exactly 0 or 1" >&2; exit 2 ;; \
	esac; \
	case "$(PRODUCTION_OUTPUT)" in \
		dist) \
			if [ "$(PRODUCTION_NO_CACHE)" != 1 ]; then \
				echo "cache-enabled builds cannot replace dist" >&2; exit 2; \
			fi ;; \
		"$$tmp_root"/*) \
			if [ -e "$(PRODUCTION_OUTPUT)" ]; then \
				echo "temporary PRODUCTION_OUTPUT must not already exist" >&2; \
				exit 2; \
			fi ;; \
		*) \
			echo "PRODUCTION_OUTPUT must be dist or a path below $$tmp_root" >&2; \
			exit 2 ;; \
	esac
	rm -rf "$(STAGE_OUTPUT)/production"
	mkdir -p "$(STAGE_OUTPUT)/production"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target output -t "$(PRODUCTION_IMAGE)" \
		$(if $(filter 1,$(PRODUCTION_NO_CACHE)),--no-cache) "$(BUILD_CONTEXT)"
	container_id=$$($(CONTAINER_ENGINE) create "$(PRODUCTION_IMAGE)" true) && \
			$(CONTAINER_ENGINE) cp "$$container_id:/build/dist/." "$(STAGE_OUTPUT)/production/" && \
			$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	@if [ "$(PRODUCTION_OUTPUT)" = dist ]; then rm -rf dist; fi
	mv "$(STAGE_OUTPUT)/production" "$(PRODUCTION_OUTPUT)"
	@echo "Canonical StageX build complete: $(PRODUCTION_OUTPUT)"
	@ls -la "$(PRODUCTION_OUTPUT)/"

build-cached:
	$(MAKE) build PRODUCTION_NO_CACHE=0 PRODUCTION_OUTPUT="$(PRODUCTION_OUTPUT)"

build-wasm:
	rm -rf "$(STAGE_OUTPUT)/wasm"
	mkdir -p "$(STAGE_OUTPUT)/wasm"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target wasm-output -t "$(WASM_IMAGE)" "$(BUILD_CONTEXT)" --no-cache
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

build-e2e: build-test-assets

build-test-assets:
	rm -rf "$(STAGE_OUTPUT)/test-assets"
	mkdir -p "$(STAGE_OUTPUT)/test-assets"
	$(CONTAINER_ENGINE) build --platform "$(BUILD_PLATFORM)" -f Containerfile \
		--target test-assets-output -t "$(E2E_IMAGE)" "$(BUILD_CONTEXT)"
	container_id=$$($(CONTAINER_ENGINE) create "$(E2E_IMAGE)" true) && \
			$(CONTAINER_ENGINE) cp "$$container_id:/build/test-assets/." \
				"$(STAGE_OUTPUT)/test-assets/" && \
			$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	rm -rf ../tests/e2e/public/generated
	mv "$(STAGE_OUTPUT)/test-assets" ../tests/e2e/public/generated
	@echo "StageX local and Nitro E2E assets complete"

clean-e2e:
	rm -rf ../tests/e2e/public/generated

clean: clean-e2e
	rm -rf dist wasm-pkg "$(STAGE_OUTPUT)"
