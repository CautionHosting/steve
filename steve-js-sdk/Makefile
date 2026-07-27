CONTAINER_ENGINE ?= docker

.PHONY: build clean

build:
	$(CONTAINER_ENGINE) build --platform linux/amd64 -f Containerfile -t enclave-service-worker-build .. --no-cache
	container_id=$$($(CONTAINER_ENGINE) create enclave-service-worker-build true) && \
	mkdir -p dist && \
	$(CONTAINER_ENGINE) cp "$$container_id:/build/dist/." dist/ && \
	$(CONTAINER_ENGINE) rm "$$container_id" > /dev/null
	@echo "Build complete:"
	@ls -la dist/

clean:
	rm -rf dist/
