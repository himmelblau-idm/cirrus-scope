all:
	cargo build --release

build-tests:
	$(MAKE) -C tests

test: build-tests
	$(MAKE) -C tests test

clean:
	cargo clean
	$(MAKE) -C tests clean

PLATFORM := $(shell grep '^ID=' /etc/os-release | awk -F= '{ print $$2 }' | tr -d '"')

DOCKER := $(shell command -v podman || command -v docker)

.packaging:
	mkdir -p ./packaging/

deb: .packaging
	for v in ubuntu22.04 ubuntu24.04 debian12; do \
		echo "Building Ubuntu $$v packages"; \
		$(DOCKER) build -t cirrus-scope-$$v-build -f images/deb/Dockerfile.$$v .; \
		$(DOCKER) run --rm --security-opt label=disable -it -v ./:/cirrus-scope cirrus-scope-$$v-build; \
		mv ./target/debian/*.deb ./packaging/; \
	done

rpm: .packaging
	for v in rocky8 rocky9 sle15sp6 tumbleweed rawhide fedora41; do \
		echo "Building $$v RPM packages"; \
		$(DOCKER) build -t cirrus-scope-$$v-build -f images/rpm/Dockerfile.$$v .; \
		$(DOCKER) run --rm --security-opt label=disable -it -v ./:/cirrus-scope cirrus-scope-$$v-build; \
		for file in ./target/generate-rpm/*.rpm; do \
			mv "$$file" "$${file%.rpm}-$$v.rpm"; \
		done; \
		mv ./target/generate-rpm/*.rpm ./packaging/; \
	done
	rpmsign --addsign ./packaging/*.rpm

package: deb rpm
	ls ./packaging/
