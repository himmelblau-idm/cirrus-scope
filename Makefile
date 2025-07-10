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

.submodules:
	git submodule init; git submodule update

.packaging:
	mkdir -p ./packaging/

DEB_TARGETS := ubuntu22.04 ubuntu24.04 debian12
RPM_TARGETS := rocky8 rocky9 sle15sp6 tumbleweed rawhide fedora41

.PHONY: package deb rpm $(DEB_TARGETS) $(RPM_TARGETS)

package: deb rpm
	ls ./packaging/

deb: $(DEB_TARGETS)

rpm: $(RPM_TARGETS)
	rpmsign --addsign ./packaging/*.rpm

$(DEB_TARGETS): %: .packaging .submodules
	@echo "Building Ubuntu $@ packages"
	mkdir -p target/$@
	$(DOCKER) build -t cirrus-scope-$@-build -f images/deb/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/cirrus-scope \
		-v $(CURDIR)/target/$@:/cirrus-scope/target \
		cirrus-scope-$@-build
	mv ./target/$@/debian/*.deb ./packaging/

$(RPM_TARGETS): %: .packaging .submodules
	@echo "Building $@ RPM packages"
	mkdir -p target/$@
	$(DOCKER) build -t cirrus-scope-$@-build -f images/rpm/Dockerfile.$@ .
	$(DOCKER) run --rm --security-opt label=disable -it \
		-v $(CURDIR):/cirrus-scope \
		-v $(CURDIR)/target/$@:/cirrus-scope/target \
		cirrus-scope-$@-build
	for file in ./target/$@/generate-rpm/*.rpm; do \
		mv "$$file" "$${file%.rpm}-$@.rpm"; \
	done
	mv ./target/$@/generate-rpm/*.rpm ./packaging/
