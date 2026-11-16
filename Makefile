PYTHON ?= python3
CLANG ?= clang-19
export PYTHONPATH := $(CURDIR)/python
ARCHES ?= amd64 arm64 armhf i386 riscv64
FORMATS ?= deb rpm apk arch

.PHONY: test bpf probe deb rpm apk arch packages clean

bpf:
	CLANG=$(CLANG) bash packaging/build-bpf.sh

probe:
	bash packaging/build-probe.sh

test: bpf
	$(PYTHON) -m unittest discover -s tests -v

deb: bpf probe
	@for a in $(ARCHES); do bash packaging/build-deb.sh $$a; done

rpm: bpf probe
	@for a in $(ARCHES); do bash packaging/build-rpm.sh $$a; done

apk: bpf probe
	@for a in $(ARCHES); do bash packaging/build-apk.sh $$a; done

arch: bpf probe
	@for a in $(ARCHES); do bash packaging/build-archpkg.sh $$a; done

packages: bpf probe
	ARCHES="$(ARCHES)" FORMATS="$(FORMATS)" bash packaging/build-all.sh

clean:
	rm -rf dist/bpf dist/probe dist/ker-probe dist/*.deb dist/*.rpm dist/*.apk dist/*.pkg.tar.zst
	find python tests -name '__pycache__' -type d -exec rm -rf {} +

-include Makefile.lab
