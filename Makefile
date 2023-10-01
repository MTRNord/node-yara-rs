BASE=$(shell pwd)
OSNAME=$(shell uname)

ifeq ($(OSNAME),Darwin)
CFLAGS  += -I/usr/local/include/node
CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
endif

ifeq ($(findstring arm64,$(CFLAGS)),arm64)
CFGOPTS += --host=aarch64-apple-darwin
endif

YARA?=4.3.2

libyara: yara

clean:
	-rm -rf $(BASE)/build/yara
	-rm -rf $(BASE)/deps/yara-$(YARA)
	cargo clean

yara: clean
	echo $(CFLAGS)
	echo $(LDFLAGS)
	echo $(CC)
	test -f $(BASE)/deps/yara-$(YARA).tar.gz || curl -L -k https://github.com/VirusTotal/yara/archive/v$(YARA).tar.gz > $(BASE)/deps/yara-$(YARA).tar.gz
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz
	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && \
			CFLAGS="$(CFLAGS)" \
			LDFLAGS="$(LDFLAGS)" \
			./configure \
					$(CFGOPTS) \
					--enable-static \
					--disable-shared \
					--with-pic \
					--prefix=$(BASE)/build/yara
	cd $(BASE)/deps/yara-$(YARA) && make
	cd $(BASE)/deps/yara-$(YARA) && make install

build: yara
	yarn build

debug_results: build
	cargo rustc --release -- --print link-args
	ldd *.node

test: build
	yarn run test