BASE=$(shell pwd)
OSNAME=$(shell uname)

ifeq ($(OSNAME),Darwin)
CFLAGS  += -I/usr/local/include/node
CFLAGS  += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
JANSSON_LDFLAGS += $(LDFLAGS)
endif

ifeq ($(findstring arm64,$(CFLAGS)),arm64)
CFGOPTS += --host=aarch64-apple-darwin
endif

YARA?=4.3.2
JANSSON?=2.13.1

libyara: yara

clean:
	-rm -rf $(BASE)/build/yara
	-rm -rf $(BASE)/deps/yara-$(YARA)
	-rm -rf $(BASE)/build/jansson
	-rm -rf $(BASE)/deps/jansson-$(JANSSON)
	cargo clean

jansson: clean
	echo $(CFLAGS)
	echo $(LDFLAGS)
	echo $(JANSSON_LDFLAGS)
	echo $(CC)
	test -f $(BASE)/deps/jansson-$(JANSSON).tar.gz || curl -L -k https://github.com/akheron/jansson/releases/download/v$(JANSSON)/jansson-$(JANSSON).tar.gz > $(BASE)/deps/jansson-$(JANSSON).tar.gz
	cd $(BASE)/deps && tar -xzvf jansson-$(JANSSON).tar.gz
	cd $(BASE)/deps/jansson-$(JANSSON) && \
			CFLAGS="$(CFLAGS)" \
			LDFLAGS="$(JANSSON_LDFLAGS)" \
			./configure \
					$(CFGOPTS) \
					--enable-static \
					--disable-shared \
					--with-pic \
					--prefix=$(BASE)/build/jansson
	cd $(BASE)/deps/jansson-$(JANSSON) && make
	cd $(BASE)/deps/jansson-$(JANSSON) && make install

yara: clean jansson
	echo $(CFLAGS)
	echo $(LDFLAGS)
	echo $(CC)
	test -f $(BASE)/deps/yara-$(YARA).tar.gz || curl -L -k https://github.com/VirusTotal/yara/archive/v$(YARA).tar.gz > $(BASE)/deps/yara-$(YARA).tar.gz
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz

	# Handle json.c
	mkdir -p $(BASE)/deps/yara-$(YARA)/libyara/modules/json
	echo "Copying json.c into libyara..."
	cp $(BASE)/deps/json.c $(BASE)/deps/yara-$(YARA)/libyara/modules/json/json.c
	@if grep -q "MODULE(json)" "$(BASE)/deps/yara-$(YARA)/libyara/modules/module_list"; then\
		echo "Already added json module to module list...";\
	else\
		echo "MODULE(json)" >> "$(BASE)/deps/yara-$(YARA)/libyara/modules/module_list";\
	fi
	@if grep -q "MODULES += libyara/modules/json/json.c" "$(BASE)/deps/yara-$(YARA)/Makefile.am"; then\
		echo "Already added json module link to Makefile.am...";\
	else\
	    echo "MODULES += libyara/modules/json/json.c" >> "$(BASE)/deps/yara-$(YARA)/Makefile.am";\
	fi

	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && \
			CFLAGS="$(CFLAGS)" \
			LDFLAGS="$(LDFLAGS)" \
			./configure \
					$(CFGOPTS) \
					--enable-cuckoo \
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
	nm build/yara/bin/yara  | grep json
	nm build/yara/lib/libyara.a  | grep json
	nm *.node  | grep json

test: build
	yarn run test