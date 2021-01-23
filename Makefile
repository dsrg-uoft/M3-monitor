.PHONY: debug install clean help

CXX = g++
CONF = release
BUILD_DIR = ../build/linux-x86_64-normal-server-$(CONF)
BUILD_JVM = $(BUILD_DIR)/images/j2sdk-image

sigve: sigve.cpp
	$(CXX) -O3 -std=c++11 -pthread sigve.cpp -o sigve

debug: sigve.cpp
	$(CXX) -g -O0 -std=c++11 -pthread sigve.cpp -o sigve

install:
	mv sigve $(BUILD_JVM)/bin

clean:
	rm -f sigve

help:
	@echo
	@echo 'sigve Makefile'
	@echo '=============='
	@echo 'commands:'
	@echo '- sigve (default): build sigve monitor'
	@echo '- install: put it in JVM image (set CONF or default to release)'
	@echo '- clean: so fresh and so clean'
	@echo '- help: show this help'
	@echo
