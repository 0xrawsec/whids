RELEASE=$(GOPATH)/release
MAIN_BASEN_SRC=whids
VERSION=v1.2

# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) compile

init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/windows

install:
	go install $(OPTS) $(MAIN_BASEN_SRC).go

compile:windows

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-$(VERSION)-386.exe $(MAIN_BASEN_SRC).go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-$(VERSION)-amd64.exe $(MAIN_BASEN_SRC).go
	cd $(RELEASE)/windows; shasum -a 256 * > sha256.txt
	cd $(RELEASE)/windows; tar -cvzf ../windows-$(VERSION).tar.gz *

clean:
	rm -rf $(RELEASE)/*
