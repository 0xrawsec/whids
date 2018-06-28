RELEASE=$(GOPATH)/release
MAIN_BASEN_SRC=whids
VERSION=1.3
COMMITID=$(shell git rev-parse HEAD)

# Strips symbols and dwarf to make binary smaller
OPTS=-ldflags "-s -w"
ifdef DEBUG
	OPTS=
endif

all:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) buildversion
	$(MAKE) additional
	$(MAKE) compile

init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/windows

install:
	go install $(OPTS) $(MAIN_BASEN_SRC).go

compile:windows

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-386.exe *.go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64.exe *.go
	cd $(RELEASE)/windows; shasum -a 256 * > sha256.txt
	cd $(RELEASE)/windows; tar -cvzf ../windows-$(VERSION).tar.gz *

buildversion:
	printf "package main\n\nconst(\n    version=\"$(VERSION)\"\n    commitID=\"$(COMMITID)\"\n)\n" > version.go

additional:
	sed -E "s/set VERSION=.*?/set VERSION=$(VERSION)/" install.bat > $(RELEASE)/windows/install.bat
	

clean:
	rm -rf $(RELEASE)/*
