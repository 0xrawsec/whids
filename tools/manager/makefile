TEST=$(GOPATH)/test
MAIN_BASEN_SRC=whids-man
RELEASE=$(GOPATH)/release/$(MAIN_BASEN_SRC)
VERSION=1.0
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
	$(MAKE) compile

test: all
	cp -r $(RELEASE) $(TEST)


init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/windows
	mkdir -p $(RELEASE)/linux
	mkdir -p $(RELEASE)/darwin

install:
	go install $(OPTS) $(MAIN_BASEN_SRC).go

compile:
	$(MAKE) windows
	$(MAKE) linux
	$(MAKE) darwin

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-386.exe *.go
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64.exe *.go
	cp -r conf $(RELEASE)/windows
	cd $(RELEASE)/windows; shasum -a 256 * > sha256.txt
	cd $(RELEASE)/windows; tar -cvzf ../windows-$(VERSION).tar.gz *

linux:
	GOARCH=386 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-v$(VERSION)-386 *.go
	GOARCH=amd64 GOOS=linux go build $(OPTS) -o $(RELEASE)/linux/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64 *.go
	cp -r conf $(RELEASE)/linux
	cd $(RELEASE)/linux; shasum -a 256 * > sha256.txt
	cd $(RELEASE)/linux; tar -cvzf ../linux-$(VERSION).tar.gz *

darwin:
	GOARCH=386 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-v$(VERSION)-386 *.go
	GOARCH=amd64 GOOS=darwin go build $(OPTS) -o $(RELEASE)/darwin/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64 *.go
	cp -r conf $(RELEASE)/darwin
	cd $(RELEASE)/darwin; shasum -a 256 * > sha256.txt
	cd $(RELEASE)/darwin; tar -cvzf ../darwin-$(VERSION).tar.gz *

buildversion:
	printf "package main\n\nconst(\n    version=\"$(VERSION)\"\n    commitID=\"$(COMMITID)\"\n)\n" > version.go

clean:
	rm -rf $(RELEASE)/*
