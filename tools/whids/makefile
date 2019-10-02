TEST=$(GOPATH)/test
MAIN_BASEN_SRC=whids
RELEASE=$(GOPATH)/release/$(MAIN_BASEN_SRC)
VERSION=1.6.1
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
	$(MAKE) installer
	$(MAKE) sysmon
	$(MAKE) dlrules

test:
	$(MAKE) clean
	$(MAKE) init
	$(MAKE) buildversion
	$(MAKE) compile
	$(MAKE) installer
	$(MAKE) sysmon
	$(MAKE) testrules
	cp -r $(RELEASE) $(TEST)

init:
	mkdir -p $(RELEASE)
	mkdir -p $(RELEASE)/windows

install:
	go install $(OPTS) $(MAIN_BASEN_SRC).go

compile: windows

windows:
	GOARCH=386 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-386.exe ./
	GOARCH=amd64 GOOS=windows go build $(OPTS) -o $(RELEASE)/windows/$(MAIN_BASEN_SRC)-v$(VERSION)-amd64.exe ./
	#cp -r conf $(RELEASE)/windows
	cd $(RELEASE)/windows; find -type f | xargs -I "{}" shasum -a 256 {} >> sha256.txt
	cd $(RELEASE)/windows; tar -cvzf ../$(MAIN_BASEN_SRC)-windows-$(VERSION).tar.gz *

buildversion:
	printf "package main\n\nconst(\n    version=\"$(VERSION)\"\n    commitID=\"$(COMMITID)\"\n)\n" > version.go

installer:
	sed -E "s/set VERSION=.*?/set VERSION=$(VERSION)/" manage.bat > $(RELEASE)/windows/manage.bat

sysmon:
	mv $(RELEASE)/../sysmon $(RELEASE)/windows/

dlrules:
	mkdir $(RELEASE)/windows/rules/
	curl https://raw.githubusercontent.com/0xrawsec/gene-rules/master/compiled.gen > $(RELEASE)/windows/rules/compiled.gen
	curl https://raw.githubusercontent.com/0xrawsec/gene-rules/master/compiled.gen.sha256 > $(RELEASE)/windows/rules/compiled.gen.sha256

testrules:
	mkdir $(RELEASE)/windows/rules/
	cp $(TEST_RULES)/compiled.gen $(RELEASE)/windows/rules/compiled.gen
	cp $(TEST_RULES)/compiled.gen.sha256 $(RELEASE)/windows/rules/compiled.gen.sha256

clean:
	rm -rf $(RELEASE)/*
