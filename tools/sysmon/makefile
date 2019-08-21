RELEASE=$(GOPATH)/release/sysmon
TEST=$(GOPATH)/test
WGET=/usr/bin/wget
STRINGS=/usr/bin/strings

all: clean
	mkdir -p $(RELEASE)
	$(MAKE) download
	$(MAKE) cpconfig
	$(MAKE) cpsysmon
	$(MAKE) finish

download:
	$(WGET) https://live.sysinternals.com/Sysmon64.exe
	
#test: clean
test:
	echo "We do nothing"
	#mkdir -p $(RELEASE)
	#$(MAKE) cpconfig
	#$(MAKE) finish
	#cp -r $(RELEASE) $(TEST)

cpconfig:
	cp -r v* $(RELEASE)
	
cpsysmon: 
	$(eval major := $(shell $(STRINGS) -e l Sysmon64.exe | grep -A 1 ProductVersion | tail -n 1 | cut -d '.' -f 1))
	$(STRINGS) -e l Sysmon64.exe | grep -A 1 ProductVersion | tail -n 1 > $(RELEASE)/v$(major)/version.txt
	mv Sysmon64.exe $(RELEASE)/v$(major)

finish:
	cd $(RELEASE); find -type f -not -name 'sha256.txt' | xargs shasum -a 256 > sha256.txt

clean:
	rm -rf $(RELEASE)/*