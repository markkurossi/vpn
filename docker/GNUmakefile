
all:
	@echo "Targets: build shell"

build:
	docker image build -t builder:1.0 .

shell:
	docker run -v $(CURDIR)/../../../..:/root/go/src -it builder:1.0  bash
