export GOBIN=$(PWD)/bin

GOPKGS=$(shell go list ./... | grep -v '/vendor/')

.PHONY: test
test:
	@go test -v -i $(GOPKGS)
	@go test -v $(GOPKGS)

.PHONY: revendor
revendor:
	@glide up -v
	@glide-vc --use-lock-file --no-tests --only-code
