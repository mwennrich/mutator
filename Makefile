GO111MODULE := on
DOCKER_TAG := $(or ${GIT_TAG_NAME}, latest)

all: mutator

.PHONY: mutator
mutator:
	go build mutator.go
	strip mutator

.PHONY: dockerimages
dockerimages:
	docker build -t mwennrich/mutator:${DOCKER_TAG} .

.PHONY: dockerpush
dockerpush:
	docker push mwennrich/mutator:${DOCKER_TAG}
