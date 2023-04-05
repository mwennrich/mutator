GO111MODULE := on
DOCKER_TAG := $(or ${GIT_TAG_NAME}, latest)

all: general-mutator

.PHONY: general-mutator
general-mutator:
	go build general-mutator.go
	strip general-mutator

.PHONY: dockerimages
dockerimages: general-mutator
	docker build -t mwennrich/general-mutator:${DOCKER_TAG} .

.PHONY: dockerpush
dockerpush: general-mutator
	docker push mwennrich/general-mutator:${DOCKER_TAG}
