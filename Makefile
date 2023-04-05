GO111MODULE := on
DOCKER_TAG := $(or ${GIT_TAG_NAME}, latest)

all: pod-mutator

.PHONY: pod-mutator
pod-mutator:
	go build pod-mutator.go
	strip pod-mutator

.PHONY: dockerimages
dockerimages: pod-mutator
	docker build -t mwennrich/pod-mutator:${DOCKER_TAG} .

.PHONY: dockerpush
dockerpush: pod-mutator
	docker push mwennrich/pod-mutator:${DOCKER_TAG}
