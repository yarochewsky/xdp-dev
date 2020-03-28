build:
	go build ./

run:
	go run main.go

DOCKER_TEST_DIR = "./docker-test"
DOCKER_TEST_IMG = "xdp-test"

veth:
	bash $(DOCKER_TEST_DIR)/scripts/veth.sh

docker-build:
	docker build -t $(DOCKER_TEST_IMG) $(DOCKER_TEST_DIR)/.

docker-run:
	docker run -it $(DOCKER_TEST_IMG)
