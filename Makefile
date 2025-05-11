.PHONY: preview build

preview:
	hugo server --renderToMemory --buildExpired --buildFuture --buildDrafts --baseURL "http://localhost:1313"

build:
	hugo --minify
