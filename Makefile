APP_NAME=dns-watch
IMG_ID=$(shell dd if=/dev/urandom bs=1k count=1 2> /dev/null | LC_CTYPE=C tr -cd "a-z0-9" | cut -c 1-22)

.PHONY: clean

build: target/x86_64-unknown-linux-musl/release/$(APP_NAME).gpg target/x86_64-unknown-linux-musl/release/$(APP_NAME).sha256

clean:
	cargo clean

target/x86_64-unknown-linux-musl/release/$(APP_NAME): Cargo.lock Cargo.toml src/main.rs
	mkdir -p target/x86_64-unknown-linux-musl/release
	docker build --tag $(APP_NAME):latest .
	docker run --rm $(APP_NAME):latest cat /home/rust/src/target/x86_64-unknown-linux-musl/release/$(APP_NAME) \
		> target/x86_64-unknown-linux-musl/release/$(APP_NAME)

%.gpg: %
	gpg --yes -a --output $@ --detach-sig $<

%.sha256: %
	cat $< | openssl dgst -sha256 > $@
