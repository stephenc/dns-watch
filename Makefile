IMG_ID=$(shell dd if=/dev/urandom bs=1k count=1 2> /dev/null | LC_CTYPE=C tr -cd "a-z0-9" | cut -c 1-22)

.PHONY: clean

build: target/x86_64-unknown-linux-musl/release/dns-watch.gpg target/x86_64-unknown-linux-musl/release/dns-watch.sha256

clean:
	cargo clean

target/x86_64-unknown-linux-musl/release/dns-watch: Cargo.lock Cargo.toml src/main.rs
	mkdir -p target/x86_64-unknown-linux-musl/release
	docker build --tag dns-watch:latest .
	docker run --rm dns-watch:latest cat /home/rust/src/target/x86_64-unknown-linux-musl/release/dns-watch \
		> target/x86_64-unknown-linux-musl/release/dns-watch

%.gpg: %
	gpg -a --output $@ --detach-sig $<

%.sha256: %
	cat $< | openssl dgst -sha256 > $@