ARG DISTRO
ARG VER

FROM ${DISTRO}:${VER} as builder

COPY . .

RUN dnf -y install clang-devel sqlite-devel glibc-devel rpm-build \
	clang-devel.i686 sqlite-devel.i686 glibc-devel.i686

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN source $HOME/.cargo/env && rustup target add i686-unknown-linux-gnu

RUN source $HOME/.cargo/env && \
	cargo build --release --verbose && \
	# device::tests::test_add_peers will fail due to restricted docker env
	# cargo test --release --verbose &&
	cargo install cargo-rpm && \
	cd client && cargo rpm build --verbose && cargo rpm build --target i686-unknown-linux-gnu --verbose && cd .. && \
	cd server && cargo rpm build --verbose && cargo rpm build --target i686-unknown-linux-gnu --verbose && cd ..

FROM scratch

COPY --from=builder /target/i686-unknown-linux-gnu/release/rpmbuild/RPMS/i686/innernet-*.rpm /
COPY --from=builder /target/release/rpmbuild/RPMS/x86_64/innernet-*.rpm /
