ARG DISTRO
ARG VER

FROM ${DISTRO}:${VER} as builder
LABEL stage=innernet-rpm

RUN dnf -y update && \
	dnf -y install clang-devel sqlite-devel glibc-devel rpm-build && \
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

WORKDIR /workdir
COPY . .
RUN rm -rf target

RUN source $HOME/.cargo/env && \
	cargo install cargo-rpm && \
	cargo build --release --verbose && \
	# device::tests::test_add_peers will fail due to restricted docker env
	cargo test --release --verbose -- --skip test_add_peers && \
	cd server && cargo rpm build && \
	cd ../client && cargo rpm build

FROM ${DISTRO}:${VER}
LABEL stage=innernet-rpm

RUN mkdir -p /target/rpm
COPY --from=builder /workdir/target/release/rpmbuild/RPMS/x86_64/innernet-*.rpm /target/rpm/
