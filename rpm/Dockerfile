ARG DISTRO
ARG VER
ARG ARCH

FROM ${DISTRO}:${VER} as builder
LABEL stage=innernet-rpm

RUN yum -y update && \
	yum -y install gcc clang-devel sqlite-devel glibc-devel rpm-build && \
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

# Copy RPMs to a temporary directory for better compatibility
RUN mkdir -p /target/rpm && \
    cp -r /workdir/target/release/rpmbuild/RPMS/${ARCH}/* /target/rpm/

FROM ${DISTRO}:${VER}
LABEL stage=innernet-rpm

RUN mkdir -p /target/rpm
COPY --from=builder /target/rpm/ /target/rpm/
