FROM rust:1.49

RUN apt update && apt upgrade -y && apt install -y libssl-dev git libpcsclite-dev
RUN rustup component add rustfmt
RUN mkdir /rustica
COPY proto /tmp/proto
COPY rustica /tmp/rustica
WORKDIR /tmp/rustica

RUN cargo build --release
RUN cp target/release/rustica /rustica/rustica
WORKDIR /rustica

ENTRYPOINT [ "/rustica/rustica" ]