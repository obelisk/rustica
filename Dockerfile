FROM rust:1.56 as builder

RUN apt update && apt upgrade -y && apt install -y git
RUN rustup component add rustfmt
RUN mkdir /rustica
COPY proto /tmp/proto
COPY rustica /tmp/rustica
WORKDIR /tmp/rustica

RUN cargo build --release

from ubuntu as runtime
COPY --from=builder /tmp/rustica/target/release/rustica /rustica
COPY examples/rustica_local_file.toml /etc/rustica/rustica.toml

ENTRYPOINT [ "/rustica" ]
