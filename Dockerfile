FROM rust:bullseye
LABEL authors="jesse"
COPY ./ .

ENTRYPOINT ["cargo", "run", "--", "--program", "yes"]
