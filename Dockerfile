FROM rust:bullseye
LABEL authors="jesse"
COPY ./ .

#ENTRYPOINT ["cargo", "test", "--", "--nocapture"]
ENTRYPOINT ["bash"]
