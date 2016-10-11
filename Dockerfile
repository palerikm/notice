FROM debian:stretch
MAINTAINER Pål-Erik Martinsen <palmarti@cisco.com>

# XXX: Workaround for https://github.com/docker/docker/issues/6345
RUN ln -s -f /bin/true /usr/bin/chfn

#RUN apt-get update && \
#    DEBIAN_FRONTEND=noninteractive \
#    apt-get install -y \
#            ca-certificates \
#            git \
#            build-essential \
#            cmake\
#            libssl-dev \
#            zlib1g-dev\
#            procps \
#            --no-install-recommends

ADD . notice

RUN \
 buildDeps='build-essential zlib1g-dev git cmake';set -x &&\
 apt-get update && apt-get install -y ca.certificates libssl-dev libbsd-dev $buildDeps  --no-install-recommends &&\
 rm -rf /var/lib/apt/lists/* &&\
 #git clone http://github.com/NATTools/stunserver.git &&\
 cd notice &&\
 rm -rf build &&\
 ./build.sh &&\
 make -C build install &&\
 #cd .. && rm -rf stunserver &&\
 #apt-get purge -y --auto-remove $buildDeps
 apt-get purge -y --auto-remove $buildDeps


EXPOSE 5061 5061/tcp
CMD ["/bin/sh", "notice/build/dist/bin/notice"]
ENTRYPOINT ["notice/build/dist/bin/notice"]
