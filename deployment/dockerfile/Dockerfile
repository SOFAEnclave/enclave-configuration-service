FROM antkubetee/kubetee-dev-ubuntu18.04-grpc-sgx-ssl:1.0

LABEL maintainer="Junxian Xiao <junxian.xjx@antfin.com>"

ARG HOMEDIR=/root

USER root
COPY ./buildout/* ${HOMEDIR}/
COPY ./bin/*.sh /usr/bin/
COPY ./conf/* /etc/kubetee/
COPY ./certs/* /etc/certs/

USER root
WORKDIR ${HOMEDIR}
ENTRYPOINT ["/usr/bin/start_service.sh"]
