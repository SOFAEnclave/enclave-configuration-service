FROM antkubetee/kubetee-dev-sgx:2.0-ubuntu20.04-sgx2.17.1

LABEL maintainer="Junxian Xiao <junxian.xjx@antfin.com>"

ARG HOMEDIR=/root

USER root
COPY ./buildout/* ${HOMEDIR}/
COPY ./aecs_instance/bin/*.sh /usr/bin/
COPY ./aecs_instance/etc/kubetee/* /etc/kubetee/
COPY ./aecs_instance/etc/certs/* /etc/certs/

USER root
WORKDIR ${HOMEDIR}
ENTRYPOINT ["/usr/bin/start_service.sh"]
