ARG ALFRESCO_TAG
FROM docker.io/alfresco/alfresco-content-repository-community:${ALFRESCO_TAG}

ARG TOMCAT_DIR=/usr/local/tomcat

USER root

ARG TRUSTSTORE_TYPE
ARG TRUSTSTORE_PASS
ARG KEYSTORE_TYPE
ARG KEYSTORE_PASS

ENV TRUSTSTORE_TYPE=$TRUSTSTORE_TYPE \
    TRUSTSTORE_PASS=$TRUSTSTORE_PASS \
    KEYSTORE_TYPE=$KEYSTORE_TYPE \
    KEYSTORE_PASS=$KEYSTORE_PASS

RUN sed -i "s/\
[[:space:]]\+<\/Engine>/\n\
        <\/Engine>\n\
        <Connector port=\"8443\" protocol=\"HTTP\/1.1\"\n\
            connectionTimeout=\"20000\"\n\
            SSLEnabled=\"true\" maxThreads=\"150\" scheme=\"https\" clientAuth=\"want\" sslProtocol=\"TLS\" sslEnabledProtocols=\"TLSv1.2\"\n\
            keystoreFile=\"\/usr\/local\/tomcat\/alfresco.keystore\"\n\
            keystorePass=\"${KEYSTORE_PASS}\" keystoreType=\"${KEYSTORE_TYPE}\" secure=\"true\"\n\
            truststoreFile=\"\/usr\/local\/tomcat\/alfresco.truststore\"\n\
            truststorePass=\"${TRUSTSTORE_PASS}\" truststoreType=\"${TRUSTSTORE_TYPE}\">\n\
        <\/Connector>/g" ${TOMCAT_DIR}/conf/server.xml;

USER alfresco