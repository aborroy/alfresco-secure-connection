ARG ACTIVEMQ_TAG
FROM alfresco/alfresco-activemq:${ACTIVEMQ_TAG}

ARG TRUSTSTORE_PASS
ARG KEYSTORE_PASS

ENV TRUSTSTORE_PASS=$TRUSTSTORE_PASS \
    KEYSTORE_PASS=$KEYSTORE_PASS

USER root

RUN sed -i "s/tcp/ssl/g" ${ACTIVEMQ_HOME}/conf/activemq.xml

RUN sed -i "s/\
[[:space:]]\+<\/broker>/\n\
        <sslContext>\n\
          <sslContext keyStore=\"file:\/opt\/activemq\/broker.ks\"\n\
            keyStorePassword=\"${KEYSTORE_PASS}\" \n\
            trustStore=\"file:\/opt\/activemq\/client-truststore.jks\"\n\
            trustStorePassword=\"${TRUSTSTORE_PASS}\"\/>\n\
        <\/sslContext>\n\
        <\/broker>/g" ${ACTIVEMQ_HOME}/conf/activemq.xml

USER ${USERNAME}