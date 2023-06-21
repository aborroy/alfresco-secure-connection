ARG SEARCH_TAG
FROM docker.io/alfresco/alfresco-search-services:${SEARCH_TAG}

ARG TRUSTSTORE_TYPE
ENV TRUSTSTORE_TYPE $TRUSTSTORE_TYPE
ARG KEYSTORE_TYPE
ENV KEYSTORE_TYPE $KEYSTORE_TYPE

RUN sed -i '/^bash.*/i \
      sed -i "'"s/alfresco.encryption.ssl.keystore.location=.*/alfresco.encryption.ssl.keystore.location=\\\/opt\\\/alfresco-search-services\\\/keystore\\\/ssl-repo-client.keystore/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties && \
      sed -i "'"s/alfresco.encryption.ssl.keystore.passwordFileLocation=.*/alfresco.encryption.ssl.keystore.passwordFileLocation=/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties && \
      sed -i "'"s/alfresco.encryption.ssl.keystore.type=.*/alfresco.encryption.ssl.keystore.type=${KEYSTORE_TYPE}/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties && \
      sed -i "'"s/alfresco.encryption.ssl.truststore.location=.*/alfresco.encryption.ssl.truststore.location=\\\/opt\\\/alfresco-search-services\\\/keystore\\\/ssl-repo-client.truststore/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties && \
      sed -i "'"s/alfresco.encryption.ssl.truststore.passwordFileLocation=.*/alfresco.encryption.ssl.truststore.passwordFileLocation=/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties && \
      sed -i "'"s/alfresco.encryption.ssl.truststore.type=.*/alfresco.encryption.ssl.truststore.type=${TRUSTSTORE_TYPE}/g"'" ${DIST_DIR}/solrhome/templates/rerank/conf/solrcore.properties' \
    ${DIST_DIR}/solr/bin/search_config_setup.sh;