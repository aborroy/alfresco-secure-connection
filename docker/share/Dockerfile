ARG SHARE_TAG
FROM docker.io/alfresco/alfresco-share:${SHARE_TAG}

RUN sed -i '/Connector port="8080"/a scheme="https" secure="true"' /usr/local/tomcat/conf/server.xml && \
    sed -i "/Connector port=\"8080\"/a proxyName=\"localhost\" proxyPort=\"443\"" /usr/local/tomcat/conf/server.xml
