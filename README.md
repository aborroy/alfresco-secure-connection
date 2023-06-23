# alfresco-secure-connection
> Alfresco Secure Connection provides (m)TLS configuration between Alfresco Services

## Description

This project uses [Alfresco SSL Generator](https://github.com/alfresco/alfresco-ssl-generator) to generate certificates and keystores required to set up (m)TLS connections between Alfresco Services.

Sample Docker Compose template is provided in [docker](docker) folder.

**NOTE** You may use your own software or PKI infrastructure to create CA and certificates, but configuration related to keystore type and certificate alias should be followed as described in this project.

The following points are describing the process to configure secure connections in ACS stack:

* Generate a self-signed CA using [Alfresco SSL Generator](https://github.com/alfresco/alfresco-ssl-generator)
* Generate certificates, keystores and truststores for Postgres, Repository, Transform, Search and Proxy using [Alfresco SSL Generator](https://github.com/alfresco/alfresco-ssl-generator)
* Apply configuration settings to Docker Compose template
* Extend Docker Images to apply additional configuration settings

## CA

Before moving on with services configuration, a working CA is required. In this project, a self-signed CA is generated.

Let's start by cloning the **Alfresco SSL Generator** project.

```
$ git clone git@github.com:Alfresco/alfresco-ssl-generator.git
```

This project is using *Linux/Mac OS* version of the generator, when using a *Windows* host `ssl-tool-win` folder must be selected.

```
$ cd alfresco-ssl-generator/ssl-tool
```

Run the following command to create a new CA certificate with RSA 2048 bits (minimum recommended) and 2 years (730 days) of validity.

```
$ ./run_ca.sh -keysize 2048 -keystorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Custom Alfresco CA" \
-servername localhost -validityduration 730
```

Copy CA public certificate `ca.cert.pem` to Docker Compose `keystore` folder.

```
$ cp ca/certs/ca.cert.pem ../../docker/keystore/ca

$ chmod 0600 ../../docker/keystore/ca/*
```

## Postgres DB

Create a certificate for `postgres` service using the CA generated, with RSA 2048 bits and keystore type `PKCS12`. Since `JKS` and `JCEKS` are also supported keystore types, from *Java 9* using the standard `PKCS12` type is recommended.

>> Despite Postgres is not accepting keystore configuration, just only certificates, `PKCS12` keystore is generated using Alfresco SSL Generator. This tool doesn't support the generation of certificates without packaging them on a keystore.

```
$ ./run_additional.sh -servicename postgres -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype PKCS12 -keystorepass kT9X6oe68t -truststoretype PKCS12 -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Postgres" \
-servername postgres -alfrescoformat current
```

Copy public certificate `postgres.cer` and private certificate `postgres.key` to Docker Compose `keystore` folder. Note that `kT9X6oe68t` is the password selected to protect the private key.

```
$ cp certificates/postgres.cer ../../docker/keystore/postgres

$ cp certificates/postgres.key ../../docker/keystore/postgres

$ chmod 0600 ../../docker/keystore/postgres/*
```

## Alfresco Repository (DB connection)

Create a certificate for `alfresco` service using the CA generated, with RSA 2048 bits and keystore type `PKCS12`.

```
$ ./run_additional.sh -servicename alfresco -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype PKCS12 -keystorepass kT9X6oe68t -truststoretype PKCS12 -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Alfresco" \
-servername alfresco -alfrescoformat current
```

Copy public certificate `alfresco.cer` and private certificate `alfresco.key` to Docker Compose `keystore` folder, as `postgres` JDBC client is only supporting TLS configuration using certificates instead of keystores.

```
$ cp certificates/alfresco.cer ../../docker/keystore/alfresco

$ cp certificates/alfresco.key ../../docker/keystore/alfresco

$ chmod 0600 ../../docker/keystore/alfresco/*
```

Since `postgres` JDBC client is accepting only a PKCS8 certificate, convert the private key to this format. Encryption password is `kT9X6oe68t`, as specified in the previous command.

```
$ openssl pkcs8 -topk8 -inform PEM -in ../../docker/keystore/alfresco/alfresco.key -outform DER \
-out ../../docker/keystore/alfresco/alfresco.pk8 -v1 PBE-MD5-DES
```

## Secure connection between Alfresco Repository and Postgres

Once certificates are available, secure connection configuration can be applied to both services.

TLS configuration for Postgres is available in [docker/config/postgres/ssl_pg_hba.conf](docker/config/postgres/ssl_pg_hba.conf) file.

```
local       all             all               trust
local       replication     all               trust

hostnossl   all             all   0.0.0.0/0   reject
hostnossl   all             all   ::/0        reject
hostssl     all             all   0.0.0.0/0   scram-sha-256 clientcert=verify-ca
hostssl     all             all   ::/0        scram-sha-256 clientcert=verify-ca
```

This postgres configuration accepts only TLS connections using SHA-256 for the credentials and verifying client certificate is issued by a given CA. In addition to the `hba_file`, enabling SSL and configuring CA public certificate and public + private postgres certificate can be done in `docker-compose.yml`.

```
  postgres:
    image: postgres:14.4
    environment:
      POSTGRES_PASSWORD: "alfresco"
      POSTGRES_USER: "alfresco"
      POSTGRES_DB: "alfresco"
    command: >-
      postgres 
      -c hba_file=/var/lib/postgresql/ssl_pg_hba.conf
      -c ssl=on
      -c ssl_cert_file=/var/lib/postgresql/postgres.cer
      -c ssl_key_file=/var/lib/postgresql/postgres.key
      -c ssl_ca_file=/var/lib/postgresql/ca.cert.pem
    volumes:
      - ./config/postgres/ssl_pg_hba.conf:/var/lib/postgresql/ssl_pg_hba.conf
      - ./keystore/postgres/postgres.cer:/var/lib/postgresql/postgres.cer
      - ./keystore/postgres/postgres.key:/var/lib/postgresql/postgres.key
      - ./keystore/ca/ca.cert.pem:/var/lib/postgresql/ca.cert.pem
```

>> Securing JDBC connection may be different according to the DB Engine used. Even when using postgres, some other configuration options are available for TLS. Check additional parameters in https://www.postgresql.org/docs/current/libpq-ssl.html

Configuring the JDBC connector in Alfresco Repository can be done mounting CA and alfresco certificates plus modifying JDBC Url connection string.

```
  alfresco:
    environment:
      JAVA_OPTS: >-
        -Ddb.driver=org.postgresql.Driver
        -Ddb.username=alfresco
        -Ddb.password=alfresco
        -Ddb.url="jdbc:postgresql://postgres:5432/alfresco?
            ssl=true&sslmode=verify-ca&
            sslrootcert=/usr/local/tomcat/ca.cert.pem&
            sslcert=/usr/local/tomcat/alfresco.cer&s
            slkey=/usr/local/tomcat/alfresco.pk8&
            sslpassword=kT9X6oe68t"
    volumes:
      - ./keystore/alfresco/alfresco.cer:/usr/local/tomcat/alfresco.cer
      - ./keystore/alfresco/alfresco.pk8:/usr/local/tomcat/alfresco.pk8
      - ./keystore/ca/ca.cert.pem:/usr/local/tomcat/ca.cert.pem
```

From this point, communication between Alfresco Repository and Database is happening using TLS protocol.

## Transform Core AIO

Create a certificate for `transform-core-aio` service using the CA generated, with RSA 2048 bits and keystore type `PKCS12`.

```
$ ./run_additional.sh -servicename transform-core-aio -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype PKCS12 -keystorepass kT9X6oe68t -truststoretype PKCS12 -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Transform Core AIO" \
-servername transform-core-aio -alfrescoformat current
```

Copy `transform-core-aio` generated keystore and truststore to Docker Compose `keystore` folder.

```
$ cp keystores/transform-core-aio/* ../../docker/keystore/tengineAIO
```

Copy also `alfresco` previously generated keystore and truststore to Docker Compose `keystore` folder.

```
$ cp keystores/alfresco/* ../../docker/keystore/alfresco
```

## Secure connection between Alfresco Repository and Transform

Apply mTLS configuration to Transform Service in `docker-compose.yml` mounting keystore and truststore as external volumes.

```
  transform-core-aio:
    image: alfresco/alfresco-transform-core-aio:3.1.0
    environment:
      SERVER_SSL_ENABLED: "true"
      SERVER_SSL_KEY_PASSWORD: "kT9X6oe68t"
      SERVER_SSL_KEY_STORE: "file:/transform-core-aio.keystore"
      SERVER_SSL_KEY_STORE_PASSWORD: "kT9X6oe68t"
      SERVER_SSL_KEY_STORE_TYPE: "PKCS12"
      SERVER_SSL_CLIENT_AUTH: "need"
      SERVER_SSL_TRUST_STORE: "file:/transform-core-aio.truststore"
      SERVER_SSL_TRUST_STORE_PASSWORD: "kT9X6oe68t"
      SERVER_SSL_TRUST_STORE_TYPE: "PKCS12"
      CLIENT_SSL_KEY_STORE: "file:/transform-core-aio.keystore"
      CLIENT_SSL_KEY_STORE_PASSWORD: "kT9X6oe68t"
      CLIENT_SSL_KEY_STORE_TYPE: "PKCS12"
      CLIENT_SSL_TRUST_STORE: "file:/transform-core-aio.truststore"
      CLIENT_SSL_TRUST_STORE_PASSWORD: "kT9X6oe68t"
      CLIENT_SSL_TRUST_STORE_TYPE: "PKCS12"
      CLIENT_SSL_HOSTNAME_VERIFICATION_DISABLED: "false"      
    volumes:
      - ./keystore/tengineAIO/transform-core-aio.keystore:/transform-core-aio.keystore
      - ./keystore/tengineAIO/transform-core-aio.truststore:/transform-core-aio.truststore

```

On the Alfresco Repository part, mount keystore and trustore and set connection values to Transform Service.

```
  alfresco:
    environment:
      JAVA_TOOL_OPTIONS: >-
        -Dencryption.ssl.keystore.type=PKCS12
        -Dencryption.ssl.keystore.location=/usr/local/tomcat/alfresco.keystore
        -Dencryption.ssl.truststore.type=PKCS12
        -Dencryption.ssl.truststore.location=/usr/local/tomcat/alfresco.truststore
        -Dssl-keystore.password=kT9X6oe68t
        -Dssl-truststore.password=kT9X6oe68t        
      JAVA_OPTS: >-
        -DlocalTransform.core-aio.url=https://transform-core-aio:8090/
        -Dhttpclient.config.transform.mTLSEnabled=true
        -Dhttpclient.config.transform.hostnameVerificationDisabled=true
    volumes:
      - ./keystore/alfresco/alfresco.keystore:/usr/local/tomcat/alfresco.keystore
      - ./keystore/alfresco/alfresco.truststore:/usr/local/tomcat/alfresco.truststore
```

From this point, communication between Alfresco Repository and Transform is happening using mTLS protocol.

## Search Services

Create a certificate for `solr6` service using the CA generated, with RSA 2048 bits and keystore type `PKCS12`.

```
$ ./run_additional.sh -servicename solr6 -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype PKCS12 -keystorepass kT9X6oe68t -truststoretype PKCS12 -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Search Service" \
-servername solr6 -alfrescoformat current
```

Copy `solr6` generated keystore and truststore to Docker Compose `keystore` folder.

```
$ cp keystores/solr6/solr6.* ../../docker/keystore/search
```

## Secure connection between Alfresco Repository and Search Services

Apply mTLS configuration to Search Service in `docker-compose.yml` mounting keystore and truststore as external volumes.

```
  solr6:
    build:
      context: ./search
      args:
        SEARCH_TAG: "2.0.7"
        TRUSTSTORE_TYPE: PKCS12
        KEYSTORE_TYPE: PKCS12
    environment:
      SOLR_ALFRESCO_HOST: "alfresco"
      SOLR_ALFRESCO_PORT: "8443"
      ALFRESCO_SECURE_COMMS: "https"
      SOLR_SOLR_HOST: "solr6"
      SOLR_SOLR_PORT: "8983"
      SOLR_CREATE_ALFRESCO_DEFAULTS: "alfresco,archive"
      SOLR_JAVA_MEM: "-Xms1g -Xmx1g"
      SOLR_SSL_TRUST_STORE: "/opt/alfresco-search-services/keystore/ssl-repo-client.truststore"
      SOLR_SSL_TRUST_STORE_TYPE: "PKCS12"
      SOLR_SSL_KEY_STORE: "/opt/alfresco-search-services/keystore/ssl-repo-client.keystore"
      SOLR_SSL_KEY_STORE_TYPE: "PKCS12"
      SOLR_SSL_NEED_CLIENT_AUTH: "true"
      JAVA_TOOL_OPTIONS: "
          -Dsolr.jetty.truststore.password=kT9X6oe68t
          -Dsolr.jetty.keystore.password=kT9X6oe68t
          -Dssl-keystore.password=kT9X6oe68t
          -Dssl-keystore.aliases=ssl-alfresco-ca,ssl-repo-client
          -Dssl-keystore.ssl-alfresco-ca.password=kT9X6oe68t
          -Dssl-keystore.ssl-repo-client.password=kT9X6oe68t
          -Dssl-truststore.password=kT9X6oe68t
          -Dssl-truststore.aliases=ssl-alfresco-ca,ssl-repo,ssl-repo-client
          -Dssl-truststore.ssl-alfresco-ca.password=kT9X6oe68t
          -Dssl-truststore.ssl-repo.password=kT9X6oe68t
          -Dssl-truststore.ssl-repo-client.password=kT9X6oe68t
      "
      SOLR_OPTS: "
          -Dsolr.ssl.checkPeerName=false
          -Dsolr.allow.unsafe.resourceloading=true
      "
    volumes:
      - ./keystore/search/solr6.keystore:/opt/alfresco-search-services/keystore/ssl-repo-client.keystore
      - ./keystore/search/solr6.truststore:/opt/alfresco-search-services/keystore/ssl-repo-client.truststore
```

In addition, default Search Services needs to be extended to apply mTLS values to `alfresco` and `archive` SOLR cores. This extension is described in [search/Dockerfile](search/Dockerfile).

```
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
```

On the Alfresco Repository part, we have mounted keystore and trustore in previous steps. Add also values for mTLS connection to Search Services using Java environment variables.

```
  alfresco:
    build:
      context: ./alfresco
      args:
        ALFRESCO_TAG: "7.4.0.1"
        TRUSTSTORE_TYPE: PKCS12
        TRUSTSTORE_PASS: kT9X6oe68t
        KEYSTORE_TYPE: PKCS12
        KEYSTORE_PASS: kT9X6oe68t
    environment:
      JAVA_TOOL_OPTIONS: >-
        -Dencryption.ssl.keystore.type=PKCS12
        -Dencryption.ssl.keystore.location=/usr/local/tomcat/alfresco.keystore
        -Dencryption.ssl.truststore.type=PKCS12
        -Dencryption.ssl.truststore.location=/usr/local/tomcat/alfresco.truststore
        -Dssl-keystore.password=kT9X6oe68t
        -Dssl-truststore.password=kT9X6oe68t        
      JAVA_OPTS: >-
        -Dsolr.host=solr6
        -Dsolr.port=8983
        -Dsolr.http.connection.timeout=1000
        -Dsolr.secureComms=https
        -Dsolr.port.ssl=8983
        -Dsolr.base.url=/solr
        -Dindex.subsystem.name=solr6
    volumes:
      - ./keystore/alfresco/alfresco.keystore:/usr/local/tomcat/alfresco.keystore
      - ./keystore/alfresco/alfresco.truststore:/usr/local/tomcat/alfresco.truststore
```

Additionally, Alfresco Repository Docker Image should be extended to expose mTLS 8443 port in Apache Tomcat. This extension is defined in [alfresco/Dockerfile](alfresco/Dockerfile)


```
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
```   

From this point, communication between Alfresco Repository and Search Services is happening using mTLS protocol.

## ActiveMQ

Create a certificate for `activemq` service using the CA generated, with RSA 2048 bits and keystore type `JKS`. In this case `PKCS12` keystore type is not an option, since it's not supported by ActiveMQ TLS configuration.

```
$ ./run_additional.sh -servicename activemq -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype JKS -keystorepass kT9X6oe68t -truststoretype JKS -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=ActiveMQ" \
-servername activemq -alfrescoformat current
```

Copy `activemq` generated keystore and truststore to Docker Compose `keystore` folder.

```
$ cp keystores/activemq/activemq.* ../../docker/keystore/activemq
```

## Secure connection between Alfresco Repository and ActiveMQ

Apply mTLS configuration to ActiveMQ in `docker-compose.yml` mounting keystore and truststore as external volumes.

```
  activemq:
    build:
      context: ./activemq
      args:
        ACTIVEMQ_TAG: "5.17.1-jre11-rockylinux8"
        TRUSTSTORE_PASS: "kT9X6oe68t"
        KEYSTORE_PASS: "kT9X6oe68t"
    volumes:
      - ./keystore/activemq/activemq.keystore:/opt/activemq/broker.ks
      - ./keystore/activemq/activemq.truststore:/opt/activemq/client-truststore.jks
```      

In addition, default ActiveMQ needs to be extended to apply mTLS values. This extension is described in [activemq/Dockerfile](activemq/Dockerfile).

```
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
```

On the Alfresco Repository part, we have mounted keystore and trustore in previous steps. Add also values for mTLS connection to Search Services using Java environment variables.

```
alfresco:
    environment:
      JAVA_OPTS: >-
        -Dmessaging.broker.url="failover:(ssl://activemq:61616)?timeout=3000&jms.useCompression=true"
        -Djavax.net.ssl.keyStore=/usr/local/tomcat/alfresco.keystore
        -Djavax.net.ssl.keyStorePassword=kT9X6oe68t
        -Djavax.net.ssl.keyStoreType=PKCS12
        -Djavax.net.ssl.trustStore=/usr/local/tomcat/alfresco.truststore
        -Djavax.net.ssl.trustStorePassword=kT9X6oe68t
        -Djavax.net.ssl.trustStoreType=PKCS12
        -Djdk.tls.client.protocols=TLSv1.2
    volumes:
      - ./keystore/alfresco/alfresco.keystore:/usr/local/tomcat/alfresco.keystore
      - ./keystore/alfresco/alfresco.truststore:/usr/local/tomcat/alfresco.truststore
```

From this point, communication between Alfresco Repository and ActiveMQ is happening using mTLS protocol.

## WebProxy

Create a certificate for `proxy` service using the CA generated, with RSA 2048 bits and keystore type `PKCS12`.

```
$ ./run_additional.sh -servicename localhost -rootcapass kT9X6oe68t -keysize 2048 \
-keystoretype PKCS12 -keystorepass kT9X6oe68t -truststoretype PKCS12 -truststorepass kT9X6oe68t \
-certdname "/C=GB/ST=UK/L=Maidenhead/O=Alfresco Software Ltd./OU=Unknown/CN=Web Proxy" \
-servername localhost -alfrescoformat current
```

Copy public certificate `localhost.cer` and private certificate `localhost.key` to Docker Compose `keystore` folder.

```
$ cp certificates/localhost.cer ../../docker/keystore/webproxy
$ cp certificates/localhost.key ../../docker/keystore/webproxy
```

## Secure connection to Web Proxy

Apply TLS configuration to Web Proxy in `docker-compose.yml` mounting certificates as external volumes and exposing default HTTPs port.

```  
  proxy:
      image: nginx:stable-alpine
      volumes:
          - ./config/nginx/nginx.conf:/etc/nginx/nginx.conf
          - ./keystore/webproxy/localhost.cer:/etc/nginx/localhost.cer
          - ./keystore/webproxy/localhost.key:/etc/nginx/localhost.key
      ports:
          - "443:443"
```

Nginx configuration file in [config/nginx/nginx.conf](config/nginx/nginx.conf) should include also SSL settings.

```
http {
    server {

        listen *:443 ssl;

        
        ssl_certificate             /etc/nginx/localhost.cer;
        ssl_certificate_key         /etc/nginx/localhost.key;
        ssl_prefer_server_ciphers   on;
        ssl_protocols               TLSv1.2 TLSv1.3;

        ...
        
    }
}
```
Additionally, Alfresco Share Docker Image should be extended to use HTTPs protocol in Apache Tomcat when invoked from a proxy. This extension is defined in [share/Dockerfile](share/Dockerfile)

```
ARG SHARE_TAG
FROM docker.io/alfresco/alfresco-share:${SHARE_TAG}

RUN sed -i '/Connector port="8080"/a scheme="https" secure="true"' /usr/local/tomcat/conf/server.xml && \
    sed -i "/Connector port=\"8080\"/a proxyName=\"localhost\" proxyPort=\"443\"" /usr/local/tomcat/conf/server.xml
```

Alfresco Repository and Alfresco Share environment variables in Docker Compose need to be modified to use TLS.

```
  alfresco:
    environment:
      JAVA_OPTS: >-
        -Dalfresco.host=localhost
        -Dalfresco.port=443
        -Dapi-explorer.url=https://localhost:443/api-explorer
        -Dalfresco.protocol=https 
        -Dshare.host=localhost
        -Dshare.port=443
        -Dshare.protocol=https 
        -Daos.baseUrlOverwrite=https://localhost/alfresco/aos 

  share:
    build:
      context: ./share
      args:
        SHARE_TAG: "7.4.0.1"    
    environment:
      CSRF_FILTER_REFERER: "https://localhost:443/.*"
      CSRF_FILTER_ORIGIN: "https://localhost:443"
      JAVA_OPTS: >-
        -Dalfresco.context=alfresco
        -Dalfresco.protocol=https
```

From this point, communication to Alfresco external services is happening using TLS protocol.
