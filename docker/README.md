# Keystore and Truststore details

The **truststore** is a common file across various components, with only the keystore format differing for `activemq` (JKS). Each truststore includes the public certificate `alfresco.ca` as a Trusted Certificate. The following truststore files are used:

* `activemq/activemq.truststore` (JKS)
* `alfresco/alfresco.truststore` (PKCS12)
* `tengineAIO/transform-core-aio.truststore` (PKCS12)
* `search/solr6.truststore` (PKCS12)

As an example, the `truststore` for Search contains the following information:

```bash
$ keytool -list -v -keystore search/solr6.truststore -storepass kT9X6oe68t -storetype PKCS12

Alias name: alfresco.ca
Entry type: trustedCertEntry
Owner: CN=Custom Alfresco CA, OU=Unknown, O=Alfresco Software Ltd., L=Maidenhead, ST=UK, C=GB
Issuer: CN=Custom Alfresco CA, OU=Unknown, O=Alfresco Software Ltd., L=Maidenhead, ST=UK, C=GB
Certificate fingerprints:
	 SHA256: 94:97:BE:9D:49:85:A1:16:FC:00:93:B8:09:6E:55:E0:5C:BD:45:85:05:F2:95:36:D8:EB:24:C4:23:A2:66:91
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key

Extensions:

BasicConstraints:[
  CA:true
  PathLen: no limit
]

KeyUsage [
  DigitalSignature
  Key_CertSign
  Crl_Sign
]
```

Each **keystore** includes the same Trusted Certificate from the previous truststore (aliased as `ssl.alfresco.ca`) and a private certificate for TLS. For example, examining the certificates for Search:

```bash
$ keytool -list -v -keystore search/solr6.keystore -storepass kT9X6oe68t -storetype PKCS12

Alias name: solr6
Entry type: PrivateKeyEntry
Owner: CN=Search Service, OU=Unknown, O=Alfresco Software Ltd., ST=UK, C=GB
Issuer: CN=Custom Alfresco CA, OU=Unknown, O=Alfresco Software Ltd., L=Maidenhead, ST=UK, C=GB
Certificate fingerprints:
	 SHA256: 9A:B7:B4:59:6A:8F:91:08:92:30:5B:80:D7:E7:50:9D:E9:D7:67:CE:D0:2F:4D:E4:01:A5:2E:29:B4:65:DF:E1
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key

Extensions:

BasicConstraints:[
  CA:false
  PathLen: undefined
]

ExtendedKeyUsages [
  serverAuth
  clientAuth
]

KeyUsage [
  DigitalSignature
  Key_Encipherment
]

NetscapeCertType [
   SSL client
   SSL server
]

SubjectAlternativeName [
  DNSName: solr6
]

*******************************************

Alias name: ssl.alfresco.ca
Entry type: trustedCertEntry
Owner: CN=Custom Alfresco CA, OU=Unknown, O=Alfresco Software Ltd., L=Maidenhead, ST=UK, C=GB
Issuer: CN=Custom Alfresco CA, OU=Unknown, O=Alfresco Software Ltd., L=Maidenhead, ST=UK, C=GB
Certificate fingerprints:
	 SHA256: 94:97:BE:9D:49:85:A1:16:FC:00:93:B8:09:6E:55:E0:5C:BD:45:85:05:F2:95:36:D8:EB:24:C4:23:A2:66:91
Signature algorithm name: SHA256withRSA
Subject Public Key Algorithm: 2048-bit RSA key

Extensions:

BasicConstraints:[
  CA:true
  PathLen: no limit
]

KeyUsage [
  DigitalSignature
  Key_CertSign
  Crl_Sign
]
```
