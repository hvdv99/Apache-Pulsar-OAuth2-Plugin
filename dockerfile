FROM maven:3.9.0-eclipse-temurin-19 AS builder

#Certs required for building on a CGI laptop
COPY ZscalerRootCertificate-2048-SHA256.der $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der
RUN $JAVA_HOME/bin/keytool -noprompt -storepass changeit -import -trustcacerts -alias zscalerrootca -file $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der -keystore $JAVA_HOME/lib/security/cacerts

WORKDIR /pulsar

#Copy and build the Apache Pulsar oAuth2 authorisation plugin
COPY pulsar_oauth2 /pulsar/pulsar_oauth2
RUN cd pulsar_oauth2 && \
   mvn clean install

FROM apachepulsar/pulsar:4.0.3

USER root
#Certs required for building on a CGI laptop
COPY ZscalerRootCertificate-2048-SHA256.der $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der
RUN $JAVA_HOME/bin/keytool -noprompt -storepass changeit -import -trustcacerts -alias zscalerrootca -file $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der -keystore $JAVA_HOME/lib/security/cacerts

COPY --from=builder pulsar/pulsar_oauth2/target/pulsaroauth2-1.0-SNAPSHOT.jar /pulsar/lib

USER 10000

CMD ["bin/pulsar", "standalone"]