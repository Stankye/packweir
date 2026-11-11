#!/bin/sh
set -eu
mkdir /tmp/project
cd /tmp/project
cat > settings.xml <<EOF
<settings><mirrors><mirror><id>packweir-hosted</id><mirrorOf>packweir-hosted-source</mirrorOf><url>http://gateway:8080/r/maven-local/</url></mirror><mirror><id>packweir</id><mirrorOf>*,!packweir-hosted-source</mirrorOf><url>http://gateway:8080/r/maven/</url></mirror></mirrors><servers><server><id>packweir</id><username>fixture</username><password>$PACKWEIR_READ_TOKEN</password></server><server><id>packweir-hosted</id><username>fixture</username><password>$PACKWEIR_READ_TOKEN</password></server></servers></settings>
EOF
cat > pom.xml <<'EOF'
<project><modelVersion>4.0.0</modelVersion><groupId>dev.packweir</groupId><artifactId>client-fixture</artifactId><version>1.0.0</version><repositories><repository><id>packweir-hosted-source</id><url>http://gateway:8080/r/maven-local/</url></repository></repositories><dependencies><dependency><groupId>dev.packweir</groupId><artifactId>fixture</artifactId><version>1.0.0</version></dependency><dependency><groupId>dev.packweir.private</groupId><artifactId>hosted-fixture</artifactId><version>1.0.0</version></dependency></dependencies></project>
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
mvn --version
echo 'PACKWEIR_CLIENT_VERSION_END'
mvn -B -s settings.xml -Dmaven.repo.local=/tmp/m2 dev.packweir:packweir-maven-plugin:1.0.0:check
test -s /tmp/m2/dev/packweir/fixture/1.0.0/fixture-1.0.0.jar
test -s /tmp/m2/dev/packweir/private/hosted-fixture/1.0.0/hosted-fixture-1.0.0.jar
