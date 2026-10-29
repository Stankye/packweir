#!/bin/sh
set -eu
mkdir -p /tmp/classes /tmp/plugin/META-INF/maven /fixtures/java
javac -cp '/usr/share/maven/lib/*' -d /tmp/classes /tests/java/FixtureMojo.java
cp /tests/java/plugin.xml /tmp/plugin/META-INF/maven/plugin.xml
cp -R /tmp/classes/* /tmp/plugin/
jar --create --date=2020-01-01T00:00:00Z --file /fixtures/java/plugin.jar -C /tmp/plugin .
printf 'packweir fixture\n' > /tmp/classes/fixture.txt
jar --create --date=2020-01-01T00:00:00Z --file /fixtures/java/library.jar -C /tmp/classes fixture.txt
