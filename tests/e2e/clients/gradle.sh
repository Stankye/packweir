#!/bin/sh
set -eu
mkdir /tmp/project
cd /tmp/project
printf "rootProject.name = 'packweir-client-fixture'\n" > settings.gradle
cat > build.gradle <<'EOF'
repositories {
    maven {
        url = uri('http://gateway:8080/r/maven/')
        allowInsecureProtocol = true
        credentials { username = 'fixture'; password = System.getenv('PACKWEIR_READ_TOKEN') }
        authentication { basic(BasicAuthentication) }
    }
}
configurations { fixture }
dependencies { fixture 'dev.packweir:fixture:1.0.0' }
tasks.register('checkFixture') {
    doLast {
        def artifact = configurations.fixture.singleFile
        def jar = new java.util.jar.JarFile(artifact)
        try { assert jar.getInputStream(jar.getJarEntry('fixture.txt')).getText('UTF-8') == 'packweir fixture\n' }
        finally { jar.close() }
    }
}
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
gradle --version
echo 'PACKWEIR_CLIENT_VERSION_END'
gradle --no-daemon --console=plain --gradle-user-home=/tmp/gradle-cache checkFixture
