#!/bin/sh
set -eu
mkdir /tmp/hosted-publish
cd /tmp/hosted-publish
printf "rootProject.name = 'hosted-fixture'\n" > settings.gradle
cat > build.gradle <<'EOF'
plugins { id 'maven-publish' }
publishing {
    publications {
        fixture(MavenPublication) {
            groupId = 'dev.packweir.private'
            artifactId = 'hosted-fixture'
            version = '1.0.0'
            artifact('/fixtures/java/library.jar') { extension = 'jar' }
            pom {
                name = 'Packweir hosted qualification fixture'
                description = 'Local publication & quarantine qualification'
            }
        }
    }
    repositories {
        maven {
            name = 'packweir'
            url = uri('http://gateway:8080/api/v1/staging/' + System.getenv('PACKWEIR_STAGE_ID') + '/')
            allowInsecureProtocol = true
            credentials { username = 'publisher'; password = System.getenv('PACKWEIR_PUBLISH_TOKEN') }
            authentication { basic(BasicAuthentication) }
        }
    }
}
EOF
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
gradle --version
echo 'PACKWEIR_CLIENT_VERSION_END'
gradle --no-daemon --console=plain --gradle-user-home=/tmp/gradle-publish-cache publishFixturePublicationToPackweirRepository
