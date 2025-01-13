pipeline {
    // Single branch pipeline
    agent {
        label 'build2'
    }

    environment {
        PROJECT="fx-libpcap"
        SSH_CRED_ID="axellio-build-github"
        ARCHIVE_DIRECTORY="/net/devsrv/build/${PROJECT}"
        ARCHIVE_SUBDIR="${ARCHIVE_DIRECTORY}/${BUILD_NUMBER}"
        SOURCE_DIRECTORY="/src"
	BRANCH=GIT_BRANCH.replaceAll("^.*/", "")
        LINK="${ARCHIVE_DIRECTORY}/LATEST_$BRANCH"
    }

    stages {
        stage('el8') {
            environment {
                PODMAN_IMAGE="containers.swlab.axellio.dom/fx-cap_build_rocky8:9cdb416"
                OS_PLATFORM="el8"
            }
            stages {
                stage('Configure') {
                    steps {
                        sshagent(credentials: [env.SSH_CRED_ID]) {
                            sh "podman pull --tls-verify=false $PODMAN_IMAGE"
                        }
                    }
                }

                stage('Clean') {
                    steps {
                        makeClean()
                    }
                }

                stage('Build') {
                    steps {
                        makeBuild()
                    }
                }

		stage('Archive') {
		    steps {
			archiveRpm()
		    }
		}
            }
        }

        stage('el9') {
            environment {
                PODMAN_IMAGE="containers.swlab.axellio.dom/fx-cap_build_rocky9:9cdb416"
                OS_PLATFORM="el9"
            }
            stages {
                stage('Configure') {
                    steps {
                        sshagent(credentials: [env.SSH_CRED_ID]) {
                            sh "podman pull --tls-verify=false $PODMAN_IMAGE"
                        }
                    }
                }

                stage('Clean') {
                    steps {
                        makeClean()
                    }
                }

                stage('Build') {
                    steps {
                        makeBuild()
                    }
                }

		stage('Archive') {
		    steps {
			archiveRpm()
		    }
		}
            }
        }
    }

    post {
        always {
            emailext(body: '''${PROJECT_NAME}/${GIT_BRANCH} - Build # ${BUILD_NUMBER} - ${BUILD_STATUS}:

Check console output at ${BUILD_URL} to view the results.

Git Revision: ${GIT_REVISION}
Changes:
${CHANGES}
''',
                     subject: '${PROJECT_NAME}/${GIT_BRANCH} - Build # ${BUILD_NUMBER} - ${BUILD_STATUS}!',
                     to: 'engineering-fx@axellio.com')
        }
        success {
            archiveStatus()
            // Remove this if you want to debug WORKSPACE
            //deleteDir()
        }
    }
}

def makeClean() {
    sh """
        podman run --rm -t \
                   --mount type=bind,source=$WORKSPACE,destination=$SOURCE_DIRECTORY,relabel=shared \
                   --workdir=$SOURCE_DIRECTORY \
                   $PODMAN_IMAGE \
                   bash --login -c "(cd libpcap; make -f Makefile-rpm clean)"
    """
}

def makeBuild() {
    sh """
        podman run --rm -t \
                   --mount type=bind,source=$WORKSPACE,destination=$SOURCE_DIRECTORY,relabel=shared \
                   --workdir=$SOURCE_DIRECTORY \
                   -e BUILD_NUMBER=$BUILD_NUMBER \
                   $PODMAN_IMAGE \
                   bash --login -c "(cd libpcap; make -f Makefile-rpm)"
    """
}

def archiveRpm() {
    sh "mkdir -p ${ARCHIVE_SUBDIR}"
    sh "find . -name \"*rpm\" | xargs -I _ cp _ $ARCHIVE_SUBDIR"
}

def archiveStatus() {
    sh """
        # Store infomation about the build
        echo $GIT_COMMIT > ${ARCHIVE_SUBDIR}/hash.git
        echo $BUILD_URL > ${ARCHIVE_SUBDIR}/build.url

        # Create symlink without subdir for latest build
        rm -f ${LINK}
        ln -s ${ARCHIVE_SUBDIR} ${LINK}
    """
}
