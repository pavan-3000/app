pipeline {
    agent any

    environment {
        DOCKER_IMAGE = "${JOB_NAME.toLowerCase().replaceAll('[^a-z0-9-]', '-')}"
        DOCKER_TAG   = "${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup Tools') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        TOOLS_DIR="$HOME/devpilot-tools"
                        mkdir -p "$TOOLS_DIR/bin"

                        if ! which trivy 2>/dev/null && [ ! -x "$TOOLS_DIR/bin/trivy" ]; then
                            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b "$TOOLS_DIR/bin" 2>/dev/null || true
                        fi
                    '''
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        def sonarOk = sh(script: 'which sonar-scanner 2>/dev/null', returnStatus: true) == 0
                        if (sonarOk) {
                            withSonarQubeEnv('SonarQube') {
                                sh 'sonar-scanner -Dsonar.projectKey=${env.JOB_NAME} -Dsonar.sources=. -Dsonar.host.url=${env.SONAR_HOST_URL}'
                            }
                        } else {
                            echo 'sonar-scanner not found — configure SonarQube Scanner in Jenkins → Manage Jenkins → Tools'
                        }
                    }
                }
            }
        }

        stage('Docker Build') {
            when { expression { return fileExists('Dockerfile') } }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        if (sh(script: 'which docker 2>/dev/null', returnStatus: true) == 0) {
                            sh "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."
                            sh "docker tag ${DOCKER_IMAGE}:${DOCKER_TAG} ${DOCKER_IMAGE}:latest"
                        } else {
                            echo 'Docker not available on this agent — skipping build'
                        }
                    }
                }
            }
        }

        stage('Trivy Scan') {
            when { expression { return fileExists('Dockerfile') } }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    script {
                        def trivyOk = sh(script: 'which trivy 2>/dev/null || test -x "$HOME/devpilot-tools/bin/trivy"', returnStatus: true) == 0
                        if (trivyOk) {
                            withEnv(["PATH+DEVPILOT=${env.HOME}/devpilot-tools/bin"]) {
                                sh "trivy image --exit-code 1 --severity HIGH,CRITICAL --format table ${DOCKER_IMAGE}:${DOCKER_TAG} | tee trivy-report.txt"
                                archiveArtifacts artifacts: 'trivy-report.txt', allowEmptyArchive: true
                            }
                        } else {
                            echo 'Trivy not available — skipping scan'
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                def status = currentBuild.result ?: 'IN_PROGRESS'
                def prompt = "Analyze this Jenkins CI/CD pipeline and give 2-3 actionable bullet points: what passed, what failed (if any), and one improvement recommendation.\n\nJob: ${env.JOB_NAME}\nBuild #${env.BUILD_NUMBER}\nBranch: ${env.GIT_BRANCH ?: env.BRANCH_NAME ?: 'unknown'}\nStatus: ${status}"
                def aiDone = false

                for (def credId : ['devpilot-anthropic-key', 'ANTHROPIC_API_KEY']) {
                    if (aiDone) break
                    try {
                        withCredentials([string(credentialsId: credId, variable: 'ANTHROPIC_KEY')]) {
                            def payload = groovy.json.JsonOutput.toJson([
                                model: 'claude-haiku-4-5-20251001',
                                max_tokens: 350,
                                messages: [[role: 'user', content: prompt]]
                            ])
                            def conn = new URL('https://api.anthropic.com/v1/messages').openConnection()
                            conn.requestMethod = 'POST'
                            conn.doOutput = true
                            conn.setRequestProperty('Content-Type', 'application/json')
                            conn.setRequestProperty('x-api-key', env.ANTHROPIC_KEY)
                            conn.setRequestProperty('anthropic-version', '2023-06-01')
                            conn.outputStream << payload.getBytes('UTF-8')
                            def code = conn.responseCode
                            def resp = code < 400 ? conn.inputStream.text : conn.errorStream.text
                            if (code == 200) {
                                def parsed = new groovy.json.JsonSlurper().parseText(resp)
                                echo "\n=== Claude AI Build Analysis ===\n${parsed.content[0].text}\n================================"
                                writeFile file: 'ai-analysis.json', text: resp
                                archiveArtifacts artifacts: 'ai-analysis.json', allowEmptyArchive: true
                                aiDone = true
                            }
                        }
                    } catch (ignored) {}
                }

                for (def credId : ['devpilot-openai-key', 'OPENAI_API_KEY']) {
                    if (aiDone) break
                    try {
                        withCredentials([string(credentialsId: credId, variable: 'OPENAI_KEY')]) {
                            def payload = groovy.json.JsonOutput.toJson([
                                model: 'gpt-4o-mini',
                                max_tokens: 350,
                                messages: [[role: 'user', content: prompt]]
                            ])
                            def conn = new URL('https://api.openai.com/v1/chat/completions').openConnection()
                            conn.requestMethod = 'POST'
                            conn.doOutput = true
                            conn.setRequestProperty('Content-Type', 'application/json')
                            conn.setRequestProperty('Authorization', "Bearer ${env.OPENAI_KEY}")
                            conn.outputStream << payload.getBytes('UTF-8')
                            def code = conn.responseCode
                            def resp = code < 400 ? conn.inputStream.text : conn.errorStream.text
                            if (code == 200) {
                                def parsed = new groovy.json.JsonSlurper().parseText(resp)
                                echo "\n=== ChatGPT Build Analysis ===\n${parsed.choices[0].message.content}\n==============================="
                                writeFile file: 'ai-analysis.json', text: resp
                                archiveArtifacts artifacts: 'ai-analysis.json', allowEmptyArchive: true
                                aiDone = true
                            }
                        }
                    } catch (ignored) {}
                }

                if (!aiDone) {
                    echo 'AI analysis skipped — configure an API key in DevPilot Settings (Claude or ChatGPT)'
                }
            }
        }
        success { echo 'Pipeline succeeded!' }
        failure  { echo 'Pipeline failed!' }
    }
}