pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                python3 -m pip install --upgrade pip
                if [ -f requirements.txt ]; then pip3 install -r requirements.txt; fi
                pip3 install pytest bandit pip-audit
                '''
            }
        }

        stage('Run Tests') {
            steps {
                sh '''
                if [ -d tests ]; then pytest; else echo "No tests folder found"; fi
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh 'bandit -r . -f json -o bandit-report.json || true'
            }
        }

        stage('SCA - pip-audit') {
            steps {
                sh 'pip-audit -f json -o pip-audit-report.json || true'
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.json', fingerprint: true
            }
        }
    }
}
