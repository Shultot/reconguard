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
                python3 -m venv venv
                . venv/bin/activate
                python -m pip install --upgrade pip
                if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
                pip install pytest bandit pip-audit
                '''
            }
        }

        stage('Run Tests') {
            steps {
                sh '''
                . venv/bin/activate
                if [ -d tests ]; then pytest; else echo "No tests folder found"; fi
                '''
            }
        }

        stage('SAST - Bandit') {
            steps {
                sh '''
                . venv/bin/activate
                bandit -r . -f json -o bandit-report.json || true
                '''
            }
        }

        stage('SCA - pip-audit') {
            steps {
                sh '''
                . venv/bin/activate
                pip-audit -f json -o pip-audit-report.json || true
                '''
            }
        }

        stage('Archive Reports') {
            steps {
                archiveArtifacts artifacts: '*.json', fingerprint: true
            }
        }
    }
}
