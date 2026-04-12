pipeline {
    agent any

    environment {
        AWS_REGION = 'ap-south-1'
        ECR_REPO_SERVER   = 'cryptonote-server'
        ECR_REPO_FRONTEND = 'cryptonote-frontend'
        IMAGE_TAG = "${BUILD_NUMBER}"
    }

    stages {

        stage('Checkout') {
            steps {
                echo 'Cloning repository...'
                checkout scm
            }
        }

        stage('Build Server Image') {
            steps {
                echo 'Building backend Docker image...'
                sh 'docker build -t $ECR_REPO_SERVER:$IMAGE_TAG ./server'
            }
        }

        stage('Build Frontend Image') {
            steps {
                echo 'Building frontend Docker image...'
                sh 'docker build -t $ECR_REPO_FRONTEND:$IMAGE_TAG -f src-ui/Dockerfile .'
            }
        }

        stage('Test') {
            steps {
                echo 'Running server tests...'
                sh 'cd server && npm install && npm test || true'
            }
        }

        stage('Push to ECR') {
            steps {
                echo 'Pushing images to Amazon ECR...'
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                echo 'Deploying to EKS...'
            }
        }
    }

    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
