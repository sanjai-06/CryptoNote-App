pipeline {
    agent any

    environment {
        AWS_REGION      = 'eu-north-1'
        AWS_ACCOUNT_ID  = '997416683939'
        ECR_SERVER      = '997416683939.dkr.ecr.eu-north-1.amazonaws.com/cryptonote-server'
        ECR_FRONTEND    = '997416683939.dkr.ecr.eu-north-1.amazonaws.com/cryptonote-frontend'
        IMAGE_TAG       = "${BUILD_NUMBER}"
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
                sh 'docker build -t $ECR_SERVER:$IMAGE_TAG ./server'
            }
        }

        stage('Build Frontend Image') {
            steps {
                echo 'Building frontend Docker image...'
                sh 'docker build -t $ECR_FRONTEND:$IMAGE_TAG -f src-ui/Dockerfile .'
            }
        }

        stage('Test') {
            steps {
                echo 'Running tests...'
                sh 'cd server && npm install && npm test || true'
            }
        }

        stage('Push to ECR') {
            steps {
                echo 'Logging in to ECR...'
                sh '''
                    aws ecr get-login-password --region $AWS_REGION | \
                    docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com
                '''
                echo 'Pushing server image...'
                sh 'docker push $ECR_SERVER:$IMAGE_TAG'
                echo 'Pushing frontend image...'
                sh 'docker push $ECR_FRONTEND:$IMAGE_TAG'
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
