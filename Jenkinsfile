pipeline {
    agent any

    environment {
        AWS_ACCOUNT_ID = '997416683939'
        AWS_REGION     = 'eu-north-1'
        ECR_REPO_SERVER   = 'cryptonote-server'
        ECR_REPO_FRONTEND = 'cryptonote-frontend'
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Images') {
            steps {
                sh "docker build --no-cache -t ${ECR_REPO_SERVER}:${IMAGE_TAG} ./CryptoNote-App/server"
                sh "docker build -t ${ECR_REPO_FRONTEND}:${IMAGE_TAG} -f CryptoNote-App/src-ui/Dockerfile ./CryptoNote-App"
    }
            }
        }

        stage('Push to ECR') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'AWS_ACCESS_KEY_ID', variable: 'AWS_ACCESS_KEY_ID'),
                        string(credentialsId: 'AWS_SECRET_ACCESS_KEY', variable: 'AWS_SECRET_ACCESS_KEY')
                    ]) {
                        echo 'Logging into Amazon ECR...'
                        sh "aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
                        
                        echo 'Pushing Images...'
                        sh "docker tag ${ECR_REPO_SERVER}:${IMAGE_TAG} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_SERVER}:${IMAGE_TAG}"
                        sh "docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_SERVER}:${IMAGE_TAG}"
                        
                        sh "docker tag ${ECR_REPO_FRONTEND}:${IMAGE_TAG} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_FRONTEND}:${IMAGE_TAG}"
                        sh "docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_FRONTEND}:${IMAGE_TAG}"
                    }
                }
            }
        }

        stage('Deploy to Kubernetes') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'AWS_ACCESS_KEY_ID', variable: 'AWS_ACCESS_KEY_ID'),
                        string(credentialsId: 'AWS_SECRET_ACCESS_KEY', variable: 'AWS_SECRET_ACCESS_KEY')
                    ]) {
                        echo 'Updating Kubeconfig...'
                        sh "aws eks update-kubeconfig --region ${AWS_REGION} --name cryptonote-cluster"
                        echo 'Deploying to Kubernetes...'
                        // Updating the images using the correct container names
                        sh "kubectl set image deployment/server server=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_SERVER}:${IMAGE_TAG} -n cryptonote"
                        sh "kubectl set image deployment/frontend frontend=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_FRONTEND}:${IMAGE_TAG} -n cryptonote"
                    }
                }
            }
        }
    }

    post {
        success { echo 'Deployment Successful!' }
        failure { echo 'Pipeline failed. Check AWS credentials or EKS cluster status.' }
    }
}