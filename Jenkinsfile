pipeline {
    agent any

    environment {
        // Use the Account ID and Region from your successful Terraform apply
        AWS_ACCOUNT_ID = '997416683939'
        AWS_REGION     = 'eu-north-1'
        ECR_REPO_SERVER   = 'cryptonote-server'
        ECR_REPO_FRONTEND = 'cryptonote-frontend'
        IMAGE_TAG = "${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Cloning repository...'
                // This is the correct way to pull your code
                checkout scm
            }
        }

        stage('Build Server Image') {
            steps {
                echo 'Building backend Docker image...'
                // 'sh' tells Jenkins to run this in the Ubuntu terminal
                sh "docker build -t ${ECR_REPO_SERVER}:${IMAGE_TAG} ./server"
            }
        }

        stage('Build Frontend Image') {
            steps {
                echo 'Building frontend Docker image...'
                sh "docker build -t ${ECR_REPO_FRONTEND}:${IMAGE_TAG} -f src-ui/Dockerfile ."
            }
        }

        stage('Push to ECR') {
            steps {
                script {
                    // This pulls your AWS keys from the Jenkins credentials store
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
                    echo 'Updating Kubeconfig and Deploying to EKS...'
                    sh "aws eks update-kubeconfig --region ${AWS_REGION} --name cryptonote-cluster"
                    
                    // These commands tell Kubernetes to pull the new images you just pushed
                    sh "kubectl set image deployment/server-deploy server-container=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_SERVER}:${IMAGE_TAG} -n cryptonote"
                    sh "kubectl set image deployment/frontend-deploy frontend-container=${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_FRONTEND}:${IMAGE_TAG} -n cryptonote"
                }
            }
        }
    }

    post {
        success { echo 'Pipeline finished successfully!' }
        failure { echo 'Pipeline failed. Check the logs above.' }
    }
}