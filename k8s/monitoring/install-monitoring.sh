#!/usr/bin/env bash
# ────────────────────────────────────────────────────────────────────────────
# install-monitoring.sh
# Installs Prometheus + Grafana on the EKS cluster using Helm.
# Prerequisites: helm, kubectl configured for the cluster
# ────────────────────────────────────────────────────────────────────────────
set -euo pipefail

NAMESPACE="monitoring"
RELEASE_NAME="kube-prometheus"

echo "==> Adding prometheus-community Helm repo..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

echo "==> Creating monitoring namespace..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

echo "==> Installing kube-prometheus-stack (Prometheus + Grafana + Alertmanager)..."
helm upgrade --install "$RELEASE_NAME" prometheus-community/kube-prometheus-stack \
  --namespace "$NAMESPACE" \
  --set grafana.service.type=LoadBalancer \
  --set grafana.adminPassword="$(openssl rand -base64 16)" \
  --set prometheus.prometheusSpec.retention=7d \
  --wait \
  --timeout 10m

echo ""
echo "==> Installation complete!"
echo ""
echo "==> Retrieving Grafana external URL (may take 1-2 minutes for ELB to provision)..."
kubectl get svc -n "$NAMESPACE" "$RELEASE_NAME-grafana" \
  -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' && echo ""

echo ""
echo "==> Grafana admin password:"
kubectl get secret -n "$NAMESPACE" "$RELEASE_NAME-grafana" \
  -o jsonpath='{.data.admin-password}' | base64 --decode && echo ""

echo ""
echo "==> Useful commands:"
echo "   kubectl get pods -n $NAMESPACE           # check all pods are running"
echo "   kubectl get svc  -n $NAMESPACE           # get all service URLs"
echo "   helm list -n $NAMESPACE                  # list installed releases"
echo ""
echo "==> Default Grafana dashboards include:"
echo "   - Kubernetes cluster resources"
echo "   - Node CPU/Memory/Disk metrics"
echo "   - Pod and container metrics"
echo "   - Alertmanager alerts"
