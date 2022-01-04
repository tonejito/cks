#!/bin/bash -ex

# TODO: Port this to ansible
# TODO: Remove '\r' from script output

help()
{
  cat << EOF
Usage: ${0} <deployment-type> [<cluster-type>] [<deployment-stage>]

<deployment-type>:	   master   | worker
<cluster-type>:		   single   | multi *
<deployment-stage>:	bootstrap * | prepare

*: default
EOF
  exit -1
}

# Print separator
python3 -c 'print("#"*80)'

# Parse arguments

case "${1}"
in
  master)
    export DEPLOYMENT_TYPE="master"
    ;;
  worker)
    export DEPLOYMENT_TYPE="worker"
    ;;
  *)
    help
    ;;
esac

banner ${DEPLOYMENT_TYPE}

case "${2}"
in
  single)
    export CLUSTER_TYPE="single"
    ;;
  multi)
    export CLUSTER_TYPE="multi"
    ;;
  *)
    export CLUSTER_TYPE="single"
    ;;
esac

banner ${CLUSTER_TYPE}

case "${3}"
in
  bootstrap)
    export DEPLOYMENT_STAGE="bootstrap"
    ;;
  prepare)
    export DEPLOYMENT_STAGE="prepare"
    ;;
  *)
    export DEPLOYMENT_STAGE="bootstrap"
    ;;
esac

banner ${DEPLOYMENT_STAGE}

echo "Deployment type is: ${DEPLOYMENT_TYPE}"

export TARGET_USER=vagrant
export TARGET_GROUP=staff
export VAGRANT_DIR=/vagrant
export SYSTEMD_PAGER=cat

mkdir -vp resources log

# ################################################################################
# # Set hostname
# 
# if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
# then
# hostnamectl set-hostname k8s.local
# fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Configure default privileges for ${TARGET_USER}

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then
usermod -aG users,sudo,adm,staff,operator ${TARGET_USER}
fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Check network configuration

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

ip addr

ip route

egrep -v '^\s*(#|$)' /etc/resolv.conf

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Prepare kernel settings for kubernetes
# https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner kernel

# Make sure that the br_netfilter module is loaded
MODPROBE_CONFIG=/etc/modules-load.d/k8s.conf
cat > ${MODPROBE_CONFIG} << EOF
overlay
br_netfilter
EOF
cp -v ${MODPROBE_CONFIG} resources/modprobe.conf

# Load kernel modules
modprobe overlay
modprobe br_netfilter

lsmod | egrep 'overlay|br_netfilter'

# Setup required sysctl params, these persist across reboots.
SYSCTL_CONFIG=/etc/sysctl.d/99-k8s.conf
cat > ${SYSCTL_CONFIG} << EOF
net.ipv4.ip_forward                 = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables  = 1
EOF
cp -v ${SYSCTL_CONFIG} resources/sysctl.conf

# Reload sysctl
sysctl --system

# Check required ports
# This script won't run if the API server port is already taken
if [ "${DEPLOYMENT_TYPE}" = "master" ]
then
nc -vz localhost 6443 2>&1 | grep "Connection refused"
fi  # "${DEPLOYMENT_TYPE}" = "master"

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Configure APT for unattended installation

export DEBIAN_FRONTEND="noninteractive"

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner apt

export APT_LOCAL_CONFIG=/etc/apt/apt.conf.d/99-local
truncate --size=0 ${APT_LOCAL_CONFIG}

cat > ${APT_LOCAL_CONFIG} << EOF
# Local APT config
# ${APT_LOCAL_CONFIG}
quiet "2";
APT::Get::Assume-Yes "1";
APT::Install-Recommends "0";
APT::Install-Suggests "0";
APT::Color "0";
Dpkg::Progress "0";
Dpkg::Progress-Fancy "0";
EOF
cp -v ${APT_LOCAL_CONFIG} resources/apt.conf

mkdir -vp /usr/share/keyrings

apt update

########################################
# Install prerequisites

apt-get install aptitude lsb-release gnupg curl ca-certificates apt-transport-https

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Install docker
# https://docs.docker.com/engine/install/ubuntu/

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner docker

# https://kubernetes.io/docs/setup/production-environment/container-runtimes/
# TODO: kubeadm complains: Using 'dockershim' is deprecated,
#       please consider using a full-fledged CRI implementation

# apt-get remove docker docker-engine docker.io containerd runc

KEYRING=/usr/share/keyrings/docker-archive-keyring.gpg
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
gpg --dearmor -o - > ${KEYRING}

ARCH=$(dpkg --print-architecture)
RELEASE=$(lsb_release -cs)
DOCKER_REPO=/etc/apt/sources.list.d/docker.list
echo "deb [arch=${ARCH} signed-by=${KEYRING}] https://download.docker.com/linux/ubuntu ${RELEASE} stable" | \
tee ${DOCKER_REPO}
cp -v ${DOCKER_REPO} resources/docker.list

apt-get update

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

########################################
# Docker
DOCKER_VERSION=20.10.12
CONTAINERD_VERSION=1.4.12
export CGROUP_DRIVER=systemd  # or cgroupfs

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

mkdir -vp /etc/docker
DOCKER_CONFIG=/etc/docker/daemon.json
cat > ${DOCKER_CONFIG} << EOF
{
  "exec-opts": ["native.cgroupdriver=${CGROUP_DRIVER}"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2"
}
EOF
cp -v ${DOCKER_CONFIG} resources/docker-daemon.json

apt-get install docker-ce docker-ce-cli containerd.io
apt-mark hold   docker-ce docker-ce-cli containerd.io

systemctl daemon-reload

for ACTION in enable restart status
do
  systemctl ${ACTION} --full docker.{socket,service}
done

usermod -aG docker ${TARGET_USER}
id ${TARGET_USER}

which docker

docker pull docker.io/library/hello-world:latest

docker run -it hello-world

docker ps -a

docker images -a

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

export CONTAINER_RUNTIME=docker

################################################################################
# Install kubernetes tools in the node
# https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

KUBERNETES_BASE_VERSION=1.22

if [ "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner k8s-tools

KEYRING=/usr/share/keyrings/kubernetes-archive-keyring.gpg
curl -fsSLo ${KEYRING} https://packages.cloud.google.com/apt/doc/apt-key.gpg

# For some reason there is no kubernetes-bionic dist for Ubuntu 18.04 LTS,
# so we have to use xenial which is for 16.04 LTS
# https://packages.cloud.google.com/apt/dists
KUBERNETES_REPO=/etc/apt/sources.list.d/kubernetes.list
echo "deb [signed-by=${KEYRING}] https://apt.kubernetes.io/ kubernetes-xenial main" | \
tee ${KUBERNETES_REPO}
cp -v ${KUBERNETES_REPO} resources/kubernetes.list

apt-get update

# FIXME: The order may not be deterministic if versions are prepended with '^\d+:' from mixed repos
KUBERNETES_TOOLS_VERSION=$(apt-cache madison kubeadm | grep "${KUBERNETES_BASE_VERSION}" | awk '{print $3}' | sort -V | tail -n 1)
KUBERNETES_TOOLS="kubelet kubectl kubeadm"

# Install specific version of the tools
KUBERNETES_TOOLS_VERSION_PIN="$(echo "${KUBERNETES_TOOLS}" | sed -e "s|^\s\+||g" -e "s|$| |g" -e "s|\s\+|=${KUBERNETES_TOOLS_VERSION} |g")"

apt-get install ${KUBERNETES_TOOLS_VERSION_PIN}
apt-mark hold ${KUBERNETES_TOOLS}

test -e ${APT_LOCAL_CONFIG} && rm -v ${APT_LOCAL_CONFIG}

which ${KUBERNETES_TOOLS}

for ACTION in enable restart status
do
  systemctl ${ACTION} --full kubelet.service
done

kubelet --version
if [ "${DEPLOYMENT_TYPE}" = "master" ]
then
  kubectl version || true
  kubeadm version
fi  # "${DEPLOYMENT_TYPE}" = "master"

fi  # "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Install kubernetes cluster with kubeadm
# https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/
# https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/configure-cgroup-driver/
# https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/#kubelet-config-k8s-io-v1beta1-KubeletConfiguration

KUBERNENTES_VERSION=$(echo "${KUBERNETES_TOOLS_VERSION}" | cut -d - -f 1)
CGROUP_DRIVER=systemd  # or cgroupfs
POD_CIDR=10.244.0.0/16  # flannel

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner kubeadm

kubeadm config images pull --kubernetes-version=${KUBERNENTES_VERSION}

${CONTAINER_RUNTIME} images

# TODO: Ensure that kubelet cgroup driver is the same as docker (or the container runtime)
# https://github.com/flannel-io/flannel/blob/master/Documentation/kubernetes.md#kubeadm
CMD="kubeadm init --kubernetes-version=${KUBERNENTES_VERSION} --pod-network-cidr ${POD_CIDR}"
KUBEADM_INIT_LOG=log/kubeadm-init.log
script -f -e -c "${CMD}" ${KUBEADM_INIT_LOG}

# Create a script to allow worker nodes to join the cluster
JOIN_SCRIPT=resources/worker-join.sh
echo "#!/bin/bash -vxe" > ${JOIN_SCRIPT}
grep -A 1 'kubeadm join' log/kubeadm-init.log >> ${JOIN_SCRIPT}
chmod -c +x ${JOIN_SCRIPT}
sed -i -e 's|||g' ${JOIN_SCRIPT}

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Set up the kubeconfig file

export KUBECONFIG=/etc/kubernetes/admin.conf

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner kubeconfig

# Set up kubeconfig for root
mkdir -vp /root/.kube
ln -vsf /etc/kubernetes/admin.conf /root/.kube/config

kubectl get nodes

# Set up kubeconfig for ${TARGET_USER}
# FIXME: ~${TARGET_USER} didn't worked here
TARGET_USER_HOME=/home/${TARGET_USER}
mkdir -vp ${TARGET_USER_HOME}/.kube
install \
  --mode 0600 --owner ${TARGET_USER} --group ${TARGET_GROUP} \
  /etc/kubernetes/admin.conf \
  ${TARGET_USER_HOME}/.kube/config
chown -R ${TARGET_USER}:${TARGET_GROUP} ${TARGET_USER_HOME}/.kube

su -l -c "kubectl get nodes" ${TARGET_USER}

# Export kubeconfig to ${VAGRANT_DIR}
# TODO: Fix context endpoint address to access outside of the cluster
# Right now it works because vagrant has a port forward and we have to pass the 
# --insecure-skip-tls-verify flag to kubectl to bypass certificate validation
mkdir -vp ${VAGRANT_DIR}/.kube
cp -va /etc/kubernetes/admin.conf ${VAGRANT_DIR}/.kube/config

# Try to replace VirtualBox NAT IP address with localhost to use port forwarding
# The API server will be reachable via the bridge interface that has a lower
# metric, so this may not be needed after all
sed -ie 's|10.0.2.15|localhost|g' ${VAGRANT_DIR}/.kube/config

cat > ${VAGRANT_DIR}/.bashrc << EOF
export KUBECONFIG=\${PWD}/.kube/config
printf "KUBECONFIG="
printenv KUBECONFIG
EOF

# Remove taint to schedule on the master node (for single node "clusters")
if [ "${CLUSTER_TYPE}" = "single" ]
then
kubectl taint nodes --all node-role.kubernetes.io/master- || true
# kubectl taint nodes $(hostname -f) node-role.kubernetes.io/master:NoSchedule- || true
fi  # "${CLUSTER_TYPE}" = "single"

kubectl get nodes

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Install helm
# https://helm.sh/docs/intro/quickstart/
# https://helm.sh/docs/intro/install/

HELM_VERSION=v3.7.2

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner helm

HELM_TMP_DIR=/tmp/helm
mkdir -vp ${HELM_TMP_DIR}
wget -c -nv \
  -O ${HELM_TMP_DIR}/helm-${HELM_VERSION}.tar.gz \
  "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz"

tar -xvvzf ${HELM_TMP_DIR}/helm-${HELM_VERSION}.tar.gz \
  --one-top-level=${HELM_TMP_DIR} linux-amd64/helm
install \
  --mode 0755 --owner root --group root \
  ${HELM_TMP_DIR}/linux-amd64/helm /usr/local/bin/helm
rm -rf ${HELM_TMP_DIR}

which helm
helm version

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap"

################################################################################
# Install Flannel CNI plugin
# https://github.com/flannel-io/flannel#deploying-flannel-manually
# Warning: policy/v1beta1 PodSecurityPolicy is deprecated in v1.21+, unavailable in v1.25+

FLANNEL_VERSION=v0.15.1
FLANNEL_NAMESPACE=kube-system
FLANNEL_SELECTOR="app=flannel"

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap" ]
then

banner flannel

source ${VAGRANT_DIR}/.bashrc

FLANNEL_YAML=resources/flannel-${FLANNEL_VERSION}.yaml
wget -c -nv \
  -O ${FLANNEL_YAML} \
  https://raw.githubusercontent.com/coreos/flannel/${FLANNEL_VERSION}/Documentation/kube-flannel.yml

kubectl describe node $(hostname -s)
kubectl apply -f ${FLANNEL_YAML}
kubectl get daemonset/kube-flannel-ds -n ${FLANNEL_NAMESPACE}

sleep 15

# kubectl wait \
#   --for=condition=ready \
#   pod \
#   --selector=${FLANNEL_SELECTOR} \
#   --namespace=${FLANNEL_NAMESPACE} \
#   --timeout=5m
kubectl get pods -l ${FLANNEL_SELECTOR} -n ${FLANNEL_NAMESPACE}
kubectl get nodes
kubectl logs daemonset/kube-flannel-ds -n ${FLANNEL_NAMESPACE}

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "bootstrap"

export CNI_NAMESPACE=${FLANNEL_NAMESPACE}

################################################################################
# join cluster

if [ "${DEPLOYMENT_TYPE}" = "worker" ]
then

banner join

  # Wait until file exists
  JOIN_SCRIPT=./resources/worker-join.sh
  while [ ! -e ${JOIN_SCRIPT} ]
  do
    sleep 2
    printf "."
  done
  printf "\n"
  KUBEADM_JOIN_LOG=log/kubeadm-join.log
  script -f -e -c "${JOIN_SCRIPT}" ${KUBEADM_JOIN_LOG}

  source ${VAGRANT_DIR}/.bashrc
  kubectl wait --for=condition=ready node/k8s-worker --timeout=10m

fi  # "${DEPLOYMENT_TYPE}" = "worker"

# Note: worker nodes must be joined at this point or master taint should be removed
# - Event: Warning: FailedScheduling:
#   1 node(s) had taint {node-role.kubernetes.io/master: }, that the pod didn't tolerate.

################################################################################
# Check that the cluster nodes are 'ready'

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare" ]
then

banner check

kubectl wait \
  --for=condition=ready \
  pod \
  --selector=${FLANNEL_SELECTOR} \
  --namespace=${FLANNEL_NAMESPACE} \
  --timeout=5m

kubectl wait --for=condition=ready node --all --timeout=10m || true

kubectl get nodes -o wide --show-labels
kubectl get all -n ${CNI_NAMESPACE}

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare"

################################################################################
# Deploy NGINX ingress controller
# https://kubernetes.github.io/ingress-nginx/deploy/

NGINX_INGRESS_VERSION=v1.1.0
NGINX_INGRESS_NAMESPACE=ingress-nginx
NGINX_INGRESS_SELECTOR="app.kubernetes.io/component=controller"

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare" ]
then

banner ingress

NGINX_INGRESS_YAML=resources/nginx-ingress-${NGINX_INGRESS_VERSION}.yaml
wget -c -nv \
  -O ${NGINX_INGRESS_YAML} \
  https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-${NGINX_INGRESS_VERSION}/deploy/static/provider/cloud/deploy.yaml

kubectl apply -f ${NGINX_INGRESS_YAML}

# Patch the NGINX ingress to use ports 80 and 443 of the host network
# https://kubernetes.github.io/ingress-nginx/deploy/baremetal/#via-the-host-network
kubectl patch deployment/ingress-nginx-controller \
  -n ${NGINX_INGRESS_NAMESPACE} \
  --patch '{"spec":{"template":{"spec":{"hostNetwork":true}}}}'

kubectl get pods -n ${NGINX_INGRESS_NAMESPACE}
sleep 15
kubectl wait \
  --for=condition=ready \
  pod \
  --selector=${NGINX_INGRESS_SELECTOR} \
  --namespace=${NGINX_INGRESS_NAMESPACE} \
  --timeout=5m
kubectl get pods -l ${NGINX_INGRESS_SELECTOR} -n ${NGINX_INGRESS_NAMESPACE}
sleep 15

netstat -ntulp | grep nginx | sort -Vk 4,4

# TODO: Set up a custom SSL CA to issue trusted certificates

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare"

################################################################################
# Deploy the kubernetes dashboard
# https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/
# https://github.com/kubernetes/dashboard/blob/v2.4.0/docs/user/installation.md
# https://github.com/kubernetes/dashboard/tree/v2.4.0/aio/deploy
# https://github.com/kubernetes/dashboard/blob/master/docs/user/access-control/creating-sample-user.md

DASHBOARD_VERSION=v2.4.0
DASHBOARD_NAMESPACE=kubernetes-dashboard
DASHBOARD_SELECTOR="k8s-app=kubernetes-dashboard"

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare" ]
then

banner dashboard

DASHBOARD_YAML=resources/kubernetes-dashboard-${DASHBOARD_VERSION}.yaml
wget -c -nv \
  -O ${DASHBOARD_YAML} \
  https://raw.githubusercontent.com/kubernetes/dashboard/${DASHBOARD_VERSION}/aio/deploy/recommended.yaml

kubectl apply -f ${DASHBOARD_YAML}

# Kubernetes dashboard RBAC
DASHBOARD_RBAC=resources/dashboard-rbac.yaml
cat > ${DASHBOARD_RBAC} << EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: ${DASHBOARD_NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: ${DASHBOARD_NAMESPACE}
EOF

kubectl apply -f ${DASHBOARD_RBAC}

DASHBOARD_SECRET="$(kubectl get serviceaccount/admin-user -n ${DASHBOARD_NAMESPACE} -o jsonpath='{.secrets[0].name}')"
DASHBOARD_BEARER_TOKEN=$(kubectl get secret ${DASHBOARD_SECRET} -n ${DASHBOARD_NAMESPACE} -o go-template='{{ .data.token | base64decode }}')
echo "${DASHBOARD_BEARER_TOKEN}" | tee log/dashboard-bearer-token.log

kubectl get services -n ${DASHBOARD_NAMESPACE}
kubectl get deployments -n ${DASHBOARD_NAMESPACE}
sleep 15
kubectl wait \
  --for=condition=ready \
  pod \
  --selector=${DASHBOARD_SELECTOR} \
  --namespace=${DASHBOARD_NAMESPACE} \
  --timeout=5m
kubectl get pods -l ${DASHBOARD_SELECTOR} -n ${DASHBOARD_NAMESPACE}

# Determine the IP address for the dashboard DNS endpoint
if [ "${CLUSTER_TYPE}" = "single" ]
then
# Deploy ingress for kubernetes-dashboard
# VirtualBox network interfaces (for vagrant)
# - eth0: NAT
# - eth1: host-only
# - eth2: Bridge
HOST_IFACE=eth2
HOST_IP="$(ip addr show dev ${HOST_IFACE} | grep '\<inet\>' | awk '{print $2}' | cut -d / -f 1)"
fi  # "${CLUSTER_TYPE}" = "single"

if [ "${CLUSTER_TYPE}" = "multi" ]
then
WORKER_NAME=k8s-worker
# HOST_IP="$(kubectl get node/${WORKER_NAME} -o jsonpath='{.metadata.annotations.flannel\.alpha\.coreos\.com/public-ip}{"\n"}')"
HOST_IP="$(kubectl get node/${WORKER_NAME} -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}')"
fi  # "${CLUSTER_TYPE}" = "single"

# Convert the IP address to dashed notation
# This is done to get only 4 domain components to aid in creating wildcard SSL certificates
DASHBOARD_DNS="dashboard.$(echo ${HOST_IP} | tr '.' '-')".nip.io

# TODO: Create another with the dotted IP address?
DASHBOARD_INGRESS=resources/dashboard-ingress.yaml
cat > ${DASHBOARD_INGRESS} << EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubernetes-dashboard-ingress
  namespace: ${DASHBOARD_NAMESPACE}
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: HTTPS
    nginx.ingress.kubernetes.io/secure-backends: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-passthrough: "true"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  rules:
  - host: ${DASHBOARD_DNS}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 443
  tls:
  - hosts:
    - ${DASHBOARD_DNS}
    secretName: kubernetes-dashboard-secret
EOF

kubectl apply -f ${DASHBOARD_INGRESS}
kubectl get ingresses -A

sleep 10

curl -kfsSL "https://${DASHBOARD_DNS}/" | grep 'Kubernetes Dashboard'

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare"

################################################################################
# Install krew
# https://krew.sigs.k8s.io/docs/user-guide/quickstart/
# https://krew.sigs.k8s.io/docs/user-guide/setup/install/

KREW_VERSION=v0.4.2

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare" ]
then

banner krew

KREW_TMP_DIR=/tmp/krew
mkdir -vp ${KREW_TMP_DIR}

wget -c -nv \
  -O ${KREW_TMP_DIR}/krew-${KREW_VERSION}.tar.gz \
  "https://github.com/kubernetes-sigs/krew/releases/download/${KREW_VERSION}/krew-linux_amd64.tar.gz"

tar -xvvzf ${KREW_TMP_DIR}/krew-${KREW_VERSION}.tar.gz -C ${KREW_TMP_DIR}

KREW_INSTALL=resources/install-krew.sh
cat > ${KREW_INSTALL} << EOF
#!/bin/bash -ex
${KREW_TMP_DIR}/krew-linux_amd64 install krew
echo "export PATH=\"\${PATH}:\${HOME}/.krew/bin\"" >> ~/.bashrc
export PATH="\${PATH}:\${HOME}/.krew/bin"

kubectl krew || true
kubectl krew version || true

kubectl krew update

kubectl krew install neat
EOF
chmod -c +x ${KREW_INSTALL}

su - vagrant -c "${VAGRANT_DIR}/${KREW_INSTALL}"

rm -rf ${KREW_TMP_DIR} ${KREW_INSTALL}

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare"

################################################################################
# Print cluster information

if [ "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare" ]
then

banner cluster

# Warning: v1 ComponentStatus is deprecated in v1.19+
kubectl get componentstatus

kubectl cluster-info

fi  # "${DEPLOYMENT_TYPE}" = "master" -a "${DEPLOYMENT_STAGE}" = "prepare"
