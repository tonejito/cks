#!/usr/bin/make -f
SHELL=/bin/bash
VAGRANT=vagrant

SNAPSHOT_NAME="provisioned"

all:	up provision snapshot deploy

again:	reset destroy up provision snapshot

reset:
	$@

destroy:
	${VAGRANT} destroy -f

up:
	${VAGRANT} up --no-provision

provision:
	${VAGRANT} provision

snapshot:
	${VAGRANT} halt -f
	${VAGRANT} snapshot save "${SNAPSHOT_NAME}"
	${VAGRANT} up

restore:
	${VAGRANT} halt -f
	${VAGRANT} snapshot restore "${SNAPSHOT_NAME}"
	${VAGRANT} up --provision

redeploy:	reset restore deploy

deploy:
	mkdir -vp resources log
	time script -f -e -c "${VAGRANT} ssh -c 'pushd /vagrant ; sudo ./deploy.sh ; popd'" log/deploy.log
	grep -A 1 'kubeadm join' resources/worker-join.sh
	cat log/dashboard-bearer-token.log
	KUBECONFIG=${PWD}/.kube/config \
	kubectl get nodes \
	  -o wide \
	  --insecure-skip-tls-verify
