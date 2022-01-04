#!/usr/bin/make -f
SHELL=/bin/bash
VAGRANT=vagrant

SNAPSHOT_NAME=provisioned

all:	reset master worker deploy

again:	reset destroy master worker deploy

reset:
	$@
#
master:	up-master provision-master snapshot-master # deploy-master-bootstrap # deploy-master-prepare

worker:	up-worker provision-worker snapshot-worker # deploy-worker
#
up:	up-master up-worker

up-master:
	vagrant up --no-provision master

up-worker:
	vagrant up --no-provision worker
#
destroy:	destroy-master destroy-worker

destroy-master:
	vagrant destroy -f master

destroy-worker:
	vagrant destroy -f worker
#
provision:	provision-master provision-worker

provision-master:
	vagrant provision master

provision-worker:
	vagrant provision worker
#
snapshot:	snapshot-master snapshot-worker

snapshot-master:	halt-master
	vagrant snapshot save master "master-${SNAPSHOT_NAME}"
	$(MAKE) up-master

snapshot-worker:	halt-worker
	vagrant snapshot save worker "worker-${SNAPSHOT_NAME}"
	$(MAKE) up-worker
#
restore:	restore-master restore-worker

restore-master:	halt-master
	vagrant restore save master "master-${SNAPSHOT_NAME}"
	$(MAKE) up-master

restore-worker:	halt-worker
	vagrant restore save worker "worker-${SNAPSHOT_NAME}"
	$(MAKE) up-worker
#
halt:	halt-master halt-worker

halt-master:
	vagrant halt -f master

halt-worker:
	vagrant halt -f worker
#
redeploy:	reset restore deploy

deploy:	deploy-master-bootstrap deploy-worker deploy-master-prepare

deploy-master-bootstrap:
	mkdir -vp resources log
	time script -f -e -c "${VAGRANT} ssh master -c 'pushd /vagrant ; sudo ./deploy.sh master multi bootstrap ; popd'" log/deploy-master.log

deploy-master-prepare:
	time script -a -f -e -c "${VAGRANT} ssh master -c 'pushd /vagrant ; sudo ./deploy.sh master multi prepare ; popd'" log/deploy-master.log
	grep -A 1 'kubeadm join' resources/worker-join.sh
	cat log/dashboard-bearer-token.log
	KUBECONFIG=${PWD}/.kube/config \
	kubectl get nodes \
	  -o wide \
	  --insecure-skip-tls-verify

deploy-worker:
	mkdir -vp resources log
	time script -f -e -c "${VAGRANT} ssh worker -c 'pushd /vagrant ; sudo ./deploy.sh worker ; popd'" log/deploy-worker.log
	KUBECONFIG=${PWD}/.kube/config \
	kubectl get nodes \
	  -o wide \
	  --insecure-skip-tls-verify
