#!/usr/bin/env bash -xe

PROJECT_NAME=midonet-kubernetes
MINION_LIST=.minions
USER=tfukushima
TIMEOUT=180
PLUGIN_DIR=/usr/libexec/kubernetes/kubelet-plugins/net/exec/
MIDOKUBE_DIR=${PLUGIN_DIR}/${PROJECT_NAME}
MIDOKUBE_LOG_DIR=/var/log/${PROJECT_NAME}
ARCHIVE=${PROJECT_NAME}.tar.gz
TMP_DIR=/tmp
EXECUTABLE=./${PROJECT_NAME}


COPY=${COPY:-1}

SSH_OPT="-i ${HOME}/.ssh/id_rsa -o UserKnownHostsFile=/dev/null -o CheckHostIP=no -o StrictHostKeyChecking=no"
PSSH=$(((which parallel-ssh > /dev/null) && which parallel-ssh) || \
        ((which pssh > /dev/null) && which pssh))
PSSH="${PSSH}"
SCP="scp ${SSH_OPT}"

echo "Creating ${MIDOKUBE_DIR} and ${MIDOKUBE_LOG_DIR}"
${PSSH} -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "sudo mkdir -p $MIDOKUBE_DIR $MIDOKUBE_LOG_DIR"

echo "Changing the permission of ${MIDOKUBE_DIR} and ${MIDOKUBE_LOG_DIR}"
${PSSH} -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "sudo chown -R tfukushima:tfukushima ${MIDOKUBE_DIR} ${MIDOKUBE_LOG_DIR}"

# echo "Creating ${MIDOKUBE_DIR}/${PROJECT_NAME}"
# $PSSH -h $MINION_LIST -x "${SSH_OPT}" -i \
#     sudo sh -c "cat > ${MIDOKUBE_DIR}/${PROJECT_NAME} <<'EOF'
# #!/usr/bin/env bash
# 
# PYTHONPATH=$PYTHONPATH:. python ${MIDOKUBE_DIR}/midonet_kubernetes/ \$@
# EOF
# "

echo "Installing pip and virtualenv"
${PSSH} -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "sudo apt-get install -y python-pip libssl-dev libffi-dev; sudo pip install virtualenv requests[security]"

if [[ "${COPY}" = "1" ]]; then
    echo "Deleting old ${PROJECT_NAME}"
    $PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
        "test -f /home/${USER}/${ARCHIVE} && rm /home/${USER}/${PROJECT_NAME}.tar.gz || true "

    echo "Copying ${PROJECT_NAME}"
    (cd ../ && tar cfz ${TMP_DIR}/${ARCHIVE} ${PROJECT_NAME})
    while read minion; do
        ${SCP} ${TMP_DIR}/${ARCHIVE} ${USER}@${minion}:/home/${USER}/
    done < ${MINION_LIST}

    echo "Deleting ${MIDOKUBE_DIR}/${PROJECT_NAME}"
    $PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
        "test -f ${MIDOKUBE_DIR} && sudo rm -rf ${MIDOKUBE_DIR} || true''"

    echo "Extracting ${MIDOKUBE_DIR}"
    $PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
        "sudo tar xfz /home/${USER}/${ARCHIVE} -C ${PLUGIN_DIR}"
fi

echo "Changing the permission of ${MIDOKUBE_DIR} and ${MIDOKUBE_LOG_DIR}"
$PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "sudo chown -R tfukushima:tfukushima ${MIDOKUBE_DIR} ${MIDOKUBE_LOG_DIR}"

echo "Creating the virtualenv"
$PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "virtualenv ${MIDOKUBE_DIR}"

echo "Installing dependencies"
$PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
    "source ${MIDOKUBE_DIR}/bin/activate && pip install -r ${MIDOKUBE_DIR}/requirements.txt"


# echo "Restarting kubelet"
# $PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
#     "sudo service kubelet restart"
# 
# echo "Checking kubelet statuses"
# $PSSH -h ${MINION_LIST} -x "${SSH_OPT}" -i \
#     "sudo service kubelet status"
