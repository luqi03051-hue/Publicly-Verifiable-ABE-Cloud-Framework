# ============================================================
# Lambda Python 3.10 + PBC + Charm-Crypto (OpenSSL11 FIX)
# Fixes: undefined symbol EVP_MD_CTX_free when importing pairinggroup
# Cause: Charm extension linked against OpenSSL 1.1, but runtime OpenSSL older.
# Solution: install OpenSSL 1.1 (openssl11 + openssl11-devel) and force build+runtime
#           to use /usr/lib64/openssl11.
# ============================================================

FROM public.ecr.aws/lambda/python:3.10

# ------------------------------------------------------------
# 1) System dependencies
# ------------------------------------------------------------
RUN yum -y update && \
    yum -y groupinstall "Development Tools" && \
    yum -y install \
        gcc gcc-c++ make cmake \
        git wget tar gzip which findutils \
        gmp gmp-devel \
        libffi libffi-devel \
        python3-devel \
        flex bison swig patch \
        openssl11 openssl11-devel \
    && yum clean all


# Force both build-time and run-time to use OpenSSL 1.1
ENV OPENSSL_LIB_DIR=/usr/lib64/openssl11
ENV OPENSSL_INCLUDE_DIR=/usr/include/openssl11
ENV LD_LIBRARY_PATH=/usr/lib64/openssl11:/usr/local/lib:$LD_LIBRARY_PATH
ENV CFLAGS="-I/usr/include/openssl11"
ENV LDFLAGS="-L/usr/lib64/openssl11"

# ------------------------------------------------------------
# 2) Install PBC (Pairing-Based Cryptography)
# ------------------------------------------------------------
RUN cd /tmp && \
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz && \
    tar xzf pbc-0.5.14.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && make -j2 && make install && \
    cd / && rm -rf /tmp/pbc-0.5.14*

# ------------------------------------------------------------
# 3) Python dependencies
# ------------------------------------------------------------
COPY requirements.txt .
RUN python3 -m pip install -U pip setuptools wheel && \
    python3 -m pip install -r requirements.txt --target /var/task

# Make Python see /var/task packages
ENV PYTHONPATH=/var/task

# ------------------------------------------------------------
# 4) Install Charm-Crypto (robust setup.py path)
#   - Dev branch ships config.dist.py; setup.py expects charm/config.py
# ------------------------------------------------------------
RUN cd /tmp && \
    git clone --depth 1 https://github.com/JHUISI/charm.git && \
    cd charm && \
    cp -f config.dist.py charm/config.py && \
    python3 setup.py install --prefix=/var/task && \
    cd / && rm -rf /tmp/charm

# Charm installs here:
ENV PYTHONPATH=/var/task/lib/python3.10/site-packages:/var/task

RUN python -m pip install --no-cache-dir pytest
# ------------------------------------------------------------
# 5) Copy project code
# ------------------------------------------------------------
COPY app.py /var/task/
# Comment this line out if the file does not exist yet
COPY abe_project_local_client_and_lambda.py /var/task/

# ------------------------------------------------------------
# 6) Lambda entry (optional)
# ------------------------------------------------------------
# CMD ["app.lambda_handler"]
COPY ta_local.py /var/task/
COPY lambda_encrypt.py /var/task/
COPY client_decrypt.py /var/task/
COPY object_store.py /var/task/
COPY pv_core.py /var/task/
COPY tests /var/task/tests
# 复制代码到 Lambda 任务目录
COPY . ${LAMBDA_TASK_ROOT}

# 指定 handler：文件名.函数名
CMD ["lambda_handler.handler"]