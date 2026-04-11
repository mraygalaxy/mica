FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

# System packages
# libstdc++5 provides libstdc++.so.5 (GLIBCPP_3.2) required by the pre-compiled
# ictc_64bit/libICTCLAS50.so, which was built with GCC 3.2.3 circa 2003.
RUN apt-get update && apt-get install -y \
    curl \
    git \
    locales \
    python-dev \
    python-openssl \
    python-setuptools \
    python-sqlalchemy \
    python-twisted \
    python-beaker \
    python-webob \
    python-simplejson \
    python-daemon \
    python-pip \
    python-crypto \
    python-zodb \
    python-pythonmagick \
    libstdc++5 \
    libffi-dev \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

ENV LANG en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# Python packages — pinned to last versions supporting Python 2.7
RUN pip install \
    cjklib \
    git+https://github.com/mraygalaxy/pdfminer.git \
    fpdf \
    couchdb \
    "requests==2.27.1" \
    git+https://github.com/mraygalaxy/jieba.git@v4 \
    "stripe==2.48.0" \
    python-gcm \
    apns \
    "oauthlib==2.1.0" \
    "requests-oauthlib==1.0.0" \
    "urllib3==1.26.18" \
    "pyOpenSSL==19.1.0" \
    "pycparser==2.21" \
    "cffi==1.14.6" \
    "cryptography==2.9.2" \
    "six==1.16.0" \
    "certifi==2021.10.8" \
    punjab

# Install CJKlib CEDICT dictionary data.
# installcjkdict always scrapes a dead mdbg.net page, so bypass it entirely:
# download the file directly and feed it to the cjklib builder.
# Note: buildcjkdb (full Unihan database) is skipped — ~300MB, add if needed.
RUN curl -L "https://www.mdbg.net/chinese/export/cedict/cedict_1_0_ts_utf-8_mdbg.txt.gz" \
        -o /tmp/cedict_1_0_ts_utf-8_mdbg.txt.gz && \
    python -c "from cjklib.build import DatabaseBuilder; b = DatabaseBuilder(dataPath=['/tmp'], databaseUrl='sqlite:////usr/local/lib/python2.7/dist-packages/cjklib/cjklib.db'); b.build(['CEDICT'])" && \
    rm /tmp/cedict_1_0_ts_utf-8_mdbg.txt.gz

# Install ICTCLAS shared library
# (Ubuntu uses /usr/lib/x86_64-linux-gnu/, not /usr/lib64 as the README says)
COPY ictc_64bit/libICTCLAS50.so /usr/lib/x86_64-linux-gnu/libICTCLAS50.so
COPY ictc_64bit/libICTCLAS50.a  /usr/lib/x86_64-linux-gnu/libICTCLAS50.a
RUN ldconfig

# Build the Python C++ extension against the installed library.
# setup.py installs mica_ictclas into Python site-packages system-wide.
WORKDIR /build
COPY mica_ictclas.cpp setup.py ICTCLAS50.h ./
RUN python setup.py build && python setup.py install

WORKDIR /mica

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/docker-entrypoint.sh"]
