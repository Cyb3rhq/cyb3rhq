FROM public.ecr.aws/o5x5t0j3/amd64/api_development:integration_test_cyb3rhq-generic

ARG CYB3RHQ_BRANCH

## install Cyb3rhq
RUN mkdir cyb3rhq && curl -sL https://github.com/cyb3rhq/cyb3rhq/tarball/${CYB3RHQ_BRANCH} | tar zx --strip-components=1 -C cyb3rhq
ADD base/agent/preloaded-vars.conf /cyb3rhq/etc/preloaded-vars.conf
RUN /cyb3rhq/install.sh

COPY base/agent/entrypoint.sh /scripts/entrypoint.sh

HEALTHCHECK --retries=900 --interval=1s --timeout=40s --start-period=30s CMD /usr/bin/python3 /tmp_volume/healthcheck/healthcheck.py || exit 1
