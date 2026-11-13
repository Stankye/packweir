ARG SERVICE_BASE
FROM ${SERVICE_BASE}

USER assemblyline
WORKDIR /opt/al_service
COPY requirements.lock /tmp/packweir-yara-requirements.lock
RUN python -m pip install --no-cache-dir --user --no-deps --only-binary=:all: --require-hashes -r /tmp/packweir-yara-requirements.lock

COPY --chown=assemblyline:assemblyline packweir_yara/__init__.py packweir_yara/service.py packweir_yara/qualification.yar ./packweir_yara/
COPY --chown=assemblyline:assemblyline service_manifest.yml ./service_manifest.yml
COPY --chown=assemblyline:assemblyline licenses ./licenses
COPY --chown=assemblyline:assemblyline bake-manifest.py ./bake-manifest.py
ENV PYTHONDONTWRITEBYTECODE=1
RUN python bake-manifest.py
ENV SERVICE_PATH=packweir_yara.service.PackweirYARA
