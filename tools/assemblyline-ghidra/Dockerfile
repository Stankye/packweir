ARG SERVICE_BASE=cccs/assemblyline-v4-service-base@sha256:ed471817fee053dac2e2d73ccbb79b2ee6edc44030725d3e74b5c5a825d4534c
FROM ${SERVICE_BASE}
USER root
COPY tools/ghidra-helper/upstream.lock.json /tmp/ghidra-upstream.lock.json
COPY tools/ghidra-helper/install-runtime.py /tmp/install-ghidra-runtime.py
RUN --mount=type=bind,from=ghidra_assets,target=/assets,ro python /tmp/install-ghidra-runtime.py
COPY tools/ghidra-helper/profile.json tools/ghidra-helper/runtime.py /opt/packweir-ghidra/
COPY tools/ghidra-helper/scripts/PackweirPre.java tools/ghidra-helper/scripts/PackweirPost.java tools/ghidra-helper/scripts/PackweirThrow.java /opt/packweir-ghidra/scripts/
COPY --chown=assemblyline:assemblyline tools/assemblyline-ghidra/packweir_ghidra/__init__.py tools/assemblyline-ghidra/packweir_ghidra/service.py /opt/al_service/packweir_ghidra/
COPY --chown=assemblyline:assemblyline tools/assemblyline-ghidra/service_manifest.yml /opt/al_service/service_manifest.yml
COPY tools/assemblyline-ghidra/bake-manifest.py /tmp/bake-ghidra-manifest.py
ENV PYTHONDONTWRITEBYTECODE=1
RUN python /tmp/bake-ghidra-manifest.py
ENV JAVA_HOME=/opt/ghidra-jdk GHIDRA_HOME=/opt/ghidra SERVICE_PATH=packweir_ghidra.service.PackweirGhidra
USER assemblyline
WORKDIR /opt/al_service
