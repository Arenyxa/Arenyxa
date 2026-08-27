FROM python:3.12-slim
WORKDIR /opt/arenyxa
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[server]"
RUN useradd --create-home --uid 10001 --user-group arenyxa && mkdir -p /data && chown -R arenyxa:arenyxa /data
USER arenyxa
EXPOSE 8787
ENTRYPOINT ["arenyxa-server", "--data-dir", "/data"]
