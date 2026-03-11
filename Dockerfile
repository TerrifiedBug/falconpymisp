FROM python:3.12-slim

RUN useradd --create-home appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY config.example.yml .
RUN chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python", "-m", "src"]
CMD ["/app/config.yml"]
