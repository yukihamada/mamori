FROM python:3.12-slim
WORKDIR /app
COPY hub/server.py /app/server.py
COPY hub/pages /app/pages
COPY agent /app/agent
COPY tools /app/tools
COPY examples /app/examples
COPY docs /app/docs
COPY media /app/media
COPY run.sh README.md /app/
RUN mkdir -p /app/data
ENV MAMORI_DATA=/app/data MAMORI_APP=/app PORT=8080 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
CMD ["python3", "/app/server.py"]
