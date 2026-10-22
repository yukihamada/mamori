FROM python:3.12-slim
WORKDIR /app
COPY hub/server.py /app/server.py
RUN mkdir -p /app/data
ENV MAMORI_DATA=/app/data PORT=8080
EXPOSE 8080
CMD ["python3", "/app/server.py"]
