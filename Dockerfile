FROM python:3.12

RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY 'requirements.txt' .

COPY . .

RUN pip install -r requirements.txt

CMD ["python", "app.py"]