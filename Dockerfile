FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

ENV DATABASE_PATH=/app/data/lockbox.db
ENV FLASK_APP=app.py

EXPOSE 5001

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0"]
