FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

ENV PYTHONPATH=/app

EXPOSE 5001

CMD ["python", "dashboard/app.py"]
