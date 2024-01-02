FROM python:3.11.3-alpine
ENV PYTHONUNBUFFERED 1
WORKDIR /taskyapi
COPY requirements.txt /taskyapi/requirements.txt
RUN pip install -r requirements.txt
COPY . /taskyapi