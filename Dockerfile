FROM python:3.11.3-alpine
ENV PYTHONUNBUFFERED 1
WORKDIR /taskyapi
COPY requirements.txt /taskyapi/requirements.txt
RUN pip install -r requirements.txt
COPY . /taskyapi
# Copy the .env file into the image
COPY .env /taskyapi/.env
EXPOSE 8000
CMD ["gunicorn", "taskyapi.wsgi:application", "--bind", "0.0.0.0:8000"]