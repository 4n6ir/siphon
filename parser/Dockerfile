FROM public.ecr.aws/lambda/python:latest
RUN pip install zat
COPY app.py ./
CMD ["app.lambdaHandler"]