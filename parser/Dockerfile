FROM public.ecr.aws/lambda/python:latest
RUN pip install pyarrow zat
COPY app.py ./
CMD ["app.lambdaHandler"]