FROM public.ecr.aws/lambda/python:latest
RUN pip install pyarrow zat
COPY parser.py ./
CMD ["parser.handler"]