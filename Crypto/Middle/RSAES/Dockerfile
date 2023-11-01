FROM python:3.8-alpine
LABEL Description="rsaes" VERSION='1.0'

COPY RSAES.py .
COPY secret.py .

RUN pip install pycryptodome
RUN pip install sympy
RUN chmod +x RSAES.py

EXPOSE 80

CMD ["python", "RSAES.py"]