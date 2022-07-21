FROM python

RUN mkdir /pykmip

COPY . /pykmip

RUN pip install -e /pykmip