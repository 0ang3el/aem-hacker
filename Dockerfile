FROM python:3

RUN git clone https://github.com/0ang3el/aem-hacker.git
WORKDIR /aem-hacker
RUN python -m pip install -r requirements.txt

ENTRYPOINT [ "/bin/bash" ]

