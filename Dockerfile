From python:slim-bullseye

ENV ISSUERURL "https://token-issuer"
ENV CLIENTID  "my-client"
ENV CLIENTSECRET "my-client-secret"
ENV OPAENDPOINT "opa-data-endpoint"
ENV REFRESHTOKEN "refresh-token"

RUN apt update && apt install -y curl && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

COPY requirements.txt ./

COPY app ../app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "./main.py -i ${CLIENTID} -s ${CLIENTSECRET} -r ${ISSUERURL} -o ${OPAENDPOINT} -f ${REFRESHTOKEN}"]

