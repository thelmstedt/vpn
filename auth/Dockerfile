FROM python:3.12-bookworm

RUN pip install playwright
RUN playwright install chromium --with-deps

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY openconnect_auth.py .

ENV USERNAME=""
ENV PASSWORD=""
ENV SERVER=""

# Run the script
CMD python openconnect_auth.py \
    --user "$USERNAME" \
    --password "$PASSWORD" \
    --server "$SERVER" \
    --output-config /app/output/config.env

