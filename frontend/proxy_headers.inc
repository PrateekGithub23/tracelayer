proxy_set_header Host $host;
# Overwrite (do not append) so a client cannot inject its own X-Forwarded-For into rate limiting or logs.
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
