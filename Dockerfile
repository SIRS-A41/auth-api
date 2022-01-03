# Specify the Dart SDK
FROM google/dart

# Resolve app dependencies.
WORKDIR /app

ADD pubspec.* /app/
RUN pub get
ADD . /app

ENV ISSUER, SECRET_KEY, CLIENT_ID, CLIENT_SECRET

# Ensure packages are still up-to-date if anything has changed
RUN pub get --offline

CMD []

# Start server.
EXPOSE 8080
ENTRYPOINT ["./start_server.sh"]
