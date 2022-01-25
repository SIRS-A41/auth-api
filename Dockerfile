# Specify the Dart SDK
FROM google/dart

# Resolve app dependencies.
WORKDIR /app

ADD pubspec.* /app/
RUN dart pub get
ADD . /app

# Ensure packages are still up-to-date if anything has changed
RUN dart pub get --offline

RUN dart run build_runner clean
RUN dart run build_runner build --delete-conflicting-outputs 

CMD []

# Start server.
# HTTPS auth requests
EXPOSE 8443 8445
ENTRYPOINT ["./start_server.sh"]
