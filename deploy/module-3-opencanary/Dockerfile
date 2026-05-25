FROM python:3.11-slim

# gcc + libffi-dev + libssl-dev are needed to compile cryptography (opencanary dep)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /var/log/opencanary /etc/opencanaryd

# Ensure the log directory is writable regardless of what UID OpenCanary runs as inside
# the container. With Docker userns-remap (container UID 0 -> host UID 100000) this is
# not strictly required, but it prevents silent failures if the UID mapping ever changes.
RUN chmod 777 /var/log/opencanary

# REQUIRED CONFIG FIELDS — opencanary.conf must contain all of the following or OpenCanary
# will raise ValueError("Invalid logging config") and exit immediately on startup.
#
# logger.class                                    must be "PyLogger"
# logger.kwargs.formatters.<name>.format          at least one formatter entry
# logger.kwargs.handlers.<name>.class             REQUIRED — must be the full Python class path,
#                                                 e.g. "logging.handlers.RotatingFileHandler"
#                                                 Omitting this field is the most common cause of
#                                                 "Unable to configure handler" crash on startup.
# logger.kwargs.handlers.<name>.level             e.g. "DEBUG"
# logger.kwargs.handlers.<name>.encoding          e.g. "utf8"
# logger.kwargs.handlers.<name>.filename          path inside the container (volume-mounted)
# logger.kwargs.handlers.<name>.maxBytes          rotation size in bytes
# logger.kwargs.handlers.<name>.backupCount       number of rotated files to keep
# logger.kwargs.handlers.<name>.formatter         must match a key in formatters above
#
# All other top-level keys (ftp.enabled, smtp.port, etc.) are optional and default to false/off.

EXPOSE 21 23 25 6379

# No --config flag — mount the config at OpenCanary's default search path instead.
# OpenCanary looks for /etc/opencanaryd/opencanary.conf first (see docker-compose.yml volume).
CMD ["opencanaryd", "--dev"]
