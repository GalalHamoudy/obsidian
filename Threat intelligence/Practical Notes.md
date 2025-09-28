use https://phishtool.com/ website to check mails .eml

## docker commands ##

- Check logs of the container
docker compose logs -f --tail=100 <container name>

- Shutdown docker
docker compose down

- Update docker after editing docker-compose.yml
docker compose up -d

## Docker Connector ##

https://github.com/OpenCTI-Platform/connectors


# Pull all images with retry capability
docker compose pull --ignore-pull-failures

# Then start the containers
docker compose up -d