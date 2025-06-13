FROM openjdk:17-alpine

RUN apk add --no-cache curl

# Set the working directory inside the container
WORKDIR /app

# Copy the compiled JAR file into the container
COPY build/libs/api_gateway-0.0.1-SNAPSHOT.jar api_gateway.jar

# Expose the application's port
EXPOSE 8078

# Run the application
ENTRYPOINT ["java", "-jar", "api_gateway.jar"]

#docker build -t ghcr.io/pibbletv/pibbletv-gateway:latest -f Dockerfile .
#docker run -d --name api-gateway -p 8078:8078 ghcr.io/pibbletv/pibbletv-gateway:latest
