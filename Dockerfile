# Use Oracle Linux 8 as the base image
FROM oraclelinux:8

# Install OpenJDK
RUN dnf install -y java-17-openjdk

# Set the working directory inside the container
WORKDIR /app

# Copy the compiled JAR file into the container
COPY build/libs/api_gateway-0.0.1-SNAPSHOT.jar api_gateway.jar

# Expose the application's port
EXPOSE 8078

# Run the application
ENTRYPOINT ["java", "-jar", "api_gateway.jar"]

#docker build -t api-gateway -f Dockerfile .
#docker run -d --name api-gateway -p 8078:8078 api-gateway
