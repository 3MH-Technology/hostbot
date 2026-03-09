# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies for psutil and others
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run current project 
# Change port 30170 to 7860 as it is the default for Hugging Face
ENV SERVER_PORT=7860
EXPOSE 7860

# Start the application
CMD ["python", "app.py"]
