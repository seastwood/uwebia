# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Copy the requirements file into the container
COPY requirements.txt /app/requirements.txt

# Install any needed dependencies specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Run Flask-Migrate commands to initialize and apply migrations
RUN flask --app main db migrate -m "Initial migration." && flask --app main db upgrade

# Define environment variable
ENV FLASK_APP=main.py

# Run main.py when the container launches
CMD ["python", "main.py"]
