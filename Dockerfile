# Use the official Python image 
FROM python:3.9 
# Set the working directory 
WORKDIR /app 
# Copy the current directory contents into the container 
COPY . . 
# Run the Python app 
CMD ["python", "blockchain.py"] 
