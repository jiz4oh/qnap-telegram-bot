FROM bitnami/python:3.12
WORKDIR /app
# Copy necessary files
COPY requirements.txt ./
# Upgrade pip and install dependencies from requirements.txt
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt
# Copy project files into the container
COPY *.py .
CMD python main.py
