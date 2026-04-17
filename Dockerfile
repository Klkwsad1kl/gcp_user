FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Initialize the database before starting
RUN python -c "from app import app, init_db; init_db()"

# Expose port (Cloud Run injects $PORT at runtime)
ENV PORT=8080

CMD exec gunicorn --bind 0.0.0.0:$PORT --workers 2 --threads 4 app:app
