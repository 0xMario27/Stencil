FROM python:3.12-slim

WORKDIR /app

# Install Python deps only
COPY web/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY web/app.py .
COPY web/templates/ ./templates/

# Copy templates for generation
COPY Surge/ ./Surge/
COPY Stash/ ./Stash/

EXPOSE 5000

CMD ["python", "app.py"]
