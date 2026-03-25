FROM python:3.9

# Create a non-root user (Hugging Face requirement)
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY --chown=user . .

# Run FastAPI on port 7860 (Hugging Face default)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860"]
