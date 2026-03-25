FROM python:3.9

# 1. Create user and set up environment
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# 2. Install dependencies first (for faster rebuilding)
COPY --chown=user requirements.txt $HOME/app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r $HOME/app/requirements.txt

# 3. Copy the application code
COPY --chown=user . $HOME/app

# 4. Start the server
# NOTE: Ensure "backend" is a folder and "main.py" is inside it.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860"]