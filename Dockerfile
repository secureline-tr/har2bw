FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home --uid 10001 app
COPY har2bw.py web.py review_bundle.py nginx_review.py policy_diff.py bunkerweb_api.py ./
COPY .streamlit/config.toml .streamlit/config.toml
USER app
EXPOSE 8501
CMD ["streamlit", "run", "web.py", "--server.address=0.0.0.0", "--server.headless=true"]
