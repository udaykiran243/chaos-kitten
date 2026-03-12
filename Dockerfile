# Stage 1: Builder
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only the files needed for installation to cache dependencies
COPY pyproject.toml README.md ./

# Create a virtual environment and install the package with browser dependencies
RUN python -m venv /opt/venv
# Enable venv
ENV PATH="/opt/venv/bin:$PATH"

# Install dependencies including the 'browser' extra for Playwright
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .[browser]

# Copy the rest of the application code
COPY chaos_kitten/ chaos_kitten/
COPY toys/ toys/
# Re-install package to include the source code
RUN pip install .[browser]


# Stage 2: Runner
FROM python:3.12-slim AS runner

# Set environment variables for security and performance
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Create non-root user for security
RUN useradd -m -r -s /bin/bash chaos

WORKDIR /app

# Install runtime dependencies required for Playwright
# Playwright needs some system libraries to run browsers
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2t64 \
    libpango-1.0-0 \
    libcairo2 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code from builder
COPY --from=builder /build/chaos_kitten /app/chaos_kitten
COPY --from=builder /build/toys /app/toys

# Change ownership of the app directory to the chaos user
RUN chown -R chaos:chaos /app

# Install Playwright browsers (chromium only to save space/time)
# Since we installed playwright in the venv, we can use it
RUN playwright install chromium --with-deps

# Create directories for reports and toys with proper ownership
RUN mkdir -p /app/reports /app/toys && \
    chown -R chaos:chaos /app/reports /app/toys

# Switch to non-root user BEFORE setting entrypoint
USER chaos

# Set entrypoint to run the application
ENTRYPOINT ["python", "-m", "chaos_kitten"]

# Default command matches typical usage (help)
CMD ["--help"]
