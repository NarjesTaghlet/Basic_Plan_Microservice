FROM node:18-alpine



# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json (if available) for reproducible builds
COPY package*.json ./
RUN npm install --legacy-peer-deps


RUN npm install -g @nestjs/cli --legacy-peer-deps


# Install production dependencies and clean npm cache to reduce image size
RUN npm ci   --legacy-peer-deps  && npm cache clean --force

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Run as non-root user for security
#RUN addgroup -S appgroup && adduser -S appuser -G appgroup
#USER appuser

# Expose port
EXPOSE 3003

# Start the application
CMD ["node", "dist/main.js"]
