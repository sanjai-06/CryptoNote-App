FROM node:20-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies including devDependencies (needed for TypeScript)
RUN npm install

# Copy all source files
COPY . .

# Compile TypeScript to dist/
RUN npm run build

# Expose port
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
