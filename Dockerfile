# Étape 1 : base image officielle
FROM node:18-alpine

# Étape 2 : créer répertoire de travail
WORKDIR /app

# Étape 3 : copier uniquement les fichiers de dépendances
COPY package*.json ./

# Étape 4 : installer toutes les dépendances (axios compris)
RUN npm install --legacy-peer-deps



<<<<<<< HEAD

# Install production dependencies and clean npm cache to reduce image size
#RUN npm ci   --legacy-peer-deps  && npm cache clean --force

# Copy application code
=======
# Étape 5 : copier le reste du code
>>>>>>> 90f962dd57f16d48587b8b4779252893995f37ca
COPY . .

# Étape 6 : compiler le projet NestJS
RUN npm run build

# Étape 7 : exposer le port utilisé par l'app
EXPOSE 3032

<<<<<<< HEAD
# Expose port
EXPOSE 3032

# Start the application
=======
# Étape 8 : lancer l'application
>>>>>>> 90f962dd57f16d48587b8b4779252893995f37ca
CMD ["node", "dist/main.js"]
