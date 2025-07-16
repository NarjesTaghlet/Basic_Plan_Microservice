# Étape 1 : base image officielle
FROM node:18-alpine

# Étape 2 : créer répertoire de travail
WORKDIR /app

# Étape 3 : copier uniquement les fichiers de dépendances
COPY package*.json ./

# Étape 4 : installer toutes les dépendances (axios compris)
RUN npm install --legacy-peer-deps

RUN ls node_modules/axios && echo "Axios OK"


# Étape 5 : copier le reste du code
COPY . .

# Étape 6 : compiler le projet NestJS
RUN npm run build

# Étape 7 : exposer le port utilisé par l'app
EXPOSE 3032

# Étape 8 : lancer l'application
CMD ["node", "dist/main.js"]
