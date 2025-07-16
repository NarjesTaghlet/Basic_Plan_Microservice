# Étape 1 : base image officielle
FROM node:18-alpine

# Étape 2 : créer répertoire de travail
WORKDIR /app

# Étape 3 : copier uniquement les fichiers de dépendances
COPY package*.json ./

# Étape 4 : installer toutes les dépendances (axios compris)
RUN npm install --legacy-peer-deps

RUN npm list axios || { echo "axios missing!"; exit 1; }

RUN npm install --save @types/axios

RUN npm install --save @nestjs/axios



COPY . .

# Étape 6 : compiler le projet NestJS
RUN npm run build

# Étape 7 : exposer le port utilisé par l'app
EXPOSE 3032



CMD ["node", "dist/main.js"]
