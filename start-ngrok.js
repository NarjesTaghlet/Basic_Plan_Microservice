const ngrok = require('ngrok');

async function startNgrok() {
  try {
    const url = await ngrok.connect({
      proto: 'http',
      addr: 3003, // Microservice déploiement
      authtoken: '2pl26Q9ezBPhit5DZ0utm9kODyx_6hhZ82WTqixtPSV5rSWij', // Remplace par ton authtoken
    });
    console.log('Ngrok tunnel créé:', url);
  } catch (error) {
    console.error('Erreur lors du démarrage de ngrok:', error.message);
  }
}

startNgrok();