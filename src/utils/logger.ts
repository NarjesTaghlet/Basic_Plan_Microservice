import * as winston from 'winston';
import * as path from 'path';

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} - ${level.toUpperCase()} - ${message}`;
    }),
  ),
  transports: [
    new winston.transports.File({
      filename: path.join(__dirname, '..', '..', 'logs', 'deployment.log'),
    }),
    new winston.transports.Console(),
  ],
});

export default logger;