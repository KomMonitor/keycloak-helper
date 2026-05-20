const winston = require('winston');

const customFormat = winston.format.printf(({ timestamp, level, message, service }) => {
  return `${timestamp} [${service}] ${level.toUpperCase()}: ${message}`;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    customFormat
  ),
  defaultMeta: { service: 'kommonitor-client-config' },
  transports: [
    new winston.transports.Console(),
  ],
});

module.exports = logger;
