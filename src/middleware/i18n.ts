import i18next from 'i18next';
import middleware from 'i18next-http-middleware';
import resourcesToBackend from 'i18next-resources-to-backend';
import fs from 'fs';
import path from 'path';

i18next
  .use(resourcesToBackend((lng: string, ns: string) => {
    const filepath = path.join(__dirname, `../locales/${lng}/${ns}.json`);
    return new Promise((resolve, reject) => {
      fs.readFile(filepath, 'utf-8', (err, data) => {
        if (err) return reject(err);
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(e);
        }
      });
    });
  }))
  .use(middleware.LanguageDetector)
  .init({
    fallbackLng: 'zh',
    preload: ['zh', 'en'],
    ns: ['translation'],
    defaultNS: 'translation',
    detection: {
      order: ['header', 'querystring', 'cookie'],
      caches: false
    },
    // debug: process.env.NODE_ENV === 'development'
    debug: process.env.NODE_ENV === 'production'
  });

export default middleware.handle(i18next);
