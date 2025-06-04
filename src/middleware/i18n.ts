import i18next from 'i18next';
import middleware from 'i18next-http-middleware';
import resourcesToBackend from 'i18next-resources-to-backend';

i18next
  .use(resourcesToBackend((lng: unknown, ns: unknown) => {
    // 動態載入 locales/zh/translation.ts
    return import(`../locales/${lng}/${ns}.ts`);
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
    debug: process.env.NODE_ENV === 'development'
  });

export default middleware.handle(i18next);
