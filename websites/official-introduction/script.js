
const dict = window.ARENYXA_I18N || {};
const metaDescription = document.querySelector('meta[name="description"]');
const htmlEl = document.documentElement;
const languageSelect = document.getElementById('languageSelect');

const deepNavigation = {
  'zh-CN': {engine_detail_e:'引擎深度解析',enterprise_detail_e:'企业模型',root_detail_e:'Root 开发者',performance_detail_e:'性能与并发',release_detail_e:'发布工程',scope_detail_e:'平台方向'},
  'zh-TW': {engine_detail_e:'引擎深度解析',enterprise_detail_e:'企業模型',root_detail_e:'Root 開發者',performance_detail_e:'效能與並行',release_detail_e:'發布工程',scope_detail_e:'平台方向'},
  en: {engine_detail_e:'Engine Deep Dive',enterprise_detail_e:'Enterprise Model',root_detail_e:'Root Developer',performance_detail_e:'Performance & Concurrency',release_detail_e:'Release Engineering',scope_detail_e:'Platform Direction'},
  ja: {engine_detail_e:'エンジン詳細',enterprise_detail_e:'エンタープライズモデル',root_detail_e:'Root Developer',performance_detail_e:'性能と並行性',release_detail_e:'リリースエンジニアリング',scope_detail_e:'プラットフォーム方針'},
  ko: {engine_detail_e:'엔진 심층 분석',enterprise_detail_e:'엔터프라이즈 모델',root_detail_e:'Root Developer',performance_detail_e:'성능 및 동시성',release_detail_e:'릴리스 엔지니어링',scope_detail_e:'플랫폼 방향'},
  de: {engine_detail_e:'Engine-Vertiefung',enterprise_detail_e:'Enterprise-Modell',root_detail_e:'Root Developer',performance_detail_e:'Leistung & Nebenläufigkeit',release_detail_e:'Release Engineering',scope_detail_e:'Plattformrichtung'},
  fr: {engine_detail_e:'Analyse des moteurs',enterprise_detail_e:'Modèle Enterprise',root_detail_e:'Root Developer',performance_detail_e:'Performances et concurrence',release_detail_e:'Ingénierie des versions',scope_detail_e:'Orientation de la plateforme'},
  es: {engine_detail_e:'Análisis de motores',enterprise_detail_e:'Modelo Enterprise',root_detail_e:'Root Developer',performance_detail_e:'Rendimiento y concurrencia',release_detail_e:'Ingeniería de versiones',scope_detail_e:'Dirección de la plataforma'},
  ru: {engine_detail_e:'Подробно о движках',enterprise_detail_e:'Корпоративная модель',root_detail_e:'Root Developer',performance_detail_e:'Производительность и параллелизм',release_detail_e:'Инженерия релизов',scope_detail_e:'Направление платформы'}
};
for (const [language, values] of Object.entries(deepNavigation)) Object.assign(dict[language] || (dict[language] = {}), values);

function resolveLanguage(raw) {
  const candidates = Array.isArray(raw) ? raw : [raw];
  for (const candidate of candidates) {
    const v = String(candidate || '').toLowerCase();
    if (v.startsWith('zh-tw') || v.startsWith('zh-hk') || v.startsWith('zh-hant')) return 'zh-TW';
    if (v.startsWith('zh-cn') || v.startsWith('zh-sg') || v.startsWith('zh-hans') || v === 'zh') return 'zh-CN';
    if (v.startsWith('en')) return 'en';
    for (const code of ['ja','ko','de','fr','es','ru']) if (v.startsWith(code)) return code;
  }
  return 'en';
}
function applyLanguage(lang) {
  const selected = dict[lang] ? lang : 'en';
  try { localStorage.setItem('arenyxa-intro-lang', selected); } catch (error) {}
  htmlEl.lang = selected;
  document.body.dataset.lang = selected;
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.dataset.i18n;
    const value = dict[selected]?.[key] ?? dict.en?.[key] ?? dict['zh-CN']?.[key];
    if (value != null) el.textContent = value;
  });
  document.querySelectorAll('.dual').forEach(el => {
    const value = selected === 'zh-CN' || selected === 'zh-TW' ? el.dataset.zh : el.dataset.en;
    if (value) el.textContent = value;
  });
  document.title = dict[selected]?.title || dict.en.title;
  if (metaDescription) metaDescription.content = dict[selected]?.hero_lead || dict.en.hero_lead;
  if (languageSelect) languageSelect.value = selected;
}
let savedLanguage = null;
try { savedLanguage = localStorage.getItem('arenyxa-intro-lang'); } catch (error) {}
applyLanguage(savedLanguage || resolveLanguage(navigator.languages?.length ? navigator.languages : navigator.language));
if (languageSelect) languageSelect.addEventListener('change', e => applyLanguage(e.target.value));

const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const revealItems = [...document.querySelectorAll('.reveal')];
if (reducedMotion) {
  revealItems.forEach(el => el.classList.add('visible'));
} else {
  const revealObserver = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      } else {
        const r = entry.boundingClientRect;
        const vh = window.innerHeight || document.documentElement.clientHeight;
        if (r.bottom < -28 || r.top > vh + 28) entry.target.classList.remove('visible');
      }
    });
  }, {threshold:[0,.10,.28],rootMargin:'28px 0px 28px 0px'});
  revealItems.forEach((el,index) => {
    el.style.transitionDelay = `${Math.min(index % 4, 3) * 32}ms`;
    revealObserver.observe(el);
  });
}
const sideLinks=[...document.querySelectorAll('.side-index a')];
const sections=sideLinks.map(a=>document.querySelector(a.getAttribute('href'))).filter(Boolean);
function updateIndex(){const y=window.scrollY+150;let current=sections[0]?.id;for(const section of sections)if(section.offsetTop<=y)current=section.id;sideLinks.forEach(a=>a.classList.toggle('active',a.getAttribute('href')===`#${current}`));}
window.addEventListener('scroll',updateIndex,{passive:true});updateIndex();
