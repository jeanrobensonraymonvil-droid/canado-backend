/**
 * CANADO TECHNIQUE — Serveur Backend
 * Proxy sécurisé entre le site et l'API Anthropic (Rooby IA)
 *
 * Installation : npm install
 * Démarrage    : node server.js (ou npm start)
 * Production   : pm2 start server.js --name canado-backend
 */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');
const Anthropic  = require('@anthropic-ai/sdk');

const app  = express();
const port = process.env.PORT || 3000;

/* ════════════════════════════════════
   CLIENT ANTHROPIC
════════════════════════════════════ */
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
});

/* ════════════════════════════════════
   MIDDLEWARES
════════════════════════════════════ */
app.use(express.json({ limit: '10kb' }));

// CORS — autoriser uniquement ton domaine en production
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Non autorisé par CORS'));
    }
  }
}));

// Limite STRICTE sur les routes IA (elles coûtent des jetons Anthropic) : 20/min par IP
const limiterIA = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes. Réessayez dans une minute.' }
});
app.use('/api/rooby', limiterIA);
app.use('/api/generate-exam', limiterIA);
app.use('/api/synthesize-evals', limiterIA);

// Limite SOUPLE sur l'API de certification : un formateur saisit vite,
// une limite à 20/min le bloquerait en pleine session d'évaluation.
const limiterAPI = rateLimit({
  windowMs: 60 * 1000,
  max: 200,
  message: { error: 'Trop de requêtes. Réessayez dans une minute.' }
});
app.use('/api/v1', limiterAPI);

/* ════════════════════════════════════
   SYSTEM PROMPT ROOBY
════════════════════════════════════ */
const ROOBY_SYSTEM = `Tu es Rooby, l'assistant IA officiel de Canado Technique (Centre de Formation Professionnelle d'Haïti).
Tu réponds en français ou en créole haïtien selon la langue de l'utilisateur. Tu es chaleureux, professionnel et concis.

INFORMATIONS SUR L'ÉCOLE :
- Nom complet : Canado Technique / CFPH-Canado Technique
- Adresse : 157 Avenue Martin Luther King, Port-au-Prince, Haïti
- Site : canadotechnique.tech | Email : info@canadotechnique.tech
- Directeur : Gary Pierre
- Approche pédagogique : APC (Approche Par Compétences), homologuée MENFP
- Plus de 72 000 étudiants formés depuis la fondation, 50+ ans d'expérience
- 4 filières, 108 modules au total, 1 800 heures par filière (programme APC homologué MENFP)

PROGRAMMES OFFERTS (4 filières — 1ère et 2ème année) :
1. TRI — Techniques de Réseaux Informatiques (28 modules)
   Réseaux, Cisco CCNA, Windows Server, Linux, Sécurité réseau, Cloud, Python, etc.

2. MEI — Mécanique d'Entretien Industrielle (28 modules)
   Usinage, Soudage, Machines-outils, Lubrification, Hydraulique, Pneumatique, etc.

3. ELM — Électromécanique (26 modules : 13 an1 + 13 an2 — 1 800 heures)
   Circuits CC/CA, Électrification de bâtiments, Moteurs, Groupes électrogènes,
   Pneumatique, Hydraulique, Électronique de puissance, Automates, Dépannage, Maintenance.

4. TEL — Télécommunications (26 modules)
   Antennes, Fibre optique, Téléphonie IP, Réseaux sans fil, Câblodistribution, etc.

SPÉCIALISATIONS (3ème année) :
- TRI → TEL : Après 2 ans en TRI, spécialisation en Télécommunications
- TEL → TRI : Après 2 ans en TEL, spécialisation en Réseaux Informatiques

TARIFS (HTG = Gourdes haïtiennes | 1 USD ≈ 133 HTG) :
- TRI : 1ère an. 4 500 HTG | 2ème an. 5 000 HTG | Complet 8 500 HTG (économie 1 000 HTG)
- MEI : 1ère an. 4 000 HTG | 2ème an. 4 500 HTG | Complet 7 500 HTG (économie 1 000 HTG)
- ELM : 1ère an. 4 200 HTG | 2ème an. 4 700 HTG | Complet 8 000 HTG (économie  900 HTG)
- TEL : 1ère an. 4 000 HTG | 2ème an. 4 500 HTG | Complet 7 500 HTG (économie 1 000 HTG)
- Frais généraux : 550 USD (payables en versements)
- Écolage 1er versement : 77 100 HTG

COMPTES BANCAIRES UNIBANK (paiement par virement) :
- USD : # 2501-0220-1150886
- HTG : # 2501-0210-1150878
- Paiement en caisse aussi accepté au bureau

MODES DE PAIEMENT : Virement bancaire Unibank · Paiement en caisse · MonCash (bientôt) · NatCash (bientôt)

INSCRIPTION :
1. Choisir le programme et la formule
2. Effectuer le paiement (virement ou caisse)
3. Soumettre le formulaire en ligne avec preuve de paiement
4. Recevoir le matricule et les accès par email sous 24-48h

PLATEFORME E-LEARNING :
- Cours vidéo protégés (accès étudiant sécurisé)
- Examens QCM multi-versions
- Fiches d'évaluation module
- Portail professeur (gestion examens, cours détachés)
- Portail administration (validation inscriptions, credentials)
- Rapport de pilotage pour la direction
- Assistant IA Rooby disponible 24h/24

CERTIFICATIONS : Diplôme reconnu MENFP · Préparation Cisco CCNA · CompTIA · Microsoft

RÈGLES DE RÉPONSE :
- Sois concis et chaleureux, maximum 3-4 phrases par réponse
- Utilise des emojis avec modération
- Si tu ne sais pas quelque chose, dis de contacter info@canadotechnique.tech
- Pour les questions hors sujet, redirige vers les sujets de l'école
- Tu peux répondre en créole haïtien si l'utilisateur écrit en créole`;

/* ════════════════════════════════════
   ROUTE PRINCIPALE — /api/rooby
════════════════════════════════════ */
app.post('/api/rooby', async (req, res) => {
  const { messages } = req.body;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ error: 'Messages manquants ou invalides.' });
  }

  // Valider et nettoyer les messages
  const cleanMessages = messages
    .filter(m => m.role && m.content && typeof m.content === 'string')
    .slice(-20) // max 20 derniers messages pour garder le contexte
    .map(m => ({ role: m.role, content: m.content.slice(0, 2000) })); // max 2000 chars/msg

  if (cleanMessages.length === 0) {
    return res.status(400).json({ error: 'Aucun message valide.' });
  }

  try {
    const response = await anthropic.messages.create({
      model:      'claude-sonnet-4-5',
      max_tokens: 800,
      system:     ROOBY_SYSTEM,
      messages:   cleanMessages,
    });

    const reply = response.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('');

    res.json({ reply });

  } catch (err) {
    console.error('[Rooby] Erreur API Anthropic:', err.message);
    res.status(500).json({
      error: 'Service temporairement indisponible.',
      reply: 'Désolé, je rencontre un problème technique. Contactez-nous à info@canadotechnique.tech 📧'
    });
  }
});

/* ════════════════════════════════════
   ROUTE — /api/generate-exam
   Génération de questions d'examen par IA
════════════════════════════════════ */
app.post('/api/generate-exam', async (req, res) => {
  const { module_code, module_titre, programme, annee, nb_questions = 10, prompt_override } = req.body;
  if (!module_code || !module_titre) {
    return res.status(400).json({ error: 'module_code et module_titre requis.' });
  }

  // Si un prompt complet est fourni (depuis l'exam builder avancé), l'utiliser directement
  const prompt = prompt_override || `Tu es un expert en formation technique professionnelle en Haïti (CFPH - Canado Technique).
Génère exactement ${nb_questions} questions QCM pour l'examen du module suivant :

- Code : ${module_code}
- Titre : ${module_titre}
- Programme : ${programme} (${annee === '1' ? '1ère' : '2ème'} année)

Chaque question doit :
- Être pertinente et adaptée au niveau technique du module
- Avoir exactement 4 choix de réponse (A, B, C, D)
- Avoir une seule bonne réponse
- Varier entre connaissances théoriques et applications pratiques

Réponds UNIQUEMENT en JSON valide, sans markdown, sans explication, format exact :
{
  "questions": [
    {
      "numero": 1,
      "question": "Texte de la question ?",
      "choix": { "A": "Premier choix", "B": "Deuxième choix", "C": "Troisième choix", "D": "Quatrième choix" },
      "reponse": "A",
      "explication": "Courte explication de la bonne réponse."
    }
  ]
}`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }]
    });

    const raw = response.content.filter(b => b.type === 'text').map(b => b.text).join('');
    const clean = raw.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);
    res.json(parsed);

  } catch (err) {
    console.error('[generate-exam] Erreur:', err.message);
    res.status(500).json({ error: 'Impossible de générer les questions.', details: err.message });
  }
});

/* ════════════════════════════════════
   ROUTE — /api/synthesize-evals
   Synthèse IA des évaluations étudiants
════════════════════════════════════ */
app.post('/api/synthesize-evals', async (req, res) => {
  const { module_code, module_titre, programme, evaluations } = req.body;
  if (!evaluations || !evaluations.length) {
    return res.status(400).json({ error: 'Aucune évaluation fournie.' });
  }

  // Préparer un résumé des données pour l'IA
  const nb = evaluations.length;
  const avgContenu = (evaluations.reduce((s,e) => s+(e.note_contenu||0), 0)/nb).toFixed(1);
  const avgProf    = (evaluations.reduce((s,e) => s+(e.note_prof||0), 0)/nb).toFixed(1);
  const avgSupport = (evaluations.reduce((s,e) => s+(e.note_support||0), 0)/nb).toFixed(1);
  const avgOrga    = (evaluations.reduce((s,e) => s+(e.note_organisation||0), 0)/nb).toFixed(1);
  const recoRate   = Math.round(evaluations.filter(e=>e.recommande).length/nb*100);
  const commentaires = evaluations
    .map(e => e.commentaire || '')
    .filter(c => c.length > 5)
    .slice(0, 15)
    .join('\n- ');

  const prompt = `Tu es un conseiller pédagogique expert pour Canado Technique (CFPH, Haïti).
Analyse les évaluations suivantes soumises par les étudiants après le module :

MODULE : ${module_code} — ${module_titre} (Programme ${programme})
NOMBRE D'ÉVALUATIONS : ${nb}

NOTES MOYENNES (sur 5) :
- Contenu du cours : ${avgContenu}/5
- Qualité du professeur : ${avgProf}/5
- Supports pédagogiques : ${avgSupport}/5
- Organisation : ${avgOrga}/5
- Taux de recommandation : ${recoRate}%

COMMENTAIRES DES ÉTUDIANTS :
- ${commentaires || 'Aucun commentaire libre.'}

Génère un rapport pédagogique structuré et bienveillant destiné au professeur.
Réponds UNIQUEMENT en JSON valide, sans markdown :
{
  "resume_executif": "2-3 phrases résumant la performance globale du module.",
  "points_forts": [
    "Point fort 1 concret et précis",
    "Point fort 2",
    "Point fort 3"
  ],
  "points_amelioration": [
    "Point à améliorer 1 avec suggestion concrète",
    "Point à améliorer 2",
    "Point à améliorer 3"
  ],
  "recommandations_pedagogiques": [
    "Recommandation actionnable 1",
    "Recommandation actionnable 2",
    "Recommandation actionnable 3"
  ],
  "message_prof": "Message encourageant et constructif de 2-3 phrases directement adressé au professeur."
}`;

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5',
      max_tokens: 1500,
      messages: [{ role: 'user', content: prompt }]
    });

    const raw = response.content.filter(b => b.type === 'text').map(b => b.text).join('');
    const clean = raw.replace(/```json|```/g, '').trim();
    const parsed = JSON.parse(clean);

    res.json({
      ...parsed,
      module_code,
      module_titre,
      programme,
      nb_evaluations: nb,
      notes: { contenu: avgContenu, prof: avgProf, support: avgSupport, organisation: avgOrga },
      taux_recommandation: recoRate,
      date_synthese: new Date().toISOString()
    });

  } catch (err) {
    console.error('[synthesize-evals] Erreur:', err.message);
    res.status(500).json({ error: 'Impossible de synthétiser les évaluations.', details: err.message });
  }
});

/* ════════════════════════════════════
   HEALTH CHECK
════════════════════════════════════ */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Canado Technique Backend',
    rooby: 'opérationnel',
    certification: process.env.DATABASE_URL ? 'active (voir /api/v1/health)' : 'inactive (DATABASE_URL manquante)',
    timestamp: new Date().toISOString()
  });
});

/* ════════════════════════════════════
   API DE CERTIFICATION  (/api/v1)
   Tables, grilles officielles et compte direction
   s'installent automatiquement au démarrage.
════════════════════════════════════ */
require('./certification')(app);

/* ════════════════════════════════════
   DÉMARRAGE
════════════════════════════════════ */
app.listen(port, () => {
  console.log(`\n🚀 Canado Technique Backend démarré`);
  console.log(`   Port          : ${port}`);
  console.log(`   Rooby IA      : POST /api/rooby`);
  console.log(`   Certification : /api/v1  (login, évaluations, diplômes, vérification)`);
  console.log(`   Health        : GET  /api/health  ·  GET /api/v1/health\n`);

  if (!process.env.ANTHROPIC_API_KEY) console.warn('⚠️  ANTHROPIC_API_KEY manquante.');
  if (!process.env.DATABASE_URL)      console.warn('⚠️  DATABASE_URL manquante → certification désactivée.');
  if (!process.env.JWT_SECRET)        console.warn('⚠️  JWT_SECRET manquante → sessions non sécurisées !');
  if (!process.env.SEAL_SECRET)       console.warn('⚠️  SEAL_SECRET manquante → scellement non sécurisé !');
});
