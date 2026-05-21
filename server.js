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

// Limite : max 20 messages / minute par IP (anti-abus)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Trop de requêtes. Réessayez dans une minute.' }
});
app.use('/api/', limiter);

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
- Plus de 1642 étudiants inscrits, 12+ ans d'expérience

PROGRAMMES OFFERTS (4 filières — 1ère et 2ème année) :
1. TRI — Techniques de Réseaux Informatiques (28 modules : 16 an1 + 12 an2)
   Réseaux, Cisco CCNA, Windows Server, Linux, Sécurité réseau, Cloud, Python, etc.

2. MEI — Mécanique d'Entretien Industrielle (28 modules : 16 an1 + 12 an2)
   Usinage, Soudage, Machines-outils, Lubrification, Hydraulique, Pneumatique, etc.

3. ELM — Électromécanique Industrielle (25 modules : 13 an1 + 12 an2)
   Circuits CC/CA, Moteurs, Automatismes, Électronique, Groupes électrogènes, etc.

4. TEL — Télécommunications (26 modules : 14 an1 + 12 an2)
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
      model:      'claude-sonnet-4-20250514',
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
   HEALTH CHECK
════════════════════════════════════ */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Canado Technique Backend',
    rooby: 'opérationnel',
    timestamp: new Date().toISOString()
  });
});

/* ════════════════════════════════════
   DÉMARRAGE
════════════════════════════════════ */
app.listen(port, () => {
  console.log(`\n🚀 Canado Technique Backend démarré`);
  console.log(`   Port     : ${port}`);
  console.log(`   Rooby IA : POST /api/rooby`);
  console.log(`   Health   : GET  /api/health\n`);

  if (!process.env.ANTHROPIC_API_KEY) {
    console.warn('⚠️  ANTHROPIC_API_KEY manquante ! Ajoutez-la dans le fichier .env');
  }
});
