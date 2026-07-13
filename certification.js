/**
 * CANADO TECHNIQUE — MODULE DE CERTIFICATION (auto-installable)
 * ═════════════════════════════════════════════════════════════
 *
 * INSTALLATION — 3 gestes :
 *
 *   1) npm install pg bcryptjs jsonwebtoken
 *
 *   2) Dans server.js, AVANT `app.listen(...)`, ajoute UNE ligne :
 *          require('./certification')(app);
 *
 *   3) Sur Railway, ajoute ces variables au service backend :
 *          JWT_SECRET     = <longue chaîne aléatoire>
 *          SEAL_SECRET    = <autre longue chaîne, différente>
 *          ADMIN_EMAIL    = direction@canadotechnique.tech
 *          ADMIN_PASSWORD = <mot de passe initial de la direction>
 *      (DATABASE_URL est déjà injectée par Railway.)
 *
 *   Push. Le serveur crée les tables, charge les 26 grilles officielles
 *   et le compte direction TOUT SEUL au démarrage. Rien à faire dans psql.
 *
 * PRINCIPE : une évaluation signée est IMMUABLE (trigger SQL).
 * Une reprise = une NOUVELLE tentative. C'est ce qui rend le diplôme opposable.
 */

const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');

const JWT_SECRET  = process.env.JWT_SECRET  || 'CHANGEZ-MOI';
const SEAL_SECRET = process.env.SEAL_SECRET || 'CHANGEZ-MOI-AUSSI';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: (process.env.DATABASE_URL || '').includes('localhost') ? false : { rejectUnauthorized: false }
});

const sceller = (o) => crypto.createHmac('sha256', SEAL_SECRET).update(JSON.stringify(o)).digest('hex');

/* ════════════════════════════════════════════════════
   SCHÉMA — idempotent : peut être rejoué sans risque
════════════════════════════════════════════════════ */
const SCHEMA = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS utilisateurs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  mot_de_passe TEXT NOT NULL,
  nom TEXT NOT NULL, prenom TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('etudiant','formateur','direction','admin')),
  actif BOOLEAN NOT NULL DEFAULT TRUE,
  cree_le TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS etudiants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  utilisateur_id UUID UNIQUE REFERENCES utilisateurs(id) ON DELETE SET NULL,
  matricule TEXT UNIQUE NOT NULL,
  nom TEXT NOT NULL, prenom TEXT NOT NULL,
  date_naissance DATE, telephone TEXT,
  filiere TEXT NOT NULL CHECK (filiere IN ('TRI','MEI','ELM','TEL')),
  cohorte TEXT NOT NULL,
  statut TEXT NOT NULL DEFAULT 'actif' CHECK (statut IN ('actif','suspendu','diplome','abandon')),
  inscrit_le TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE IF NOT EXISTS modules (
  code TEXT PRIMARY KEY,
  filiere TEXT NOT NULL, annee SMALLINT NOT NULL CHECK (annee IN (1,2)),
  titre TEXT NOT NULL, enonce TEXT, heures SMALLINT NOT NULL,
  type_objectif TEXT NOT NULL CHECK (type_objectif IN ('comportement','situation')),
  seuil_points SMALLINT, seuil_criteres SMALLINT, total_criteres SMALLINT,
  duree_epreuve TEXT, grille_officielle BOOLEAN NOT NULL DEFAULT FALSE,
  actif BOOLEAN NOT NULL DEFAULT TRUE);
ALTER TABLE modules ADD COLUMN IF NOT EXISTS grille_officielle BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS criteres (
  id SERIAL PRIMARY KEY,
  module_code TEXT NOT NULL REFERENCES modules(code) ON DELETE CASCADE,
  ordre SMALLINT NOT NULL, libelle TEXT NOT NULL,
  points SMALLINT, obligatoire BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (module_code, ordre));

CREATE TABLE IF NOT EXISTS inscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  etudiant_id UUID NOT NULL REFERENCES etudiants(id) ON DELETE CASCADE,
  module_code TEXT NOT NULL REFERENCES modules(code),
  debut_le DATE, UNIQUE (etudiant_id, module_code));

CREATE TABLE IF NOT EXISTS evaluations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  etudiant_id UUID NOT NULL REFERENCES etudiants(id) ON DELETE RESTRICT,
  module_code TEXT NOT NULL REFERENCES modules(code),
  formateur_id UUID NOT NULL REFERENCES utilisateurs(id),
  tentative SMALLINT NOT NULL DEFAULT 1,
  date_epreuve DATE NOT NULL,
  points_obtenus SMALLINT, criteres_valides SMALLINT,
  detail JSONB NOT NULL,
  verdique BOOLEAN NOT NULL DEFAULT FALSE, motif_verdique TEXT,
  mention TEXT NOT NULL CHECK (mention IN ('REUSSITE','ECHEC')),
  observations TEXT,
  signee_le TIMESTAMPTZ NOT NULL DEFAULT now(),
  scellement TEXT NOT NULL,
  annulee BOOLEAN NOT NULL DEFAULT FALSE, motif_annulation TEXT,
  UNIQUE (etudiant_id, module_code, tentative));

CREATE INDEX IF NOT EXISTS idx_eval_etu ON evaluations(etudiant_id);
CREATE INDEX IF NOT EXISTS idx_eval_mod ON evaluations(module_code);

CREATE TABLE IF NOT EXISTS certificats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  numero TEXT UNIQUE NOT NULL,
  etudiant_id UUID NOT NULL REFERENCES etudiants(id),
  filiere TEXT NOT NULL,
  delivre_par UUID NOT NULL REFERENCES utilisateurs(id),
  delivre_le TIMESTAMPTZ NOT NULL DEFAULT now(),
  modules_valides JSONB NOT NULL, total_heures SMALLINT NOT NULL,
  scellement TEXT NOT NULL,
  revoque BOOLEAN NOT NULL DEFAULT FALSE, motif_revocation TEXT);

CREATE TABLE IF NOT EXISTS journal (
  id BIGSERIAL PRIMARY KEY,
  utilisateur_id UUID REFERENCES utilisateurs(id),
  action TEXT NOT NULL, cible TEXT, donnees JSONB, ip TEXT,
  horodatage TIMESTAMPTZ NOT NULL DEFAULT now());

-- 🔒 Une évaluation signée est IMMUABLE. Seule mutation permise : l'annulation, tracée.
CREATE OR REPLACE FUNCTION eval_immuable() RETURNS TRIGGER AS $fn$
BEGIN
  IF OLD.annulee = FALSE AND NEW.annulee = TRUE THEN RETURN NEW; END IF;
  RAISE EXCEPTION 'Évaluation signée immuable — créez une nouvelle tentative.';
END; $fn$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_eval_immuable ON evaluations;
CREATE TRIGGER trg_eval_immuable BEFORE UPDATE ON evaluations
  FOR EACH ROW EXECUTE FUNCTION eval_immuable();

CREATE OR REPLACE VIEW v_dossier AS
SELECT e.id AS etudiant_id, e.matricule, e.filiere,
       m.code, m.titre, m.heures, m.type_objectif,
       ev.mention, ev.points_obtenus, ev.criteres_valides,
       ev.tentative, ev.date_epreuve, ev.verdique
FROM etudiants e
CROSS JOIN modules m
LEFT JOIN LATERAL (
  SELECT * FROM evaluations x
   WHERE x.etudiant_id = e.id AND x.module_code = m.code AND NOT x.annulee
   ORDER BY (x.mention = 'REUSSITE') DESC, x.tentative DESC LIMIT 1
) ev ON TRUE
WHERE m.filiere = e.filiere AND m.actif;

CREATE OR REPLACE VIEW v_eligibilite AS
SELECT etudiant_id, matricule, filiere,
       COUNT(*) FILTER (WHERE mention='REUSSITE') AS modules_reussis,
       COUNT(*) AS modules_requis,
       COUNT(*) FILTER (WHERE mention='REUSSITE') = COUNT(*) AS eligible
FROM v_dossier GROUP BY etudiant_id, matricule, filiere;
`;

/* ════════════════════════════════════════════════════
   INSTALLATION AUTOMATIQUE AU DÉMARRAGE
════════════════════════════════════════════════════ */
async function installer() {
  if (!process.env.DATABASE_URL) {
    console.warn('⚠️  DATABASE_URL absente — certification désactivée.');
    return false;
  }
  const c = await pool.connect();
  try {
    await c.query(SCHEMA);
    console.log('   ✅ Schéma de certification en place');

    // ── Chargement des 26 grilles officielles ──
    const f = path.join(__dirname, 'grilles-evaluation.json');
    if (fs.existsSync(f)) {
      const grilles = JSON.parse(fs.readFileSync(f, 'utf-8'));
      for (const m of grilles) {
        await c.query(
          `INSERT INTO modules (code,filiere,annee,titre,enonce,heures,type_objectif,
                                seuil_points,seuil_criteres,total_criteres,duree_epreuve,grille_officielle)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (code) DO UPDATE SET
             titre=EXCLUDED.titre, enonce=EXCLUDED.enonce, heures=EXCLUDED.heures,
             type_objectif=EXCLUDED.type_objectif, seuil_points=EXCLUDED.seuil_points,
             seuil_criteres=EXCLUDED.seuil_criteres, total_criteres=EXCLUDED.total_criteres,
             duree_epreuve=EXCLUDED.duree_epreuve, grille_officielle=EXCLUDED.grille_officielle`,
          [m.code, m.filiere, m.annee, m.titre, m.enonce, m.heures, m.type_objectif,
           m.seuil_points, m.seuil_criteres, m.total_criteres, m.duree_epreuve || null,
           !!m.grille_officielle]);

        await c.query('DELETE FROM criteres WHERE module_code=$1', [m.code]);
        for (const cr of m.criteres) {
          await c.query(
            'INSERT INTO criteres (module_code,ordre,libelle,points,obligatoire) VALUES ($1,$2,$3,$4,$5)',
            [m.code, cr.ordre, cr.libelle, cr.points, !!cr.obligatoire]);
        }
      }
      const { rows } = await c.query(
        `SELECT filiere,
                COUNT(*) n,
                COUNT(*) FILTER (WHERE grille_officielle) officielles
           FROM modules GROUP BY filiere ORDER BY filiere`);
      const tot = rows.reduce((s2, r) => s2 + Number(r.n), 0);
      console.log(`   ✅ ${tot} modules chargés (4 filières) :`);
      rows.forEach(r => console.log(
        `        ${r.filiere} : ${r.n} modules · ${r.officielles} grille(s) officielle(s)` +
        (Number(r.officielles) ? '' : '  ⚠️ note globale (guide non dépouillé)')));
    } else {
      console.warn('   ⚠️  ELM-grilles-evaluation.json introuvable — grilles non chargées.');
    }

    // ── Compte direction initial ──
    if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 10);
      const r = await c.query(
        `INSERT INTO utilisateurs (email,mot_de_passe,nom,prenom,role)
         VALUES ($1,$2,'Direction','CFPH','direction')
         ON CONFLICT (email) DO NOTHING RETURNING id`,
        [process.env.ADMIN_EMAIL.toLowerCase(), hash]);
      if (r.rowCount) console.log(`   ✅ Compte direction créé : ${process.env.ADMIN_EMAIL}`);
    }
    return true;
  } catch (e) {
    console.error('   ❌ Installation certification :', e.message);
    return false;
  } finally { c.release(); }
}

/* ════════════════════════════════════════════════════
   ROUTES
════════════════════════════════════════════════════ */
module.exports = function (app) {
  installer();

  const auth = (...roles) => (req, res, next) => {
    const h = req.headers.authorization || '';
    const t = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!t) return res.status(401).json({ error: 'Authentification requise.' });
    try {
      req.user = jwt.verify(t, JWT_SECRET);
      if (roles.length && !roles.includes(req.user.role))
        return res.status(403).json({ error: 'Droits insuffisants.' });
      next();
    } catch { return res.status(401).json({ error: 'Session expirée.' }); }
  };

  const trace = (req, action, cible, donnees) => pool.query(
    'INSERT INTO journal (utilisateur_id,action,cible,donnees,ip) VALUES ($1,$2,$3,$4,$5)',
    [req.user?.id || null, action, cible, donnees || null, req.ip]).catch(() => {});

  /* ── AUTH ── */
  app.post('/api/v1/auth/login', async (req, res) => {
    const { email, mot_de_passe } = req.body || {};
    if (!email || !mot_de_passe) return res.status(400).json({ error: 'Email et mot de passe requis.' });
    try {
      const { rows } = await pool.query(
        'SELECT * FROM utilisateurs WHERE lower(email)=lower($1) AND actif', [email]);
      const u = rows[0];
      if (!u || !(await bcrypt.compare(mot_de_passe, u.mot_de_passe)))
        return res.status(401).json({ error: 'Identifiants invalides.' });
      const token = jwt.sign({ id: u.id, role: u.role, nom: u.nom, prenom: u.prenom },
        JWT_SECRET, { expiresIn: '12h' });
      res.json({ token, user: { id: u.id, nom: u.nom, prenom: u.prenom, role: u.role } });
    } catch { res.status(500).json({ error: 'Erreur serveur.' }); }
  });

  app.post('/api/v1/utilisateurs', auth('direction', 'admin'), async (req, res) => {
    const { email, mot_de_passe, nom, prenom, role } = req.body || {};
    if (!email || !mot_de_passe || !nom || !prenom || !role)
      return res.status(400).json({ error: 'Champs manquants.' });
    try {
      const hash = await bcrypt.hash(mot_de_passe, 10);
      const { rows } = await pool.query(
        `INSERT INTO utilisateurs (email,mot_de_passe,nom,prenom,role)
         VALUES ($1,$2,$3,$4,$5) RETURNING id,email,nom,prenom,role`,
        [email.toLowerCase(), hash, nom, prenom, role]);
      trace(req, 'user.create', email, { role });
      res.status(201).json(rows[0]);
    } catch (e) { res.status(400).json({ error: 'Email déjà utilisé ?' }); }
  });

  /* ── ÉTUDIANTS ── */
  app.get('/api/v1/etudiants', auth('formateur', 'direction', 'admin'), async (req, res) => {
    const { filiere, cohorte } = req.query;
    const { rows } = await pool.query(
      `SELECT id,matricule,nom,prenom,filiere,cohorte,statut FROM etudiants
        WHERE ($1::text IS NULL OR filiere=$1) AND ($2::text IS NULL OR cohorte=$2)
        ORDER BY nom,prenom`, [filiere || null, cohorte || null]);
    res.json(rows);
  });

  app.post('/api/v1/etudiants', auth('direction', 'admin'), async (req, res) => {
    const { nom, prenom, filiere, cohorte, telephone, date_naissance } = req.body || {};
    if (!nom || !prenom || !filiere || !cohorte)
      return res.status(400).json({ error: 'nom, prenom, filiere, cohorte requis.' });
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const { rows: n } = await c.query(
        'SELECT COUNT(*)+1 AS n FROM etudiants WHERE filiere=$1 AND cohorte=$2', [filiere, cohorte]);
      const matricule = `${filiere}-${cohorte}-${String(n[0].n).padStart(4, '0')}`;
      const { rows } = await c.query(
        `INSERT INTO etudiants (matricule,nom,prenom,filiere,cohorte,telephone,date_naissance)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [matricule, nom, prenom, filiere, cohorte, telephone || null, date_naissance || null]);
      await c.query('COMMIT');
      trace(req, 'etudiant.create', matricule, { nom, prenom, filiere });
      res.status(201).json(rows[0]);
    } catch (e) { await c.query('ROLLBACK'); res.status(500).json({ error: 'Création impossible.' }); }
    finally { c.release(); }
  });

  /* ── GRILLE OFFICIELLE D'UN MODULE ── */
  app.get('/api/v1/modules', auth(), async (req, res) => {
    const { rows } = await pool.query(
      'SELECT * FROM modules WHERE ($1::text IS NULL OR filiere=$1) ORDER BY code',
      [req.query.filiere || null]);
    res.json(rows);
  });

  app.get('/api/v1/modules/:code/grille', auth(), async (req, res) => {
    const { rows: m } = await pool.query('SELECT * FROM modules WHERE code=$1', [req.params.code]);
    if (!m[0]) return res.status(404).json({ error: 'Module inconnu.' });
    const { rows: c } = await pool.query(
      'SELECT ordre,libelle,points,obligatoire FROM criteres WHERE module_code=$1 ORDER BY ordre',
      [req.params.code]);
    res.json({ module: m[0], criteres: c });
  });

  /* ── ÉVALUATION SOMMATIVE (le cœur) ── */
  app.post('/api/v1/evaluations', auth('formateur', 'direction', 'admin'), async (req, res) => {
    const { etudiant_id, module_code, date_epreuve, detail, note_globale,
            verdique = false, motif_verdique, observations } = req.body || {};
    if (!etudiant_id || !module_code || !date_epreuve)
      return res.status(400).json({ error: 'etudiant_id, module_code, date_epreuve requis.' });
    if (!detail && note_globale == null)
      return res.status(400).json({ error: 'Fournir « detail » (grille) ou « note_globale » (/100).' });
    if (verdique && !motif_verdique)
      return res.status(400).json({ error: 'Un manquement grave doit être motivé.' });

    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const { rows: mm } = await c.query('SELECT * FROM modules WHERE code=$1', [module_code]);
      const mod = mm[0];
      if (!mod) throw new Error('Module inconnu.');
      const { rows: cc } = await c.query(
        'SELECT ordre,points,obligatoire FROM criteres WHERE module_code=$1 ORDER BY ordre', [module_code]);

      // ⚖️ Mention calculée CÔTÉ SERVEUR — jamais côté client.
      let points = null, valides = null, mention;
      const grille = cc.length > 0;

      if (!grille) {
        // ── Aucune grille officielle chargée : NOTE GLOBALE /100 ──
        // (TRI / TEL / MEI, en attendant le dépouillement de leurs Guides d'évaluation)
        points = Number(note_globale);
        if (!Number.isFinite(points) || points < 0 || points > 100)
          throw new Error('note_globale doit être un nombre entre 0 et 100.');
        mention = (!verdique && points >= mod.seuil_points) ? 'REUSSITE' : 'ECHEC';

      } else if (mod.type_objectif === 'comportement') {
        points = cc.reduce((s, x) => s + (Number(detail[x.ordre]) || 0), 0);
        const maxi = cc.reduce((s, x) => s + (x.points || 0), 0);
        if (points > maxi) throw new Error(`Total ${points} > barème ${maxi}.`);
        mention = (!verdique && points >= mod.seuil_points) ? 'REUSSITE' : 'ECHEC';

      } else {
        valides = cc.filter(x => !!detail[x.ordre]).length;
        const oblig = cc.filter(x => x.obligatoire).every(x => !!detail[x.ordre]);
        mention = (!verdique && valides >= mod.seuil_criteres && oblig) ? 'REUSSITE' : 'ECHEC';
      }

      const { rows: t } = await c.query(
        'SELECT COALESCE(MAX(tentative),0)+1 AS n FROM evaluations WHERE etudiant_id=$1 AND module_code=$2',
        [etudiant_id, module_code]);
      const tentative = t[0].n;
      const seal = sceller({ etudiant_id, module_code, tentative, date_epreuve,
                             points, valides, mention, verdique, formateur: req.user.id });

      const { rows } = await c.query(
        `INSERT INTO evaluations (etudiant_id,module_code,formateur_id,tentative,date_epreuve,
            points_obtenus,criteres_valides,detail,verdique,motif_verdique,mention,observations,scellement)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
        [etudiant_id, module_code, req.user.id, tentative, date_epreuve,
         points, valides, detail || { note_globale: points }, verdique,
         motif_verdique || null, mention, observations || null, seal]);

      await c.query('COMMIT');
      trace(req, 'eval.create', `${module_code}/${etudiant_id}`, { mention, points, valides, tentative, verdique });
      res.status(201).json(rows[0]);
    } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
    finally { c.release(); }
  });

  app.post('/api/v1/evaluations/:id/annuler', auth('direction', 'admin'), async (req, res) => {
    const { motif } = req.body || {};
    if (!motif) return res.status(400).json({ error: 'Motif obligatoire.' });
    await pool.query('UPDATE evaluations SET annulee=TRUE, motif_annulation=$2 WHERE id=$1',
      [req.params.id, motif]);
    trace(req, 'eval.cancel', req.params.id, { motif });
    res.json({ ok: true });
  });

  /* ── DOSSIER ÉTUDIANT ── */
  app.get('/api/v1/etudiants/:id/dossier', auth(), async (req, res) => {
    if (req.user.role === 'etudiant') {
      const { rows } = await pool.query('SELECT id FROM etudiants WHERE utilisateur_id=$1', [req.user.id]);
      if (!rows[0] || rows[0].id !== req.params.id)
        return res.status(403).json({ error: 'Accès refusé.' });
    }
    const { rows } = await pool.query('SELECT * FROM v_dossier WHERE etudiant_id=$1 ORDER BY code', [req.params.id]);
    const { rows: e } = await pool.query('SELECT * FROM v_eligibilite WHERE etudiant_id=$1', [req.params.id]);
    const heures = rows.filter(r => r.mention === 'REUSSITE').reduce((s, r) => s + r.heures, 0);
    res.json({ modules: rows, eligibilite: e[0] || null, heures_acquises: heures });
  });

  /* ── DIPLÔME ── */
  app.post('/api/v1/certificats', auth('direction', 'admin'), async (req, res) => {
    const { etudiant_id } = req.body || {};
    const c = await pool.connect();
    try {
      await c.query('BEGIN');
      const { rows: el } = await c.query('SELECT * FROM v_eligibilite WHERE etudiant_id=$1', [etudiant_id]);
      if (!el[0]?.eligible)
        throw new Error(`Non éligible : ${el[0]?.modules_reussis || 0}/${el[0]?.modules_requis || 0} modules validés.`);

      const { rows: d } = await c.query(
        'SELECT code,titre,mention,points_obtenus,criteres_valides,heures FROM v_dossier WHERE etudiant_id=$1 ORDER BY code',
        [etudiant_id]);
      const { rows: et } = await c.query('SELECT * FROM etudiants WHERE id=$1', [etudiant_id]);
      const e = et[0];
      const an = new Date().getFullYear();
      const { rows: n } = await c.query(
        'SELECT COUNT(*)+1 AS n FROM certificats WHERE numero LIKE $1', [`CFPH-${e.filiere}-${an}-%`]);
      const numero = `CFPH-${e.filiere}-${an}-${String(n[0].n).padStart(4, '0')}`;
      const heures = d.reduce((s, x) => s + x.heures, 0);
      const seal = sceller({ numero, matricule: e.matricule, filiere: e.filiere, modules: d, heures });

      const { rows } = await c.query(
        `INSERT INTO certificats (numero,etudiant_id,filiere,delivre_par,modules_valides,total_heures,scellement)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [numero, etudiant_id, e.filiere, req.user.id, JSON.stringify(d), heures, seal]);
      await c.query("UPDATE etudiants SET statut='diplome' WHERE id=$1", [etudiant_id]);
      await c.query('COMMIT');
      trace(req, 'cert.deliver', numero, { matricule: e.matricule, heures });
      res.status(201).json(rows[0]);
    } catch (e) { await c.query('ROLLBACK'); res.status(400).json({ error: e.message }); }
    finally { c.release(); }
  });

  /* ── VÉRIFICATION PUBLIQUE (QR code) — sans authentification ── */
  app.get('/api/v1/verifier/:numero', async (req, res) => {
    const { rows } = await pool.query(
      `SELECT c.numero,c.filiere,c.delivre_le,c.total_heures,c.modules_valides,c.revoque,
              e.nom,e.prenom,e.matricule
         FROM certificats c JOIN etudiants e ON e.id=c.etudiant_id
        WHERE c.numero=$1`, [req.params.numero]);
    const c = rows[0];
    if (!c) return res.status(404).json({ valide: false, message: 'Certificat introuvable.' });
    if (c.revoque) return res.json({ valide: false, message: 'Certificat révoqué.' });
    res.json({
      valide: true, numero: c.numero,
      titulaire: `${c.prenom} ${c.nom}`, matricule: c.matricule,
      filiere: c.filiere, delivre_le: c.delivre_le, total_heures: c.total_heures,
      modules: c.modules_valides,
      emetteur: 'CFPH — Canado Technique · Programme homologué MENFP'
    });
  });

  /* ── PILOTAGE ── */
  app.get('/api/v1/stats', auth('direction', 'admin'), async (req, res) => {
    const { rows } = await pool.query(`
      SELECT m.code, m.titre,
             COUNT(*) FILTER (WHERE ev.mention='REUSSITE') AS reussites,
             COUNT(ev.id) AS tentatives,
             ROUND(AVG(ev.points_obtenus)) AS moyenne
        FROM modules m LEFT JOIN evaluations ev
          ON ev.module_code=m.code AND NOT ev.annulee
       GROUP BY m.code, m.titre ORDER BY m.code`);
    res.json(rows);
  });

  /* ── SANTÉ DU MODULE CERTIFICATION ── */
  app.get('/api/v1/health', async (req, res) => {
    try {
      const { rows } = await pool.query(
        `SELECT filiere, COUNT(*) modules,
                COUNT(*) FILTER (WHERE grille_officielle) grilles_officielles
           FROM modules GROUP BY filiere ORDER BY filiere`);
      const { rows: c } = await pool.query('SELECT COUNT(*) n FROM criteres');
      res.json({ status: 'ok', base: 'connectée',
                 total_modules: rows.reduce((s2, r) => s2 + Number(r.modules), 0),
                 total_criteres: Number(c[0].n), filieres: rows });
    } catch (e) {
      res.status(500).json({ status: 'ko', erreur: e.message });
    }
  });

  console.log('   🎓 API de certification montée sur /api/v1');
};
