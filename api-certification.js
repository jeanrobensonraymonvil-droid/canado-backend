/**
 * CANADO TECHNIQUE — API DE CERTIFICATION  (/api/v1)
 * ───────────────────────────────────────────────────
 * À insérer dans server.js AVANT le `app.listen(...)`.
 *
 *   npm install pg bcryptjs jsonwebtoken
 *
 * Variables d'environnement à ajouter :
 *   DATABASE_URL   = postgres://...          (Railway fournit l'URL)
 *   JWT_SECRET     = <chaîne longue et aléatoire>
 *   SEAL_SECRET    = <autre chaîne longue>   (scellement des évaluations)
 *
 * PRINCIPE : une évaluation signée est IMMUABLE (trigger SQL).
 * Une reprise = une NOUVELLE tentative. C'est ce qui rend le diplôme opposable.
 */

const { Pool }  = require('pg');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

const JWT_SECRET  = process.env.JWT_SECRET  || 'CHANGEZ-MOI';
const SEAL_SECRET = process.env.SEAL_SECRET || 'CHANGEZ-MOI-AUSSI';

const sceller = (obj) =>
  crypto.createHmac('sha256', SEAL_SECRET).update(JSON.stringify(obj)).digest('hex');

/* ── AUTH ─────────────────────────────────────────── */
function auth(...roles) {
  return (req, res, next) => {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentification requise.' });
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      if (roles.length && !roles.includes(req.user.role)) {
        return res.status(403).json({ error: 'Droits insuffisants.' });
      }
      next();
    } catch {
      return res.status(401).json({ error: 'Session expirée.' });
    }
  };
}

const trace = (req, action, cible, donnees) =>
  pool.query(
    'INSERT INTO journal (utilisateur_id, action, cible, donnees, ip) VALUES ($1,$2,$3,$4,$5)',
    [req.user?.id || null, action, cible, donnees || null, req.ip]
  ).catch(() => {});

/* ════════════════════════════════════════════════════
   AUTHENTIFICATION
════════════════════════════════════════════════════ */
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, mot_de_passe } = req.body || {};
  if (!email || !mot_de_passe) return res.status(400).json({ error: 'Email et mot de passe requis.' });
  try {
    const { rows } = await pool.query(
      'SELECT * FROM utilisateurs WHERE lower(email)=lower($1) AND actif', [email]);
    const u = rows[0];
    if (!u || !(await bcrypt.compare(mot_de_passe, u.mot_de_passe))) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }
    const token = jwt.sign(
      { id: u.id, role: u.role, nom: u.nom, prenom: u.prenom },
      JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { id: u.id, nom: u.nom, prenom: u.prenom, role: u.role } });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

/* ════════════════════════════════════════════════════
   ÉTUDIANTS
════════════════════════════════════════════════════ */
app.get('/api/v1/etudiants', auth('formateur', 'direction', 'admin'), async (req, res) => {
  const { filiere, cohorte } = req.query;
  const { rows } = await pool.query(
    `SELECT id, matricule, nom, prenom, filiere, cohorte, statut
       FROM etudiants
      WHERE ($1::text IS NULL OR filiere = $1)
        AND ($2::text IS NULL OR cohorte = $2)
      ORDER BY nom, prenom`, [filiere || null, cohorte || null]);
  res.json(rows);
});

app.post('/api/v1/etudiants', auth('direction', 'admin'), async (req, res) => {
  const { nom, prenom, filiere, cohorte, telephone, date_naissance } = req.body || {};
  if (!nom || !prenom || !filiere || !cohorte) {
    return res.status(400).json({ error: 'nom, prenom, filiere et cohorte sont requis.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: c } = await client.query(
      `SELECT COUNT(*)+1 AS n FROM etudiants WHERE filiere=$1 AND cohorte=$2`, [filiere, cohorte]);
    const matricule = `${filiere}-${cohorte}-${String(c[0].n).padStart(4, '0')}`;
    const { rows } = await client.query(
      `INSERT INTO etudiants (matricule, nom, prenom, filiere, cohorte, telephone, date_naissance)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [matricule, nom, prenom, filiere, cohorte, telephone || null, date_naissance || null]);
    await client.query('COMMIT');
    trace(req, 'etudiant.create', matricule, { nom, prenom, filiere });
    res.status(201).json(rows[0]);
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Création impossible.' });
  } finally { client.release(); }
});

/* ════════════════════════════════════════════════════
   MODULES & GRILLES OFFICIELLES
════════════════════════════════════════════════════ */
app.get('/api/v1/modules/:code/grille', auth(), async (req, res) => {
  const { rows: m } = await pool.query('SELECT * FROM modules WHERE code=$1', [req.params.code]);
  if (!m[0]) return res.status(404).json({ error: 'Module inconnu.' });
  const { rows: c } = await pool.query(
    'SELECT ordre, libelle, points, obligatoire FROM criteres WHERE module_code=$1 ORDER BY ordre',
    [req.params.code]);
  res.json({ module: m[0], criteres: c });
});

/* ════════════════════════════════════════════════════
   ÉVALUATION SOMMATIVE — le cœur de la certification
════════════════════════════════════════════════════ */
app.post('/api/v1/evaluations', auth('formateur', 'direction', 'admin'), async (req, res) => {
  const { etudiant_id, module_code, date_epreuve, detail,
          verdique = false, motif_verdique, observations } = req.body || {};

  if (!etudiant_id || !module_code || !date_epreuve || !detail) {
    return res.status(400).json({ error: 'etudiant_id, module_code, date_epreuve et detail sont requis.' });
  }
  if (verdique && !motif_verdique) {
    return res.status(400).json({ error: 'Un manquement grave doit être motivé.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: mm } = await client.query('SELECT * FROM modules WHERE code=$1', [module_code]);
    const mod = mm[0];
    if (!mod) throw new Error('Module inconnu.');

    const { rows: cc } = await client.query(
      'SELECT ordre, points, obligatoire FROM criteres WHERE module_code=$1 ORDER BY ordre', [module_code]);

    // ── Calcul de la mention — CÔTÉ SERVEUR, jamais côté client ──
    let points = null, valides = null, mention;

    if (mod.type_objectif === 'comportement') {
      points = cc.reduce((s, c) => s + (detail[c.ordre] ? Number(detail[c.ordre]) : 0), 0);
      const maxi = cc.reduce((s, c) => s + (c.points || 0), 0);
      if (points > maxi) throw new Error(`Total (${points}) supérieur au barème (${maxi}).`);
      mention = (!verdique && points >= mod.seuil_points) ? 'REUSSITE' : 'ECHEC';
    } else {
      // module de situation : critères satisfaits, dont les critères obligatoires
      valides = cc.filter(c => !!detail[c.ordre]).length;
      const oblig = cc.filter(c => c.obligatoire).every(c => !!detail[c.ordre]);
      mention = (!verdique && valides >= mod.seuil_criteres && oblig) ? 'REUSSITE' : 'ECHEC';
    }

    const { rows: t } = await client.query(
      'SELECT COALESCE(MAX(tentative),0)+1 AS n FROM evaluations WHERE etudiant_id=$1 AND module_code=$2',
      [etudiant_id, module_code]);
    const tentative = t[0].n;

    const seal = sceller({ etudiant_id, module_code, tentative, date_epreuve,
                           points, valides, mention, verdique, formateur: req.user.id });

    const { rows } = await client.query(
      `INSERT INTO evaluations
         (etudiant_id, module_code, formateur_id, tentative, date_epreuve,
          points_obtenus, criteres_valides, detail, verdique, motif_verdique,
          mention, observations, scellement)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [etudiant_id, module_code, req.user.id, tentative, date_epreuve,
       points, valides, detail, verdique, motif_verdique || null,
       mention, observations || null, seal]);

    await client.query('COMMIT');
    trace(req, 'eval.create', `${module_code}/${etudiant_id}`, { mention, points, valides, tentative, verdique });
    res.status(201).json(rows[0]);

  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

// Annulation tracée (jamais de suppression)
app.post('/api/v1/evaluations/:id/annuler', auth('direction', 'admin'), async (req, res) => {
  const { motif } = req.body || {};
  if (!motif) return res.status(400).json({ error: 'Motif obligatoire.' });
  await pool.query('UPDATE evaluations SET annulee=TRUE, motif_annulation=$2 WHERE id=$1',
    [req.params.id, motif]);
  trace(req, 'eval.cancel', req.params.id, { motif });
  res.json({ ok: true });
});

/* ════════════════════════════════════════════════════
   DOSSIER DE L'ÉTUDIANT
════════════════════════════════════════════════════ */
app.get('/api/v1/etudiants/:id/dossier', auth(), async (req, res) => {
  // un étudiant ne voit que son propre dossier
  if (req.user.role === 'etudiant') {
    const { rows } = await pool.query(
      'SELECT id FROM etudiants WHERE utilisateur_id=$1', [req.user.id]);
    if (!rows[0] || rows[0].id !== req.params.id) {
      return res.status(403).json({ error: 'Accès refusé.' });
    }
  }
  const { rows } = await pool.query(
    'SELECT * FROM v_dossier WHERE etudiant_id=$1 ORDER BY code', [req.params.id]);
  const { rows: e } = await pool.query(
    'SELECT * FROM v_eligibilite WHERE etudiant_id=$1', [req.params.id]);
  const heures = rows.filter(r => r.mention === 'REUSSITE').reduce((s, r) => s + r.heures, 0);
  res.json({ modules: rows, eligibilite: e[0] || null, heures_acquises: heures });
});

/* ════════════════════════════════════════════════════
   CERTIFICAT / DIPLÔME
════════════════════════════════════════════════════ */
app.post('/api/v1/certificats', auth('direction', 'admin'), async (req, res) => {
  const { etudiant_id } = req.body || {};
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: el } = await client.query(
      'SELECT * FROM v_eligibilite WHERE etudiant_id=$1', [etudiant_id]);
    if (!el[0]?.eligible) {
      throw new Error(`Non éligible : ${el[0]?.modules_reussis || 0}/${el[0]?.modules_requis || 0} modules validés.`);
    }

    const { rows: d } = await client.query(
      'SELECT code, titre, mention, points_obtenus, criteres_valides, heures FROM v_dossier WHERE etudiant_id=$1 ORDER BY code',
      [etudiant_id]);
    const { rows: etu } = await client.query('SELECT * FROM etudiants WHERE id=$1', [etudiant_id]);
    const e = etu[0];

    const annee = new Date().getFullYear();
    const { rows: n } = await client.query(
      `SELECT COUNT(*)+1 AS n FROM certificats WHERE numero LIKE $1`, [`CFPH-${e.filiere}-${annee}-%`]);
    const numero = `CFPH-${e.filiere}-${annee}-${String(n[0].n).padStart(4, '0')}`;
    const heures = d.reduce((s, x) => s + x.heures, 0);
    const seal = sceller({ numero, matricule: e.matricule, filiere: e.filiere, modules: d, heures });

    const { rows } = await client.query(
      `INSERT INTO certificats (numero, etudiant_id, filiere, delivre_par, modules_valides, total_heures, scellement)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [numero, etudiant_id, e.filiere, req.user.id, JSON.stringify(d), heures, seal]);

    await client.query(`UPDATE etudiants SET statut='diplome' WHERE id=$1`, [etudiant_id]);
    await client.query('COMMIT');
    trace(req, 'cert.deliver', numero, { matricule: e.matricule, heures });
    res.status(201).json(rows[0]);

  } catch (e) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: e.message });
  } finally { client.release(); }
});

/* ── VÉRIFICATION PUBLIQUE (sans authentification) ──
   C'est ce qui distingue un diplôme d'un simple PDF :
   un employeur scanne le QR code → il vérifie.            */
app.get('/api/v1/verifier/:numero', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.numero, c.filiere, c.delivre_le, c.total_heures, c.modules_valides,
            c.revoque, e.nom, e.prenom, e.matricule
       FROM certificats c JOIN etudiants e ON e.id = c.etudiant_id
      WHERE c.numero = $1`, [req.params.numero]);
  const c = rows[0];
  if (!c) return res.status(404).json({ valide: false, message: 'Certificat introuvable.' });
  if (c.revoque) return res.json({ valide: false, message: 'Certificat révoqué.' });
  res.json({
    valide: true,
    numero: c.numero,
    titulaire: `${c.prenom} ${c.nom}`,
    matricule: c.matricule,
    filiere: c.filiere,
    delivre_le: c.delivre_le,
    total_heures: c.total_heures,
    modules: c.modules_valides,
    emetteur: 'CFPH — Canado Technique · Programme homologué MENFP'
  });
});

/* ── PILOTAGE (direction) ── */
app.get('/api/v1/stats', auth('direction', 'admin'), async (req, res) => {
  const { rows } = await pool.query(`
    SELECT m.code, m.titre,
           COUNT(*) FILTER (WHERE ev.mention='REUSSITE') AS reussites,
           COUNT(ev.id)                                  AS tentatives,
           ROUND(AVG(ev.points_obtenus))                 AS moyenne
      FROM modules m LEFT JOIN evaluations ev
        ON ev.module_code = m.code AND NOT ev.annulee
     GROUP BY m.code, m.titre ORDER BY m.code`);
  res.json(rows);
});
